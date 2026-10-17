"""SQLite persistence for Engine E4.

All SQL is parameterised (SQL-injection defence, NFR-05) and every capture is
written inside a single transaction: if anything fails the transaction rolls
back and a :class:`~backend.errors.StorageError` is raised - persistence is
never claimed when it did not happen (UC-07).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from typing import Any

from backend.errors import StorageError
from backend.models import DecodedPacket, Flow, Layer, Packet

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    file_hash    TEXT,
    packet_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS packets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id   INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    packet_index INTEGER NOT NULL,
    timestamp    REAL    NOT NULL,
    length       INTEGER NOT NULL,
    raw          BLOB    NOT NULL,
    UNIQUE (capture_id, packet_index)
);

CREATE TABLE IF NOT EXISTS layers (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id   INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    packet_index INTEGER NOT NULL,
    position     INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    fields_json  TEXT    NOT NULL,
    undecoded    BLOB,
    UNIQUE (capture_id, packet_index, position)
);

CREATE TABLE IF NOT EXISTS flows (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id       INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    flow_id          INTEGER NOT NULL,
    src_ip           TEXT    NOT NULL,
    dst_ip           TEXT    NOT NULL,
    src_port         INTEGER NOT NULL,
    dst_port         INTEGER NOT NULL,
    protocol         TEXT    NOT NULL,
    packet_count     INTEGER NOT NULL,
    byte_count       INTEGER NOT NULL,
    start_ts         REAL,
    end_ts           REAL,
    duration         REAL,
    packet_indices   TEXT    NOT NULL,
    UNIQUE (capture_id, flow_id)
);

CREATE INDEX IF NOT EXISTS idx_packets_capture ON packets(capture_id);
CREATE INDEX IF NOT EXISTS idx_layers_capture  ON layers(capture_id, packet_index);
CREATE INDEX IF NOT EXISTS idx_flows_capture   ON flows(capture_id);
CREATE INDEX IF NOT EXISTS idx_flows_protocol  ON flows(protocol);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip    ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip    ON flows(dst_ip);
"""

_INSERT_PACKET = (
    "INSERT INTO packets (capture_id, packet_index, timestamp, length, raw) "
    "VALUES (?, ?, ?, ?, ?)"
)
_INSERT_LAYER = (
    "INSERT INTO layers (capture_id, packet_index, position, name, "
    "fields_json, undecoded) VALUES (?, ?, ?, ?, ?, ?)"
)
_INSERT_FLOW = (
    "INSERT INTO flows (capture_id, flow_id, src_ip, dst_ip, src_port, dst_port, "
    "protocol, packet_count, byte_count, start_ts, end_ts, duration, packet_indices) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def _dump_fields(fields: dict[str, Any]) -> str:
    return json.dumps(fields, default=str, sort_keys=True)


def flow_row(capture_id: int, flow: Flow) -> tuple[Any, ...]:
    """Flatten a :class:`Flow` into the ``flows`` table row."""
    src_ip, dst_ip, src_port, dst_port, protocol = flow.five_tuple
    return (
        capture_id,
        flow.flow_id,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        flow.packet_count,
        flow.byte_count,
        flow.start_ts,
        flow.end_ts,
        flow.duration,
        json.dumps(list(flow.packet_indices)),
    )


def row_to_flow(row: sqlite3.Row) -> Flow:
    return Flow(
        flow_id=row["flow_id"],
        five_tuple=(
            row["src_ip"],
            row["dst_ip"],
            row["src_port"],
            row["dst_port"],
            row["protocol"],
        ),
        packet_indices=json.loads(row["packet_indices"]),
        byte_count=row["byte_count"],
        start_ts=row["start_ts"],
        end_ts=row["end_ts"],
        duration=row["duration"],
    )


class CaptureStore:
    """Thin repository over a SQLite database."""

    def __init__(self, path: str = ":memory:") -> None:
        try:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(SCHEMA)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {path!r}: {exc}") from exc

    def close(self) -> None:
        self._conn.close()

    def persist(
        self,
        *,
        name: str,
        file_hash: str | None,
        packets: Sequence[Packet],
        flows: Sequence[Flow],
        decoded: Sequence[DecodedPacket] | None = None,
    ) -> int:
        """Write capture, packets, layers and flows in one transaction."""
        try:
            with self._conn:
                cursor = self._conn.execute(
                    "INSERT INTO captures (name, file_hash, packet_count) "
                    "VALUES (?, ?, ?)",
                    (name, file_hash, len(packets)),
                )
                capture_id = int(cursor.lastrowid)
                self._conn.executemany(
                    _INSERT_PACKET,
                    [
                        (capture_id, p.index, p.timestamp, p.length, p.raw_bytes)
                        for p in packets
                    ],
                )
                if decoded:
                    self._conn.executemany(
                        _INSERT_LAYER, _layer_rows(capture_id, decoded)
                    )
                self._conn.executemany(
                    _INSERT_FLOW, [flow_row(capture_id, flow) for flow in flows]
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to store capture: {exc}") from exc
        return capture_id

    def list_captures(self) -> list[dict[str, Any]]:
        rows = self._execute(
            "SELECT id, name, file_hash, packet_count, created_at FROM captures "
            "ORDER BY id",
            (),
        )
        return [dict(row) for row in rows]

    def fetch_packets(
        self, capture_id: int, offset: int = 0, limit: int = 50
    ) -> list[Packet]:
        rows = self._execute(
            "SELECT packet_index, timestamp, length, raw FROM packets "
            "WHERE capture_id = ? ORDER BY packet_index LIMIT ? OFFSET ?",
            (capture_id, limit, offset),
        )
        return [
            Packet(
                index=row["packet_index"],
                timestamp=row["timestamp"],
                length=row["length"],
                raw_bytes=bytes(row["raw"]),
            )
            for row in rows
        ]

    def fetch_layers(self, capture_id: int, packet_index: int) -> list[Layer]:
        rows = self._execute(
            "SELECT name, fields_json, undecoded FROM layers "
            "WHERE capture_id = ? AND packet_index = ? ORDER BY position",
            (capture_id, packet_index),
        )
        return [
            Layer(
                name=row["name"],
                fields=json.loads(row["fields_json"]),
                undecoded_bytes=bytes(row["undecoded"] or b""),
            )
            for row in rows
        ]

    def fetch_flows(
        self,
        *,
        capture_id: int | None = None,
        where: str = "",
        params: Sequence[Any] = (),
        limit: int | None = None,
    ) -> list[Flow]:
        conditions: list[str] = []
        values: list[Any] = []
        if capture_id is not None:
            conditions.append("capture_id = ?")
            values.append(capture_id)
        if where:
            conditions.append(f"({where})")
            values.extend(params)
        sql = "SELECT * FROM flows"
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY id"
        if limit is not None:
            sql += " LIMIT ?"
            values.append(limit)
        return [row_to_flow(row) for row in self._execute(sql, values)]

    def fetch_flow(self, capture_id: int, flow_id: int) -> Flow | None:
        rows = self._execute(
            "SELECT * FROM flows WHERE capture_id = ? AND flow_id = ?",
            (capture_id, flow_id),
        )
        return row_to_flow(rows[0]) if rows else None

    def _execute(self, sql: str, params: Sequence[Any]) -> list[sqlite3.Row]:
        try:
            return list(self._conn.execute(sql, params).fetchall())
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc


def _layer_rows(
    capture_id: int, decoded: Sequence[DecodedPacket]
) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for item in decoded:
        for position, layer in enumerate(item.layers):
            rows.append(
                (
                    capture_id,
                    item.packet_index,
                    position,
                    layer.name,
                    _dump_fields(layer.fields),
                    layer.undecoded_bytes,
                )
            )
    return rows
