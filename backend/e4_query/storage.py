"""SQLite persistence for Engine E4 — Schema v2.

Schema v1: captures, packets (raw), layers, flows  (offline PCAP mode)
Schema v2: + probes, correlation_records, diagnostic_alerts (distributed mode)

All SQL is parameterised (SQL-injection defence) and every write uses
a transaction — rollback on failure, StorageError raised to caller.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from typing import Any

from backend.errors import StorageError
from backend.models import (
    CorrelationRecord,
    DecodedPacket,
    DiagnosticAlert,
    Flow,
    Layer,
    Packet,
)

# ──────────────────────────────────────────────────────────────────────────────
# Schema
# ──────────────────────────────────────────────────────────────────────────────

_SCHEMA_V1 = """
PRAGMA journal_mode=WAL;

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

_SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS probes (
    probe_id      INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL DEFAULT '',
    ip            TEXT    NOT NULL DEFAULT '',
    location      TEXT    NOT NULL DEFAULT '',
    role          TEXT    NOT NULL DEFAULT 'unknown',
    first_seen_ns INTEGER,
    last_seen_ns  INTEGER,
    status        TEXT    NOT NULL DEFAULT 'offline'
);

CREATE TABLE IF NOT EXISTS correlation_records (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint      INTEGER NOT NULL,
    probe1_observed  INTEGER NOT NULL DEFAULT 0,
    probe2_observed  INTEGER NOT NULL DEFAULT 0,
    match_state      TEXT    NOT NULL,
    deadline_ns      INTEGER NOT NULL,
    created_at_ns    INTEGER NOT NULL,
    t1_ns            INTEGER,
    t2_ns            INTEGER,
    delay_ns         INTEGER,
    flags            INTEGER NOT NULL DEFAULT 0,
    probe1_seq       INTEGER,
    probe2_seq       INTEGER
);

CREATE TABLE IF NOT EXISTS diagnostic_alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    category            TEXT    NOT NULL,
    severity            TEXT    NOT NULL,
    confidence          TEXT    NOT NULL,
    detected_at_ns      INTEGER NOT NULL,
    recommended_action  TEXT    NOT NULL,
    evidence_refs_json  TEXT    NOT NULL DEFAULT '[]',
    metrics_json        TEXT    NOT NULL DEFAULT '{}',
    resolved_at_ns      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_corr_fingerprint ON correlation_records(fingerprint);
CREATE INDEX IF NOT EXISTS idx_corr_state       ON correlation_records(match_state);
CREATE INDEX IF NOT EXISTS idx_corr_created     ON correlation_records(created_at_ns);
CREATE INDEX IF NOT EXISTS idx_alert_category   ON diagnostic_alerts(category);
CREATE INDEX IF NOT EXISTS idx_alert_detected   ON diagnostic_alerts(detected_at_ns);
"""

_SCHEMA_VERSION = 2

# ──────────────────────────────────────────────────────────────────────────────
# Insert templates
# ──────────────────────────────────────────────────────────────────────────────

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
_INSERT_CORR = (
    "INSERT INTO correlation_records "
    "(fingerprint, probe1_observed, probe2_observed, match_state, deadline_ns, "
    "created_at_ns, t1_ns, t2_ns, delay_ns, flags, probe1_seq, probe2_seq) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_INSERT_ALERT = (
    "INSERT INTO diagnostic_alerts "
    "(category, severity, confidence, detected_at_ns, recommended_action, "
    "evidence_refs_json, metrics_json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)

# ──────────────────────────────────────────────────────────────────────────────
# Row helpers
# ──────────────────────────────────────────────────────────────────────────────

def _dump(obj: Any) -> str:
    return json.dumps(obj, default=str, sort_keys=True)


def flow_row(capture_id: int, flow: Flow) -> tuple[Any, ...]:
    src_ip, dst_ip, src_port, dst_port, protocol = flow.five_tuple
    return (
        capture_id, flow.flow_id,
        src_ip, dst_ip, src_port, dst_port, protocol,
        flow.packet_count, flow.byte_count,
        flow.start_ts, flow.end_ts, flow.duration,
        json.dumps(list(flow.packet_indices)),
    )


def row_to_flow(row: sqlite3.Row) -> Flow:
    return Flow(
        flow_id=row["flow_id"],
        five_tuple=(
            row["src_ip"], row["dst_ip"],
            row["src_port"], row["dst_port"],
            row["protocol"],
        ),
        packet_indices=json.loads(row["packet_indices"]),
        byte_count=row["byte_count"],
        start_ts=row["start_ts"],
        end_ts=row["end_ts"],
        duration=row["duration"],
    )


def row_to_corr(row: sqlite3.Row) -> CorrelationRecord:
    return CorrelationRecord(
        fingerprint=row["fingerprint"],
        probe1_observed=bool(row["probe1_observed"]),
        probe2_observed=bool(row["probe2_observed"]),
        match_state=row["match_state"],
        deadline_ns=row["deadline_ns"],
        created_at_ns=row["created_at_ns"],
        t1_ns=row["t1_ns"],
        t2_ns=row["t2_ns"],
        delay_ns=row["delay_ns"],
        flags=row["flags"],
        probe1_seq=row["probe1_seq"],
        probe2_seq=row["probe2_seq"],
    )


def row_to_alert(row: sqlite3.Row) -> DiagnosticAlert:
    return DiagnosticAlert(
        alert_id=row["id"],
        category=row["category"],
        severity=row["severity"],
        confidence=row["confidence"],
        detected_at_ns=row["detected_at_ns"],
        recommended_action=row["recommended_action"],
        evidence_refs=json.loads(row["evidence_refs_json"]),
        metrics=json.loads(row["metrics_json"]),
        resolved_at_ns=row["resolved_at_ns"],
    )


# ──────────────────────────────────────────────────────────────────────────────
# CaptureStore
# ──────────────────────────────────────────────────────────────────────────────

class CaptureStore:
    """Thin repository over a SQLite database (schema v2)."""

    def __init__(self, path: str = ":memory:") -> None:
        try:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._apply_migrations()
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {path!r}: {exc}") from exc

    def _apply_migrations(self) -> None:
        """Idempotent: apply schema v1 then v2 if not already present."""
        ver = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if ver < 1:
            self._conn.executescript(_SCHEMA_V1)
            self._conn.execute(f"PRAGMA user_version = 1")
            self._conn.commit()
            ver = 1
        if ver < 2:
            self._conn.executescript(_SCHEMA_V2)
            self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ── Offline capture persistence ────────────────────────────────────

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
                    [(capture_id, p.index, p.timestamp, p.length, p.raw_bytes)
                     for p in packets],
                )
                if decoded:
                    self._conn.executemany(
                        _INSERT_LAYER, _layer_rows(capture_id, decoded)
                    )
                self._conn.executemany(
                    _INSERT_FLOW, [flow_row(capture_id, f) for f in flows]
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to store capture: {exc}") from exc
        return capture_id

    # ── Distributed mode persistence ───────────────────────────────────

    def store_correlation(self, record: CorrelationRecord) -> int:
        """Insert one CorrelationRecord; returns its row id."""
        try:
            with self._conn:
                cur = self._conn.execute(
                    _INSERT_CORR,
                    (
                        record.fingerprint,
                        int(record.probe1_observed),
                        int(record.probe2_observed),
                        record.match_state,
                        record.deadline_ns,
                        record.created_at_ns,
                        record.t1_ns,
                        record.t2_ns,
                        record.delay_ns,
                        record.flags,
                        record.probe1_seq,
                        record.probe2_seq,
                    ),
                )
                return int(cur.lastrowid)
        except sqlite3.Error as exc:
            raise StorageError(f"failed to store correlation: {exc}") from exc

    def store_correlations(self, records: Sequence[CorrelationRecord]) -> None:
        """Bulk-insert correlation records in one transaction."""
        try:
            with self._conn:
                self._conn.executemany(
                    _INSERT_CORR,
                    [
                        (
                            r.fingerprint, int(r.probe1_observed),
                            int(r.probe2_observed), r.match_state,
                            r.deadline_ns, r.created_at_ns,
                            r.t1_ns, r.t2_ns, r.delay_ns,
                            r.flags, r.probe1_seq, r.probe2_seq,
                        )
                        for r in records
                    ],
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to store correlations: {exc}") from exc

    def store_alert(self, alert: DiagnosticAlert) -> int:
        """Insert one DiagnosticAlert; returns its row id."""
        try:
            with self._conn:
                cur = self._conn.execute(
                    _INSERT_ALERT,
                    (
                        alert.category,
                        alert.severity,
                        alert.confidence,
                        alert.detected_at_ns,
                        alert.recommended_action,
                        json.dumps(alert.evidence_refs),
                        json.dumps(alert.metrics),
                    ),
                )
                return int(cur.lastrowid)
        except sqlite3.Error as exc:
            raise StorageError(f"failed to store alert: {exc}") from exc

    def store_alerts(self, alerts: Sequence[DiagnosticAlert]) -> None:
        """Bulk-insert alerts."""
        try:
            with self._conn:
                self._conn.executemany(
                    _INSERT_ALERT,
                    [
                        (
                            a.category, a.severity, a.confidence,
                            a.detected_at_ns, a.recommended_action,
                            json.dumps(a.evidence_refs), json.dumps(a.metrics),
                        )
                        for a in alerts
                    ],
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to store alerts: {exc}") from exc

    # ── Queries ─────────────────────────────────────────────────────────

    def list_captures(self) -> list[dict[str, Any]]:
        rows = self._execute(
            "SELECT id, name, file_hash, packet_count, created_at "
            "FROM captures ORDER BY id", ()
        )
        return [dict(row) for row in rows]

    def fetch_packets(self, capture_id: int, offset: int = 0, limit: int = 50) -> list[Packet]:
        rows = self._execute(
            "SELECT packet_index, timestamp, length, raw FROM packets "
            "WHERE capture_id = ? ORDER BY packet_index LIMIT ? OFFSET ?",
            (capture_id, limit, offset),
        )
        return [
            Packet(index=r["packet_index"], timestamp=r["timestamp"],
                   length=r["length"], raw_bytes=bytes(r["raw"]))
            for r in rows
        ]

    def fetch_layers(self, capture_id: int, packet_index: int) -> list[Layer]:
        rows = self._execute(
            "SELECT name, fields_json, undecoded FROM layers "
            "WHERE capture_id = ? AND packet_index = ? ORDER BY position",
            (capture_id, packet_index),
        )
        return [
            Layer(name=r["name"], fields=json.loads(r["fields_json"]),
                  undecoded_bytes=bytes(r["undecoded"] or b""))
            for r in rows
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
        return [row_to_flow(r) for r in self._execute(sql, values)]

    def fetch_flow(self, capture_id: int, flow_id: int) -> Flow | None:
        rows = self._execute(
            "SELECT * FROM flows WHERE capture_id = ? AND flow_id = ?",
            (capture_id, flow_id),
        )
        return row_to_flow(rows[0]) if rows else None

    def fetch_correlations(
        self,
        *,
        match_state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CorrelationRecord]:
        if match_state:
            rows = self._execute(
                "SELECT * FROM correlation_records WHERE match_state = ? "
                "ORDER BY created_at_ns DESC LIMIT ? OFFSET ?",
                (match_state, limit, offset),
            )
        else:
            rows = self._execute(
                "SELECT * FROM correlation_records "
                "ORDER BY created_at_ns DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        return [row_to_corr(r) for r in rows]

    def fetch_alerts(
        self,
        *,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DiagnosticAlert]:
        if category:
            rows = self._execute(
                "SELECT * FROM diagnostic_alerts WHERE category = ? "
                "ORDER BY detected_at_ns DESC LIMIT ? OFFSET ?",
                (category, limit, offset),
            )
        else:
            rows = self._execute(
                "SELECT * FROM diagnostic_alerts "
                "ORDER BY detected_at_ns DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        return [row_to_alert(r) for r in rows]

    def correlation_stats(self) -> dict[str, Any]:
        """Aggregate stats for the live dashboard."""
        rows = self._execute(
            "SELECT match_state, COUNT(*) as cnt FROM correlation_records "
            "GROUP BY match_state", ()
        )
        counts = {r["match_state"]: r["cnt"] for r in rows}
        total = sum(counts.values())
        loss_count = counts.get("unmatched", 0) + counts.get("late", 0)
        loss_rate = loss_count / total if total else 0.0

        delay_rows = self._execute(
            "SELECT AVG(delay_ns) as avg_d, MAX(delay_ns) as max_d "
            "FROM correlation_records WHERE delay_ns IS NOT NULL "
            "AND match_state = 'matched'", ()
        )
        avg_d = delay_rows[0]["avg_d"] if delay_rows and delay_rows[0]["avg_d"] else 0
        max_d = delay_rows[0]["max_d"] if delay_rows and delay_rows[0]["max_d"] else 0

        return {
            "total_records": total,
            "matched": counts.get("matched", 0),
            "unmatched": counts.get("unmatched", 0),
            "late": counts.get("late", 0),
            "probe2_only": counts.get("probe2_only", 0),
            "loss_rate": round(loss_rate, 4),
            "avg_delay_ms": round((avg_d or 0) / 1_000_000, 3),
            "max_delay_ms": round((max_d or 0) / 1_000_000, 3),
        }

    def _execute(self, sql: str, params: Sequence[Any]) -> list[sqlite3.Row]:
        try:
            return list(self._conn.execute(sql, params).fetchall())
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _layer_rows(capture_id: int, decoded: Sequence[DecodedPacket]) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for item in decoded:
        for position, layer in enumerate(item.layers):
            rows.append((
                capture_id, item.packet_index, position,
                layer.name, _dump(layer.fields), layer.undecoded_bytes,
            ))
    return rows
