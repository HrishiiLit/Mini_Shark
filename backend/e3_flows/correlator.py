"""E3 multi-point packet correlation hub.

Matches invariant packet fingerprints between ingress and egress probes in O(1) time,
schedules timeouts on a min-heap, computes transit delay (ΔT = T2 - T1), and emits
correlation records.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from backend.models import CorrelationRecord, ProbeTelemetry

logger = logging.getLogger(__name__)

# Protocol & correlation flags
CLOCK_SKEW_SUSPECT = 1
COLLISION_DISAMBIGUATED = 2
FRAGMENT = 4
DUPLICATE_T2_IGNORED = 8
FINGERPRINT_VERSION_MISMATCH = 16

_PREAMBLE_MAGIC = b"MSHK"
_PREAMBLE_SIZE = 16
_RECORD_SIZE = 24
_PREAMBLE_VERSION = 1
_MAX_IN_FLIGHT = 50_000


@dataclass
class _InFlight:
    """In-flight packet observation stored until paired or expired."""

    fingerprint: int
    probe_id: int
    timestamp_ns: int
    seq: int
    deadline_ns: int
    captured_len: int
    alive: bool = True


class CorrelationHub:
    """In-memory correlation hub for matching multi-probe packet telemetry."""

    def __init__(
        self,
        timeout_ms: int = 500,
        on_record: Callable[[CorrelationRecord], None] | None = None,
        probe1_id: int = 1,
        probe2_id: int = 2,
    ) -> None:
        self._timeout_ns = timeout_ms * 1_000_000
        self._on_record = on_record
        self._probe1_id = probe1_id
        self._probe2_id = probe2_id

        # Hash tables for in-flight pairing
        self._table: dict[int, _InFlight] = {}      # Ingress clients waiting for server
        self._table_p2: dict[int, _InFlight] = {}   # Server (Probe 2) waiting for ingress client

        self._heap: list[tuple[int, int]] = []
        self.records: list[CorrelationRecord] = []
        self.connected_probes: dict[str, dict[str, Any]] = {}

        self.stats: dict[str, int] = {
            "matched": 0,
            "late": 0,
            "unmatched": 0,
            "duplicate_t2": 0,
            "probe2_only": 0,
        }

    # Core matching

    def ingest(self, telemetry: ProbeTelemetry) -> CorrelationRecord | None:
        """Process an incoming telemetry record and match against in-flight observations."""
        self._expire_timeouts()

        fp = telemetry.fingerprint
        ts = telemetry.timestamp_ns
        pid = telemetry.probe_id
        now = time.time_ns()

        if pid == self._probe2_id:
            # Server observation (Probe 2): match against ingress observations
            entry = self._table.get(fp)
            if entry is not None and entry.alive:
                entry.alive = False
                del self._table[fp]

                flags = self._dt_flags(entry.timestamp_ns, ts)
                rec = self._make_record(
                    fp=fp,
                    p1_ts=entry.timestamp_ns,
                    p2_ts=ts,
                    p1_seq=entry.seq,
                    p2_seq=telemetry.seq,
                    match_state="matched",
                    deadline_ns=entry.deadline_ns,
                    flags=flags,
                    client_probe_id=entry.probe_id,
                )
                self.stats["matched"] += 1
                self._emit(rec)
                return rec

            # Arrived before ingress probe: buffer in _table_p2
            if fp in self._table_p2:
                self.stats["duplicate_t2"] += 1
                return None

            deadline = ts + self._timeout_ns
            entry2 = _InFlight(
                fingerprint=fp,
                probe_id=pid,
                timestamp_ns=ts,
                seq=telemetry.seq,
                deadline_ns=deadline,
                captured_len=telemetry.captured_len,
            )
            self._table_p2[fp] = entry2
            heapq.heappush(self._heap, (deadline, fp))
            self._compact_heap()
            return None

        else:
            # Ingress client observation (Probe 1, Probe 3, etc.)
            entry2 = self._table_p2.get(fp)
            if entry2 is not None and entry2.alive:
                entry2.alive = False
                del self._table_p2[fp]
                flags = self._dt_flags(ts, entry2.timestamp_ns)
                rec = self._make_record(
                    fp=fp,
                    p1_ts=ts,
                    p2_ts=entry2.timestamp_ns,
                    p1_seq=telemetry.seq,
                    p2_seq=entry2.seq,
                    match_state="matched",
                    deadline_ns=entry2.deadline_ns,
                    flags=flags,
                    client_probe_id=pid,
                )
                self.stats["matched"] += 1
                self._emit(rec)
                return rec

            if fp in self._table:
                self.stats["duplicate_t2"] += 1
                return None

            self._maybe_evict()

            deadline = ts + self._timeout_ns
            entry = _InFlight(
                fingerprint=fp,
                probe_id=pid,
                timestamp_ns=ts,
                seq=telemetry.seq,
                deadline_ns=deadline,
                captured_len=telemetry.captured_len,
            )
            self._table[fp] = entry
            heapq.heappush(self._heap, (deadline, fp))
            self._compact_heap()
            return None

    def flush_expired(self) -> list[CorrelationRecord]:
        """Force-expire entries that have passed their deadline."""
        return self._expire_timeouts(force_all=False)

    def flush_all(self) -> list[CorrelationRecord]:
        """Expire all in-flight entries immediately on shutdown."""
        return self._expire_timeouts(force_all=True)

    # Ingestion server & probe connections

    async def start_server(self, host: str = "0.0.0.0", port: int = 9000) -> None:
        """Run the asyncio TCP server receiving 24-byte probe telemetry."""
        server = await asyncio.start_server(
            self._handle_probe_connection,
            host=host,
            port=port,
            reuse_port=hasattr(asyncio, "SO_REUSEPORT"),
        )
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        logger.info("E3 TCP server listening on %s", addrs)
        async with server:
            await server.serve_forever()

    async def _handle_probe_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle individual probe TCP session and connection lifecycle."""
        peer = writer.get_extra_info("peername")
        peer_ip = str(peer[0]) if peer else "unknown"
        conn_key = f"{peer_ip}:{peer[1] if peer else id(writer)}"
        probe_id: int | None = None
        try:
            probe_id = await self._read_preamble(reader, peer)
            self.connected_probes[conn_key] = {
                "conn_key": conn_key,
                "peer": peer,
                "ip": peer_ip,
                "port": peer[1] if peer else 0,
                "probe_id": probe_id,
                "connected_at": time.time(),
                "last_seen": time.time(),
                "records": 0,
            }
            logger.info("Probe %d connected from %s", probe_id, peer_ip)
            await self._read_records(reader, peer, conn_key)
        except asyncio.IncompleteReadError:
            logger.info("Probe %s (probe_id=%s) disconnected", peer, probe_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Probe %s error: %s", peer, exc)
        finally:
            if conn_key in self.connected_probes:
                del self.connected_probes[conn_key]
                logger.info("Probe %s unregistered", probe_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_preamble(
        self, reader: asyncio.StreamReader, peer: Any
    ) -> int:
        """Read and validate the 16-byte MSHK connection preamble."""
        data = await reader.readexactly(_PREAMBLE_SIZE)
        magic = data[0:4]
        version = data[4]
        rec_sz = data[5]
        probe_id = int.from_bytes(data[6:8], "big")

        if magic != _PREAMBLE_MAGIC:
            raise ValueError(f"Bad preamble magic from {peer}: {magic!r}")
        if version != _PREAMBLE_VERSION:
            raise ValueError(f"Unsupported preamble version {version} from {peer}")
        if rec_sz != _RECORD_SIZE:
            raise ValueError(f"Unexpected record size {rec_sz} from {peer}")
        return probe_id

    async def _read_records(
        self, reader: asyncio.StreamReader, peer: Any, conn_key: str = ""
    ) -> None:
        """Stream and unpack fixed 24-byte telemetry records."""
        while True:
            data = await reader.readexactly(_RECORD_SIZE)
            try:
                telemetry = ProbeTelemetry.unpack(data)
            except ValueError as exc:
                logger.warning("Malformed record from %s: %s", peer, exc)
                continue
            now_sec = time.time()
            if conn_key in self.connected_probes:
                self.connected_probes[conn_key]["last_seen"] = now_sec
                self.connected_probes[conn_key]["records"] += 1
            self.ingest(telemetry)

    def probe_status(self) -> dict[str, Any]:
        """Return snapshot of active probe connections."""
        now = time.time()
        active = [
            p for p in self.connected_probes.values()
            if (now - p.get("last_seen", 0)) < 30.0
        ]
        # Deduplicate by probe_id, keeping most active connection
        by_probe_id: dict[int, dict[str, Any]] = {}
        for p in active:
            pid = p["probe_id"]
            if pid not in by_probe_id or p.get("records", 0) >= by_probe_id[pid].get("records", 0):
                by_probe_id[pid] = p

        deduped_active = list(by_probe_id.values())
        client_probes = [p for p in deduped_active if p["probe_id"] != self._probe2_id]
        p1 = client_probes[0] if client_probes else None
        p2 = next((p for p in deduped_active if p["probe_id"] == self._probe2_id), None)

        active_list = [
            {
                "ip": p["ip"],
                "probe_id": p["probe_id"],
                "records": p.get("records", 0),
                "connected_at": p.get("connected_at", now),
            }
            for p in deduped_active
        ]
        return {
            "probe1_connected": p1 is not None,
            "probe1_ip": p1["ip"] if p1 else None,
            "probe2_connected": p2 is not None,
            "probe2_ip": p2["ip"] if p2 else None,
            "active_clients": active_list,
            "total_connected": len(deduped_active),
        }

    # Memory management & record creation

    def _compact_heap(self) -> None:
        """Rebuild the min-heap to purge inactive entries."""
        live_count = sum(1 for e in self._table.values() if e.alive) + sum(
            1 for e in self._table_p2.values() if e.alive
        )
        if len(self._heap) > 2 * (live_count + 1):
            self._heap = [
                (e.deadline_ns, fp) for fp, e in self._table.items() if e.alive
            ] + [
                (e.deadline_ns, fp) for fp, e in self._table_p2.items() if e.alive
            ]
            heapq.heapify(self._heap)

    def _maybe_evict(self) -> None:
        """Evict oldest in-flight entry if memory ceiling is reached."""
        if len(self._table) < _MAX_IN_FLIGHT:
            return
        while self._heap:
            deadline, fp = heapq.heappop(self._heap)
            entry = self._table.get(fp)
            if entry is not None and entry.alive:
                entry.alive = False
                del self._table[fp]
                rec = self._make_record(
                    fp=fp,
                    p1_ts=entry.timestamp_ns,
                    p2_ts=None,
                    p1_seq=entry.seq,
                    p2_seq=None,
                    match_state="unmatched",
                    deadline_ns=entry.deadline_ns,
                    flags=0,
                    client_probe_id=entry.probe_id,
                )
                self.stats["unmatched"] += 1
                self._emit(rec)
                return

    def _expire_timeouts(self, *, force_all: bool = False) -> list[CorrelationRecord]:
        """Expire and emit records that exceeded the correlation timeout."""
        now = time.time_ns()
        emitted: list[CorrelationRecord] = []
        while self._heap:
            deadline, fp = self._heap[0]
            if not force_all and deadline > now:
                break
            heapq.heappop(self._heap)

            # Expire ingress observations
            entry = self._table.get(fp)
            if entry is not None and entry.alive:
                entry.alive = False
                del self._table[fp]
                rec = self._make_record(
                    fp=fp,
                    p1_ts=entry.timestamp_ns,
                    p2_ts=None,
                    p1_seq=entry.seq,
                    p2_seq=None,
                    match_state="unmatched",
                    deadline_ns=entry.deadline_ns,
                    flags=0,
                    client_probe_id=entry.probe_id,
                )
                self.stats["unmatched"] += 1
                self._emit(rec)
                emitted.append(rec)
                continue

            # Expire server observations that arrived without ingress partner
            entry2 = self._table_p2.get(fp)
            if entry2 is not None and entry2.alive:
                entry2.alive = False
                del self._table_p2[fp]
                rec = self._make_record(
                    fp=fp,
                    p1_ts=None,
                    p2_ts=entry2.timestamp_ns,
                    p1_seq=None,
                    p2_seq=entry2.seq,
                    match_state="probe2_only",
                    deadline_ns=entry2.deadline_ns,
                    flags=0,
                )
                self.stats["probe2_only"] += 1
                self._emit(rec)
                emitted.append(rec)
                continue

        return emitted

    @staticmethod
    def _dt_flags(t1_ns: int, t2_ns: int) -> int:
        """Flag clock skew if delay is negative or exceeds 5s."""
        delay = t2_ns - t1_ns
        if delay < 0 or delay > 5_000_000_000:
            return CLOCK_SKEW_SUSPECT
        return 0

    def _make_record(
        self,
        *,
        fp: int,
        p1_ts: int | None,
        p2_ts: int | None,
        p1_seq: int | None,
        p2_seq: int | None,
        match_state: str,
        deadline_ns: int,
        flags: int,
        client_probe_id: int = 1,
    ) -> CorrelationRecord:
        """Construct a CorrelationRecord with delay and client attribution."""
        delay_ns = None
        if p1_ts is not None and p2_ts is not None:
            delay_ns = p2_ts - p1_ts
            if delay_ns < 0 or delay_ns > 5_000_000_000:
                flags |= CLOCK_SKEW_SUSPECT

        rec = CorrelationRecord(
            fingerprint=fp,
            probe1_observed=p1_ts is not None,
            probe2_observed=p2_ts is not None,
            match_state=match_state,
            deadline_ns=deadline_ns,
            created_at_ns=time.time_ns(),
            t1_ns=p1_ts,
            t2_ns=p2_ts,
            delay_ns=delay_ns,
            flags=flags,
            probe1_seq=p1_seq,
            probe2_seq=p2_seq,
        )
        object.__setattr__(rec, "client_probe_id", client_probe_id)
        return rec

    def _emit(self, record: CorrelationRecord) -> None:
        """Emit record to callback or internal list."""
        if self._on_record:
            self._on_record(record)
        else:
            self.records.append(record)
