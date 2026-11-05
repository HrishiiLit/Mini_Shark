"""E3 — Multi-Point Correlation Hub (Phase 4).

Receives ProbeTelemetry records from two probes, matches them by fingerprint
in O(1) average time via an in-memory dict, schedules expiration deadlines on
a min-heap (O(log K)), computes one-way delay ΔT = T2 - T1, and emits
CorrelationRecord events.

Usage::

    hub = CorrelationHub(timeout_ms=500, on_record=my_callback)
    hub.ingest(telemetry)   # call for each arriving ProbeTelemetry

TCP ingestion server::

    await hub.start_server(host="0.0.0.0", port=9000)
"""

from __future__ import annotations

import asyncio
import heapq
import logging
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from backend.models import CorrelationRecord, ProbeTelemetry

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
CLOCK_SKEW_SUSPECT         = 1
COLLISION_DISAMBIGUATED    = 2
FRAGMENT                   = 4
DUPLICATE_T2_IGNORED       = 8
FINGERPRINT_VERSION_MISMATCH = 16

_PREAMBLE_MAGIC   = b"MSHK"
_PREAMBLE_SIZE    = 16
_RECORD_SIZE      = 24
_PREAMBLE_VERSION = 1

# Hard ceiling on the number of in-flight Probe-1 observations held in memory.
# Under 100% packet loss with sustained traffic the table would otherwise grow
# without bound.  When the ceiling is hit the oldest (earliest-deadline) entry
# is force-expired as UNMATCHED before the new one is inserted.
_MAX_IN_FLIGHT = 50_000

# ──────────────────────────────────────────────────────────────────────────────
# In-flight entry stored in the hash table
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _InFlight:
    fingerprint: int
    probe_id: int
    timestamp_ns: int
    seq: int
    deadline_ns: int
    captured_len: int
    alive: bool = True          # set False when emitted (lazy heap removal)


# ──────────────────────────────────────────────────────────────────────────────
# Correlation Hub
# ──────────────────────────────────────────────────────────────────────────────

class CorrelationHub:
    """In-memory O(1) correlation hub for two-probe packet matching.

    Args:
        timeout_ms: Unmatched-packet timeout in milliseconds (default 500).
        on_record:  Callback called with each emitted CorrelationRecord.
                    If None, records are appended to ``self.records``.
        probe1_id:  Probe ID of the source/client probe (default 1).
        probe2_id:  Probe ID of the destination/server probe (default 2).
    """

    def __init__(
        self,
        timeout_ms: int = 500,
        on_record: Callable[[CorrelationRecord], None] | None = None,
        probe1_id: int = 1,
        probe2_id: int = 2,
    ) -> None:
        self._timeout_ns  = timeout_ms * 1_000_000
        self._on_record   = on_record
        self._probe1_id   = probe1_id
        self._probe2_id   = probe2_id

        # hash table: fingerprint → _InFlight (only Probe-1 side stored)
        self._table: dict[int, _InFlight] = {}

        # min-heap: (deadline_ns, fingerprint)
        self._heap: list[tuple[int, int]] = []

        # public records list (used when no callback given)
        self.records: list[CorrelationRecord] = []

        # stats
        self.stats: dict[str, int] = {
            "matched": 0,
            "late": 0,
            "unmatched": 0,
            "duplicate_t2": 0,
            "probe2_only": 0,
        }
        self.connected_probes: dict[Any, dict[str, Any]] = {}

    # ── Public API ──────────────────────────────────────────────────────────

    def ingest(self, telemetry: ProbeTelemetry) -> CorrelationRecord | None:
        """Process one ProbeTelemetry record. Returns a CorrelationRecord if
        one is emitted immediately (matched), otherwise None (stored for later
        matching or timeout).
        """
        self._expire_timeouts()

        fp   = telemetry.fingerprint
        ts   = telemetry.timestamp_ns
        pid  = telemetry.probe_id
        now  = time.time_ns()

        if pid == self._probe1_id:
            # ── First observation: store in table + heap ─────────────────
            if fp in self._table:
                # Already have a Probe-1 entry; could be a retransmission.
                # Keep the existing entry — the new one is treated as duplicate.
                self.stats["duplicate_t2"] += 1
                return None

            # Enforce memory cap before inserting — evict oldest live entry.
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

        elif pid == self._probe2_id:
            # ── Second observation: try to match ─────────────────────────
            entry = self._table.get(fp)
            if entry is None:
                # Probe-2 only (no matching Probe-1 record)
                rec = self._make_record(
                    fp=fp,
                    p1_ts=None, p2_ts=ts,
                    p1_seq=None, p2_seq=telemetry.seq,
                    match_state="probe2_only",
                    deadline_ns=now + self._timeout_ns,
                    flags=0,
                )
                self.stats["probe2_only"] += 1
                self._emit(rec)
                return rec

            if not entry.alive:
                # Already emitted as unmatched; late arrival
                rec = self._make_record(
                    fp=fp,
                    p1_ts=entry.timestamp_ns, p2_ts=ts,
                    p1_seq=entry.seq, p2_seq=telemetry.seq,
                    match_state="late",
                    deadline_ns=entry.deadline_ns,
                    flags=self._dt_flags(entry.timestamp_ns, ts),
                )
                self.stats["late"] += 1
                self._emit(rec)
                return rec

            # Normal match — remove from table
            entry.alive = False
            del self._table[fp]

            flags = self._dt_flags(entry.timestamp_ns, ts)
            rec = self._make_record(
                fp=fp,
                p1_ts=entry.timestamp_ns, p2_ts=ts,
                p1_seq=entry.seq, p2_seq=telemetry.seq,
                match_state="matched",
                deadline_ns=entry.deadline_ns,
                flags=flags,
            )
            self.stats["matched"] += 1
            self._emit(rec)
            return rec

        else:
            logger.warning("Unknown probe_id %d — ignored", pid)
            return None

    def flush_expired(self) -> list[CorrelationRecord]:
        """Force-expire all entries that have passed their deadline.
        Call this periodically or before shutdown.
        """
        return self._expire_timeouts(force_all=False)

    def flush_all(self) -> list[CorrelationRecord]:
        """Expire every in-flight entry regardless of deadline (shutdown)."""
        return self._expire_timeouts(force_all=True)

    # ── TCP ingestion server ─────────────────────────────────────────────────

    async def start_server(self, host: str = "0.0.0.0", port: int = 9000) -> None:
        """Start the asyncio TCP ingestion server on *port*.

        This is a coroutine — await it inside an asyncio event loop or
        create it as a background task::

            asyncio.create_task(hub.start_server())
        """
        server = await asyncio.start_server(
            self._handle_probe_connection, host, port
        )
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        logger.info("E3 TCP ingestion server listening on %s", addrs)
        async with server:
            await server.serve_forever()

    async def _handle_probe_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("Probe connected from %s", peer)
        self.connected_probes[peer] = {
            "peer": peer,
            "ip": str(peer[0]) if peer else "unknown",
            "port": peer[1] if peer else 0,
            "connected_at": time.time(),
            "last_seen": time.time(),
            "probe_id": None,
            "records": 0,
        }
        try:
            await self._read_preamble(reader, peer)
            await self._read_records(reader, peer)
        except asyncio.IncompleteReadError:
            logger.info("Probe %s disconnected", peer)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Probe %s error: %s", peer, exc)
        finally:
            if peer in self.connected_probes:
                del self.connected_probes[peer]
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_preamble(
        self, reader: asyncio.StreamReader, peer: Any
    ) -> None:
        """Read and validate the 16-byte connection preamble."""
        data = await reader.readexactly(_PREAMBLE_SIZE)
        magic   = data[0:4]
        version = data[4]
        rec_sz  = data[5]

        if magic != _PREAMBLE_MAGIC:
            raise ValueError(f"Bad preamble magic from {peer}: {magic!r}")
        if version != _PREAMBLE_VERSION:
            raise ValueError(f"Unsupported preamble version {version} from {peer}")
        if rec_sz != _RECORD_SIZE:
            raise ValueError(f"Unexpected record size {rec_sz} from {peer}")
        logger.info("Preamble OK from %s (record_size=%d)", peer, rec_sz)

    async def _read_records(
        self, reader: asyncio.StreamReader, peer: Any
    ) -> None:
        """Read fixed-size 24-byte records until connection closes."""
        while True:
            data = await reader.readexactly(_RECORD_SIZE)
            try:
                telemetry = ProbeTelemetry.unpack(data)
            except ValueError as exc:
                logger.warning("Malformed record from %s: %s", peer, exc)
                continue
            if peer in self.connected_probes:
                self.connected_probes[peer]["probe_id"] = telemetry.probe_id
                self.connected_probes[peer]["last_seen"] = time.time()
                self.connected_probes[peer]["records"] += 1
            self.ingest(telemetry)


    def probe_status(self) -> dict[str, Any]:
        """Return connected probes snapshot."""
        now = time.time()
        probes = list(self.connected_probes.values())
        p1 = next((p for p in probes if p["probe_id"] == self._probe1_id), None)
        p2 = next((p for p in probes if p["probe_id"] == self._probe2_id), None)
        active_list = [
            {
                "ip": p["ip"],
                "probe_id": p["probe_id"],
                "records": p["records"],
                "connected_at": p["connected_at"],
            }
            for p in probes
            if (now - p["last_seen"]) < 10.0
        ]
        return {
            "probe1_connected": p1 is not None and (now - p1["last_seen"]) < 10.0,
            "probe1_ip": p1["ip"] if p1 else None,
            "probe2_connected": p2 is not None and (now - p2["last_seen"]) < 10.0,
            "probe2_ip": p2["ip"] if p2 else None,
            "active_clients": active_list,
            "total_connected": len(active_list),
        }

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _compact_heap(self) -> None:
        """Rebuild the heap when dead nodes outnumber live ones 2-to-1.

        Matched entries are never removed from the heap explicitly (lazy
        deletion); over time this causes the heap to grow to O(all-time
        matched count).  Compaction brings it back to O(in-flight count).
        """
        live_count = sum(1 for e in self._table.values() if e.alive)
        if len(self._heap) > 2 * (live_count + 1):
            self._heap = [
                (e.deadline_ns, fp)
                for fp, e in self._table.items()
                if e.alive
            ]
            heapq.heapify(self._heap)

    def _maybe_evict(self) -> None:
        """Force-expire the oldest in-flight entry when the table is full.

        Prevents unbounded memory growth under 100% packet-loss conditions
        where Probe-1 observations pile up with no matching Probe-2 side.
        """
        if len(self._table) < _MAX_IN_FLIGHT:
            return
        now = time.time_ns()
        # Pop heap nodes until we find a live one to evict
        while self._heap:
            deadline, fp = heapq.heappop(self._heap)
            entry = self._table.get(fp)
            if entry is not None and entry.alive:
                entry.alive = False
                del self._table[fp]
                rec = self._make_record(
                    fp=fp,
                    p1_ts=entry.timestamp_ns, p2_ts=None,
                    p1_seq=entry.seq, p2_seq=None,
                    match_state="unmatched",
                    deadline_ns=entry.deadline_ns,
                    flags=0,
                )
                self.stats["unmatched"] += 1
                self._emit(rec)
                return

    def _expire_timeouts(self, *, force_all: bool = False) -> list[CorrelationRecord]:
        now = time.time_ns()
        emitted: list[CorrelationRecord] = []
        while self._heap:
            deadline, fp = self._heap[0]
            if not force_all and deadline > now:
                break
            heapq.heappop(self._heap)
            entry = self._table.get(fp)
            if entry is None or not entry.alive:
                continue   # already matched or already expired
            entry.alive = False
            del self._table[fp]
            rec = self._make_record(
                fp=fp,
                p1_ts=entry.timestamp_ns, p2_ts=None,
                p1_seq=entry.seq, p2_seq=None,
                match_state="unmatched",
                deadline_ns=entry.deadline_ns,
                flags=0,
            )
            self.stats["unmatched"] += 1
            self._emit(rec)
            emitted.append(rec)
        return emitted

    @staticmethod
    def _dt_flags(t1_ns: int, t2_ns: int) -> int:
        delay = t2_ns - t1_ns
        if delay < 0 or delay > 5_000_000_000:   # negative or > 5 s → suspect
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
    ) -> CorrelationRecord:
        delay_ns = None
        if p1_ts is not None and p2_ts is not None:
            delay_ns = p2_ts - p1_ts
            if delay_ns < 0 or delay_ns > 5_000_000_000:
                flags |= CLOCK_SKEW_SUSPECT

        return CorrelationRecord(
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

    def _emit(self, record: CorrelationRecord) -> None:
        if self._on_record:
            self._on_record(record)
        else:
            self.records.append(record)
