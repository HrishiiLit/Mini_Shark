from __future__ import annotations

import asyncio   # must be imported before the version-check block below
import sys

if sys.version_info >= (3, 11):
    _async_timeout = asyncio.timeout
else:
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _async_timeout(delay):
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        handle = loop.call_later(delay, task.cancel)
        try:
            yield
        except asyncio.CancelledError:
            raise asyncio.TimeoutError() from None
        finally:
            handle.cancel()

"""TCP Telemetry Ingestion Service (Engine E3) — Port 9000.

Implements the persistent TCP ingestion service specified in data_contract.md §4
and api_routes.md §2:
  - Listens on TCP port 9000 (asyncio).
  - Handles 16-byte preamble (MSHK magic, version=1, record_size=24, clock hint).
  - Streams fixed 24-byte big-endian ProbeTelemetry records.
  - Buffers chunked/partial reads across TCP frames.
  - Tracks connected probes, heartbeats, and estimated clock offsets.
  - Drives CorrelationEngine matching and periodic deadline expiration.
  - Provides a reusable TelemetryClient for probes and tests.
"""


import logging
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from backend.models import CorrelationFlags, ProbeTelemetry, TelemetryPreamble

from .correlation import CorrelationEngine

logger = logging.getLogger("minishark.e3.ingestion")

PREAMBLE_SIZE = 16
RECORD_SIZE = 24

@dataclass
class ConnectedProbe:
    """Connection and liveness state for a connected probe host."""

    probe_id: int
    remote_addr: str
    remote_port: int
    connected_at_ns: int
    last_seen_ns: int
    last_heartbeat_ns: int
    clock_offset_s_estimate: float = 0.0
    packets_received: int = 0
    records_rejected: int = 0
    status: str = "online"  # "online" | "offline" | "degraded"


class TelemetryServer:
    """Asyncio TCP ingestion server on port 9000."""

    def __init__(
        self,
        engine: CorrelationEngine | None = None,
        host: str = "0.0.0.0",
        port: int = 9000,
        expire_interval_ms: int = 50,
        idle_timeout_s: float = 30.0,
        max_connections: int = 8,
        clock_tolerance_s: float = 60.0,
    ) -> None:
        if (
            min(expire_interval_ms, idle_timeout_s, max_connections, clock_tolerance_s)
            <= 0
        ):
            raise ValueError(
                "intervals, clock tolerance and connection limit must be positive"
            )
        self.host = host
        self.port = port
        self.engine = engine if engine is not None else CorrelationEngine()
        self.expire_interval_s = expire_interval_ms / 1000.0
        self.idle_timeout_s = idle_timeout_s
        self.max_connections = max_connections
        self.clock_tolerance_ns = int(clock_tolerance_s * 1_000_000_000)

        self._server: asyncio.Server | None = None
        self._expire_task: asyncio.Task | None = None
        self._is_running = False
        self._connected_probes: dict[int, ConnectedProbe] = {}
        self._peer_to_probe_id: dict[tuple[str, int], int] = {}
        self._client_writers: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task] = set()
        self._probe_writers: dict[int, asyncio.StreamWriter] = {}
        self.total_records_ingested = 0
        self.rejected_connections = 0
        self.records_rejected = 0

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def connected_probes(self) -> dict[int, ConnectedProbe]:
        return dict(self._connected_probes)

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """Start the TCP ingestion server and background expiration task."""
        if self._is_running:
            return

        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
            reuse_address=True,
            limit=4096,
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._is_running = True
        self._expire_task = asyncio.create_task(self._expiration_loop())
        logger.info(
            "Telemetry ingestion service listening on %s:%d", self.host, self.port
        )

    async def stop(self) -> None:
        """Gracefully stop the server, cancel tasks, and close connections."""
        if not self._is_running:
            return

        self._is_running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        if self._expire_task and not self._expire_task.done():
            self._expire_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._expire_task

        for writer in list(self._client_writers):
            writer.close()
        tasks = tuple(self._client_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        for probe in self._connected_probes.values():
            probe.status = "offline"

        logger.info("Telemetry ingestion service stopped")

    # -----------------------------------------------------------------------
    # Client Handler
    # -----------------------------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a persistent TCP connection from a single probe."""
        task = asyncio.current_task()
        self._client_tasks.add(task)
        accepted = len(self._client_writers) < self.max_connections
        self._client_writers.add(writer)
        peer = writer.get_extra_info("peername")
        remote_addr, remote_port = peer[0], peer[1]
        peer_key = (remote_addr, remote_port)
        probe_id_assigned: int | None = None
        try:
            if not accepted:
                raise ValueError("connection limit reached")
            async with _async_timeout(self.idle_timeout_s):
                raw = await reader.readexactly(PREAMBLE_SIZE)
            preamble = TelemetryPreamble.unpack(raw)
            clock_offset = time.time() - preamble.probe_clock_epoch_s
            while self._is_running:
                async with _async_timeout(self.idle_timeout_s):
                    raw = await reader.readexactly(RECORD_SIZE)
                record = ProbeTelemetry.unpack(raw)
                self._validate_record(record, probe_id_assigned, writer)
                if probe_id_assigned is None:
                    probe_id_assigned = record.probe_id
                    self._register_probe(record.probe_id, writer, clock_offset)
                    self._peer_to_probe_id[peer_key] = record.probe_id
                self._consume_record(record, clock_offset)
        except asyncio.IncompleteReadError as exc:
            if exc.partial:
                self._reject_record(probe_id_assigned)
                logger.warning("Truncated telemetry from %s", peer)
        except ValueError as exc:
            self.rejected_connections += 1
            self._reject_record(probe_id_assigned)
            logger.warning("Rejected telemetry from %s: %s", peer, exc)
        except (TimeoutError, OSError) as exc:
            logger.debug("Probe %s disconnected: %s", probe_id_assigned, exc)
        finally:
            self._client_writers.discard(writer)
            if self._probe_writers.get(probe_id_assigned) is writer:
                self._probe_writers.pop(probe_id_assigned)
                self._connected_probes[probe_id_assigned].status = "offline"
            self._peer_to_probe_id.pop(peer_key, None)
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            self._client_tasks.discard(task)

    def _validate_record(
        self, record: ProbeTelemetry, assigned: int | None, writer: asyncio.StreamWriter
    ) -> None:
        if record.type_flags not in (0x11, 0x13):
            raise ValueError("unsupported record version or type")
        if record.probe_id not in (self.engine.probe1_id, self.engine.probe2_id):
            raise ValueError("unknown probe ID")
        if assigned is not None and assigned != record.probe_id:
            raise ValueError("probe ID changed within connection")
        owner = self._probe_writers.get(record.probe_id)
        if owner is not None and owner is not writer:
            raise ValueError("probe already has an active connection")

    def _register_probe(
        self, probe_id: int, writer: asyncio.StreamWriter, clock_offset: float
    ) -> None:
        peer = writer.get_extra_info("peername")
        now = time.time_ns()
        self._probe_writers[probe_id] = writer
        self._connected_probes[probe_id] = ConnectedProbe(
            probe_id=probe_id,
            remote_addr=peer[0],
            remote_port=peer[1],
            connected_at_ns=now,
            last_seen_ns=now,
            last_heartbeat_ns=0,
            clock_offset_s_estimate=clock_offset,
        )

    def _reject_record(self, probe_id: int | None) -> None:
        self.records_rejected += 1
        if probe_id in self._connected_probes:
            self._connected_probes[probe_id].records_rejected += 1

    def _consume_record(self, record: ProbeTelemetry, clock_offset: float) -> None:
        probe = self._connected_probes[record.probe_id]
        now = time.time_ns()
        probe.last_seen_ns = now
        probe.status = "online"
        self.total_records_ingested += 1
        if record.type_flags == 0x13:
            probe.last_heartbeat_ns = now
            return
        probe.packets_received += 1
        # Clock skew is evaluated by CorrelationEngine._match() after both
        # probe timestamps (T1 and T2) are available and can be compared
        # against each other — not against hub wall-clock time.  Comparing
        # record.timestamp_ns to hub time.time_ns() produces false positives
        # whenever the probe and hub clocks differ by even a few seconds
        # (common across independent VMs without NTP).  Pass flags=0 here;
        # the correlator sets CLOCK_SKEW_SUSPECT when delay_ns < 0 or > 10 s.
        self.engine.process_telemetry(record, flags=0)

    # -----------------------------------------------------------------------
    # Expiration Background Task
    # -----------------------------------------------------------------------

    async def _expiration_loop(self) -> None:
        """Periodically trigger deadline expirations on the CorrelationEngine."""
        while self._is_running:
            try:
                await asyncio.sleep(self.expire_interval_s)
                self.engine.expire_deadlines()
                self._check_probe_liveness()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in expiration loop: %s", exc)

    def _check_probe_liveness(self) -> None:
        """Mark probes degraded after 15 seconds without valid telemetry."""
        now_ns = time.time_ns()
        stale_threshold_ns = 15_000_000_000  # 15 seconds
        for probe in self._connected_probes.values():
            if (
                probe.status == "online"
                and (now_ns - probe.last_seen_ns) > stale_threshold_ns
            ):
                probe.status = "degraded"

    # -----------------------------------------------------------------------
    # Status / Introspection
    # -----------------------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        """Return server readiness and connected probes per api_routes.md §2."""
        return {
            "listening": self._is_running,
            "port": self.port,
            "connected_probes": [
                p.probe_id
                for p in self._connected_probes.values()
                if p.status == "online"
            ],
            "total_records_ingested": self.total_records_ingested,
            "records_rejected": self.records_rejected,
            "rejected_connections": self.rejected_connections,
            "active_connections": len(self._client_writers),
            "probes": [
                {
                    "probe_id": p.probe_id,
                    "ip": p.remote_addr,
                    "port": p.remote_port,
                    "status": p.status,
                    "packets_sent": p.packets_received,
                    "records_rejected": p.records_rejected,
                    "last_seen_ns": p.last_seen_ns,
                    "last_heartbeat_ns": p.last_heartbeat_ns,
                    "clock_offset_ms_estimate": round(
                        p.clock_offset_s_estimate * 1000.0, 2
                    ),
                }
                for p in self._connected_probes.values()
            ],
        }

    def probe_status(self) -> dict[str, Any]:
        """Return probe status in dashboard-compatible format."""
        self._check_probe_liveness()
        p1 = self._connected_probes.get(self.engine.probe1_id)
        p2 = self._connected_probes.get(self.engine.probe2_id)
        p1_online = p1 is not None and p1.status == "online"
        p2_online = p2 is not None and p2.status == "online"
        active_list = [
            {
                "ip": p.remote_addr,
                "probe_id": p.probe_id,
                "records": p.packets_received,
                "connected_at": p.connected_at_ns / 1_000_000_000.0,
            }
            for p in self._connected_probes.values()
            if p.status == "online"
        ]
        return {
            "probe1_connected": p1_online,
            "probe1_ip": p1.remote_addr if p1_online and p1 else None,
            "probe2_connected": p2_online,
            "probe2_ip": p2.remote_addr if p2_online and p2 else None,
            "active_clients": active_list,
            "total_connected": len(active_list),
        }


class TelemetryClient:
    """Client utility to stream telemetry records to the central server."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 9000, probe_id: int = 1
    ) -> None:
        self.host = host
        self.port = port
        self.probe_id = probe_id
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._seq = 0

    async def connect(self) -> None:
        """Connect to the telemetry server and send the 16-byte preamble."""
        if self._writer is not None:
            raise RuntimeError("TelemetryClient already connected")
        self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
        preamble = TelemetryPreamble(
            magic=b"MSHK",
            version=1,
            record_size=RECORD_SIZE,
            probe_clock_epoch_s=int(time.time()),
        )
        self._writer.write(preamble.pack())
        await self._writer.drain()

    async def send_record(self, record: ProbeTelemetry) -> None:
        """Send a single ProbeTelemetry record."""
        if not self._writer:
            raise RuntimeError("TelemetryClient not connected")
        if record.probe_id != self.probe_id:
            raise ValueError("record probe ID does not match client")
        self._writer.write(record.pack())
        await self._writer.drain()

    async def send_batch(self, records: list[ProbeTelemetry]) -> None:
        """Send a batch of ProbeTelemetry records."""
        if not self._writer:
            raise RuntimeError("TelemetryClient not connected")
        if any(record.probe_id != self.probe_id for record in records):
            raise ValueError("record probe ID does not match client")
        payload = b"".join(r.pack() for r in records)
        self._writer.write(payload)
        await self._writer.drain()

    async def send_heartbeat(self) -> None:
        """Send a type-3 heartbeat / probe summary record."""
        if not self._writer:
            raise RuntimeError("TelemetryClient not connected")
        # type_flags: version 1 (0x10) | record type 3 (0x03) = 0x13
        type_flags = (1 << 4) | 3
        now_ns = time.time_ns()
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        record = ProbeTelemetry(
            fingerprint=0,
            timestamp_ns=now_ns,
            seq=self._seq,
            probe_id=self.probe_id,
            type_flags=type_flags,
            captured_len=0,
        )
        await self.send_record(record)

    async def close(self) -> None:
        """Close the client connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                pass
            self._writer = None
            self._reader = None
