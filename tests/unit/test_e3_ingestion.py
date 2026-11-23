from __future__ import annotations
import anyio
"""Integration and unit tests for TCP Telemetry Ingestion (ingestion.py).

Tests:
  - TelemetryServer lifecycle (start / stop)
  - 16-byte preamble handshake and rejection of malformed preambles
  - Persistent TCP streaming from Probe 1 and Probe 2
  - Live correlation of streaming telemetry over TCP port
  - Chunked / partial-read handling across TCP stream boundaries
  - Probe heartbeat and liveness tracking
  - Graceful disconnect and status updates
"""


import asyncio
import socket
import time
from dataclasses import replace

import pytest
from helpers import tcp_frame

from backend.e2_dissection import ProtocolDissector
from backend.e3_flows.correlation import CorrelationEngine
from backend.e3_flows.ingestion import TelemetryClient, TelemetryServer
from backend.models import (
    CorrelationRecord,
    MatchState,
    Packet,
    ProbeTelemetry,
    TelemetryPreamble,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _wait_until(predicate, timeout=2.0):
    start = time.time()
    while not predicate():
        if time.time() - start > timeout:
            raise TimeoutError('Condition not met within timeout')
        await asyncio.sleep(0.01)


@pytest.mark.parametrize("offset,value", [(0, 0), (4, 2), (5, 25), (6, 1), (12, 1)])
def test_preamble_rejects_unknown_format_and_nonzero_reserved(offset, value):
    raw = bytearray(TelemetryPreamble().pack())
    raw[offset] = value
    with pytest.raises(ValueError):
        TelemetryPreamble.unpack(bytes(raw))


def _free_port() -> int:
    """Find a free local port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.anyio
async def test_server_lifecycle():
    port = _free_port()
    server = TelemetryServer(host="127.0.0.1", port=port)
    assert not server.is_running

    await server.start()
    assert server.is_running
    status = server.get_status()
    assert status["listening"] is True
    assert status["port"] == port

    await server.stop()
    assert not server.is_running


@pytest.mark.anyio
async def test_preamble_validation_rejection():
    port = _free_port()
    server = TelemetryServer(host="127.0.0.1", port=port)
    await server.start()

    try:
        # 1. Connect and send bad magic
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        bad_preamble = b"BADM\x01\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        writer.write(bad_preamble)
        await writer.drain()

        # Server should close connection
        data = await reader.read(100)
        assert data == b""
        writer.close()
        await writer.wait_closed()

        # 2. Connect with valid preamble using TelemetryClient
        client = TelemetryClient(host="127.0.0.1", port=port, probe_id=1)
        await client.connect()
        # Should stay open
        await client.send_heartbeat()
        await asyncio.sleep(0.05)
        status = server.get_status()
        assert 1 in status["connected_probes"]
        await client.close()

    finally:
        await server.stop()


@pytest.mark.anyio
async def test_two_probes_streaming_and_live_correlation():
    port = _free_port()
    engine = CorrelationEngine(timeout_ms=500)
    server = TelemetryServer(engine=engine, host="127.0.0.1", port=port)
    await server.start()

    correlated_events: list[CorrelationRecord] = []
    engine.subscribe(correlated_events.append)

    client1 = TelemetryClient(host="127.0.0.1", port=port, probe_id=1)
    client2 = TelemetryClient(host="127.0.0.1", port=port, probe_id=2)

    try:
        await client1.connect()
        await client2.connect()

        fp = 0xABCD1234EF567890
        now = time.time_ns()
        t1 = now
        t2 = now + 8_500_000  # +8.5 ms delay

        rec1 = ProbeTelemetry(
            fingerprint=fp,
            timestamp_ns=t1,
            seq=1,
            probe_id=1,
            type_flags=0x11,  # v1, type 1 (packet)
            captured_len=74,
        )
        rec2 = ProbeTelemetry(
            fingerprint=fp,
            timestamp_ns=t2,
            seq=1,
            probe_id=2,
            type_flags=0x11,
            captured_len=74,
        )

        # Probe 1 sends record
        await client1.send_record(rec1)
        await asyncio.sleep(0.05)
        assert len(correlated_events) == 0  # In-flight

        # Probe 2 sends matching record
        await client2.send_record(rec2)
        await asyncio.sleep(0.05)

        assert len(correlated_events) == 1
        event = correlated_events[0]
        assert event.match_state == MatchState.MATCHED.value
        assert event.fingerprint == fp
        assert event.delay_ns == 8_500_000
        assert event.delay_ms == pytest.approx(8.5)
        assert event.probe1_seq == 1
        assert event.probe2_seq == 1

        stats = server.get_status()
        assert stats["total_records_ingested"] >= 2

    finally:
        await client1.close()
        await client2.close()
        await server.stop()


@pytest.mark.anyio
async def test_chunked_streaming_across_tcp():
    port = _free_port()
    engine = CorrelationEngine(timeout_ms=500)
    server = TelemetryServer(engine=engine, host="127.0.0.1", port=port)
    await server.start()

    correlated_events: list[CorrelationRecord] = []
    engine.subscribe(correlated_events.append)

    try:
        # Directly connect raw socket to simulate fragmented TCP packets
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        preamble = TelemetryPreamble(
            magic=b"MSHK",
            version=1,
            record_size=24,
            probe_clock_epoch_s=int(time.time()),
        )
        writer.write(preamble.pack())
        await writer.drain()

        fp = 0x5555444433332222
        t1 = time.time_ns()
        rec = ProbeTelemetry(
            fingerprint=fp,
            timestamp_ns=t1,
            seq=1,
            probe_id=1,
            type_flags=0x11,
            captured_len=60,
        )
        packed = rec.pack()

        # Send in two chunks: first 9 bytes, then remaining 15 bytes
        writer.write(packed[:9])
        await writer.drain()
        await asyncio.sleep(0.02)

        # Nothing in table yet
        assert engine.get_stats()["correlation"]["in_flight"] == 0

        # Send second chunk
        writer.write(packed[9:])
        await writer.drain()
        await asyncio.sleep(0.05)

        # Record was fully assembled and processed!
        assert engine.get_stats()["correlation"]["in_flight"] == 1

        writer.close()
        await writer.wait_closed()

    finally:
        await server.stop()


@pytest.mark.anyio
async def test_probe_disconnect_marks_offline():
    port = _free_port()
    server = TelemetryServer(host="127.0.0.1", port=port)
    await server.start()

    try:
        client = TelemetryClient(host="127.0.0.1", port=port, probe_id=2)
        await client.connect()
        await client.send_heartbeat()
        await asyncio.sleep(0.05)

        probes = server.get_status()["probes"]
        assert any(p["probe_id"] == 2 and p["status"] == "online" for p in probes)

        # Disconnect client
        await client.close()
        await asyncio.sleep(0.05)

        probes = server.get_status()["probes"]
        assert any(p["probe_id"] == 2 and p["status"] == "offline" for p in probes)

    finally:
        await server.stop()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "change",
    [
        {"type_flags": 0x21},
        {"type_flags": 0x12},
        {"probe_id": 0},
        {"probe_id": 3},
    ],
)
async def test_bad_record_closes_connection_and_cleans_resources(change):
    server = TelemetryServer(host="127.0.0.1", port=0)
    await server.start()
    try:
        reader, writer = await asyncio.open_connection(server.host, server.port)
        writer.write(TelemetryPreamble(probe_clock_epoch_s=int(time.time())).pack())
        good = ProbeTelemetry(1, time.time_ns(), 1, 1, 0x11, 64)
        writer.write(replace(good, **change).pack())
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 1) == b""
        await _wait_until(lambda: not server._client_tasks)
        assert not server._client_writers
        assert server.records_rejected == 1
        assert server.total_records_ingested == 0
        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.anyio
async def test_identity_switch_and_duplicate_probe_connection_rejected():
    server = TelemetryServer(host="127.0.0.1", port=0)
    await server.start()
    client = TelemetryClient(server.host, server.port, probe_id=1)
    await client.connect()
    try:
        await client.send_heartbeat()
        await _wait_until(lambda: 1 in server.connected_probes)
        reader, writer = await asyncio.open_connection(server.host, server.port)
        writer.write(TelemetryPreamble().pack())
        writer.write(ProbeTelemetry(0, time.time_ns(), 1, 1, 0x13, 0).pack())
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert server.connected_probes[1].status == "online"
        writer.close()
        await writer.wait_closed()
        # Raw write bypasses the client's own identity validation.
        client._writer.write(ProbeTelemetry(0, time.time_ns(), 2, 2, 0x13, 0).pack())
        await client._writer.drain()
        assert await asyncio.wait_for(client._reader.read(), 1) == b""
        await _wait_until(lambda: server.connected_probes[1].status == "offline")
        assert 2 not in server.connected_probes
    finally:
        await client.close()
        await server.stop()


@pytest.mark.anyio
async def test_idle_partial_preamble_and_stop_leave_no_tasks_or_writers():
    server = TelemetryServer(host="127.0.0.1", port=0, idle_timeout_s=0.03)
    await server.start()
    reader, writer = await asyncio.open_connection(server.host, server.port)
    writer.write(b"MS")
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 1) == b""
    writer.close()
    await writer.wait_closed()
    _reader, writer = await asyncio.open_connection(server.host, server.port)
    await _wait_until(lambda: bool(server._client_tasks))
    await server.stop()
    assert not server._client_tasks
    assert not server._client_writers
    assert not server._peer_to_probe_id
    writer.close()
    await writer.wait_closed()


@pytest.mark.anyio
async def test_truncated_record_rejected_and_heartbeat_restores_liveness():
    server = TelemetryServer(host="127.0.0.1", port=0)
    await server.start()
    client = TelemetryClient(server.host, server.port)
    await client.connect()
    try:
        await client.send_heartbeat()
        await _wait_until(lambda: 1 in server.connected_probes)
        server.connected_probes[1].last_seen_ns -= 16_000_000_000
        server._check_probe_liveness()
        assert server.connected_probes[1].status == "degraded"
        await client.send_heartbeat()
        await _wait_until(lambda: server.connected_probes[1].status == "online")
        client._writer.write(b"truncated")
        await client._writer.drain()
        await client.close()
        await _wait_until(lambda: server.records_rejected == 1)
    finally:
        await client.close()
        await server.stop()


@pytest.mark.anyio
async def test_e2_two_hop_telemetry_over_tcp_with_interleaving_and_late_correction():
    engine = CorrelationEngine(timeout_ms=40)
    server = TelemetryServer(engine, host="127.0.0.1", port=0, expire_interval_ms=5)
    events = []
    engine.subscribe(events.append)
    await server.start()
    clients = [TelemetryClient(server.host, server.port, probe_id=i) for i in (1, 2)]
    try:
        for client in clients:
            await client.connect()
        dissector = ProtocolDissector()
        records = []
        stamp = time.time_ns()
        for index in range(3):
            frame = tcp_frame(sport=12000 + index)
            packet = Packet(index, stamp, len(frame), frame)
            first = dissector.make_telemetry(
                dissector.dissect_one(packet), packet, 1, index
            )
            hop = bytearray(frame)
            hop[:12] = b"\xaa" * 12  # router rewrites MAC addresses
            hop[22] -= 1  # IPv4 TTL
            second_packet = replace(
                packet, timestamp=stamp + 2_000_000, raw_bytes=bytes(hop)
            )
            second = dissector.make_telemetry(
                dissector.dissect_one(second_packet), second_packet, 2, index
            )
            assert first.fingerprint == second.fingerprint
            records.append((first, second))
        await clients[1].send_record(records[0][1])  # reverse arrival
        await _wait_until(lambda: server.total_records_ingested == 1)
        await clients[0].send_batch([pair[0] for pair in records])
        await _wait_until(lambda: len(events) >= 3)
        await clients[1].send_record(records[1][1])  # late recovery
        await _wait_until(lambda: len(events) == 4)
        assert sorted(event.match_state for event in events) == [
            "late",
            "matched",
            "unmatched",
            "unmatched",
        ]
        assert engine.get_stats()["correlation"]["uncorrected_unmatched_total"] == 1
        assert events[0].delay_ns == 2_000_000
    finally:
        for client in clients:
            await client.close()
        await server.stop()
