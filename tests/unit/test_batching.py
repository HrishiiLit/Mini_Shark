"""Unit test for telemetry record batching and MTU envelope validation."""

import pytest
import struct
import socket
import time
from backend.models import ProbeTelemetry
from backend.probe.client import TelemetryClient
from backend.e3_flows.correlator import CorrelationHub


def test_50_records_payload_size_and_mtu_envelope():
    """Verify byte-level layout of 50 merged records:
    50 records * 24 bytes = 1,200 bytes payload.
    1,200 bytes + 20B TCP + 20B IP + 14B Ethernet = 1,254 bytes total wire size.
    Must fit cleanly within 1,500 bytes Ethernet MTU without fragmentation.
    """
    records = []
    batch_buffer = bytearray()

    for seq in range(50):
        rec = ProbeTelemetry(
            fingerprint=0xAABBCCDDEEFF0000 + seq,
            timestamp_ns=1_700_000_000_000_000_000 + seq * 1_000_000,
            seq=seq,
            probe_id=1,
            type_flags=0x11,
            captured_len=512,
        )
        records.append(rec)
        packed = rec.pack()
        assert len(packed) == 24, "Each ProbeTelemetry record must be exactly 24 bytes"
        batch_buffer.extend(packed)

    # 1. Verify batch payload size
    assert len(batch_buffer) == 1200, "50 records must be exactly 1,200 bytes"

    # 2. Verify MTU envelope
    tcp_header_len = 20
    ipv4_header_len = 20
    ethernet_header_len = 14
    total_wire_frame = len(batch_buffer) + tcp_header_len + ipv4_header_len + ethernet_header_len

    assert total_wire_frame == 1254
    assert total_wire_frame <= 1500, f"Frame size {total_wire_frame} must be <= 1,500 MTU"

    # 3. Verify server-side unpack of contiguous stream
    unpacked_records = []
    buf = bytes(batch_buffer)
    for offset in range(0, len(buf), 24):
        chunk = buf[offset : offset + 24]
        unpacked = ProbeTelemetry.unpack(chunk)
        unpacked_records.append(unpacked)

    assert len(unpacked_records) == 50
    for i, rec in enumerate(unpacked_records):
        assert rec.seq == i
        assert rec.fingerprint == 0xAABBCCDDEEFF0000 + i


def test_3_hop_drop_localization():
    """Verify hop-by-hop link drop localization:
    - Packet seen at Client (P1) and Router (P10), missing at Server (P2) -> Link 2 Drop!
    - Packet seen at Client (P1), missing at Router (P10) and Server (P2) -> Link 1 Drop!
    - Packet seen at Client (P1), Router (P10), and Server (P2) -> Matched healthy!
    """
    records = []
    hub = CorrelationHub(
        timeout_ms=500,
        on_record=records.append,
        probe1_id=1,
        probe2_id=2,
        router_probe_id=10,
    )
    base_ns = time.time_ns()

    # 1. Packet A: Lost on Link 2 (Router -> Server)
    fp_a = 0xAAAA0001
    hub.ingest(ProbeTelemetry(fingerprint=fp_a, timestamp_ns=base_ns, seq=1, probe_id=1, type_flags=0x11, captured_len=512))
    hub.ingest(ProbeTelemetry(fingerprint=fp_a, timestamp_ns=base_ns + 1_000_000, seq=1, probe_id=10, type_flags=0x11, captured_len=512))

    # 2. Packet B: Lost on Link 1 (Client -> Router)
    fp_b = 0xBBBB0002
    hub.ingest(ProbeTelemetry(fingerprint=fp_b, timestamp_ns=base_ns, seq=2, probe_id=1, type_flags=0x11, captured_len=512))

    # 3. Packet C: Healthy transit (Client -> Router -> Server)
    fp_c = 0xCCCC0003
    hub.ingest(ProbeTelemetry(fingerprint=fp_c, timestamp_ns=base_ns, seq=3, probe_id=1, type_flags=0x11, captured_len=512))
    hub.ingest(ProbeTelemetry(fingerprint=fp_c, timestamp_ns=base_ns + 1_000_000, seq=3, probe_id=10, type_flags=0x11, captured_len=512))
    hub.ingest(ProbeTelemetry(fingerprint=fp_c, timestamp_ns=base_ns + 2_500_000, seq=3, probe_id=2, type_flags=0x11, captured_len=512))

    # Flush timeouts for dropped packets
    hub.flush_all()

    by_fp = {r.fingerprint: r for r in records}

    assert by_fp[fp_c].match_state == "matched"
    assert by_fp[fp_c].router_observed is True

    assert by_fp[fp_a].match_state == "unmatched"
    assert by_fp[fp_a].drop_link == "link_2"
    assert by_fp[fp_a].router_observed is True

    assert by_fp[fp_b].match_state == "unmatched"
    assert by_fp[fp_b].drop_link == "link_1"
    assert by_fp[fp_b].router_observed is False

