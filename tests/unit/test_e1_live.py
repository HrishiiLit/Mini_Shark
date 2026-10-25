"""Unit tests for Engine E1 live and replay packet capture."""

import time
from pathlib import Path
import pytest

from backend.e1_capture.live import LiveCaptureEngine, ReplayCaptureEngine
from backend.models import CapturedPacket

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def test_captured_packet_attributes():
    """CapturedPacket contract fields must be correctly accessible and immutable."""
    pkt = CapturedPacket(
        probe_id=2,
        seq=42,
        timestamp_ns=1700000000123456789,
        captured_len=128,
        original_len=1514,
        data=b"\xaa" * 128,
        interface="eth1",
    )
    assert pkt.probe_id == 2
    assert pkt.seq == 42
    assert pkt.timestamp_ns == 1700000000123456789
    assert pkt.captured_len == 128
    assert pkt.original_len == 1514
    assert len(pkt.data) == 128
    assert pkt.interface == "eth1"


def test_live_capture_engine_validation():
    """LiveCaptureEngine should reject invalid probe IDs."""
    with pytest.raises(ValueError):
        LiveCaptureEngine(probe_id=0)

    with pytest.raises(ValueError):
        LiveCaptureEngine(probe_id=256)

    engine = LiveCaptureEngine(probe_id=1, interface="test0", buffer_capacity=500)
    assert engine.probe_id == 1
    assert engine.ring_buffer.capacity == 500
    assert not engine.is_running


def test_replay_capture_engine_streams_pcap():
    """ReplayCaptureEngine must stream all packets from a fixture PCAP into the ring buffer."""
    pcap_path = DATA_DIR / "sample_tcp.pcap"
    assert pcap_path.exists(), f"Missing fixture {pcap_path}"

    engine = ReplayCaptureEngine(
        pcap_path=pcap_path,
        probe_id=1,
        interface="sim0",
        buffer_capacity=100,
    )

    engine.start()
    assert engine.is_running

    received: list[CapturedPacket] = []
    # Drain until replay completes and buffer closes
    while True:
        pkt = engine.ring_buffer.pop(timeout=0.2)
        if pkt is None:
            if not engine.is_running and engine.ring_buffer.is_empty():
                break
            continue
        received.append(pkt)

    engine.stop()
    assert not engine.is_running

    # Verify packets were received
    assert len(received) > 0
    # Verify monotonic sequence numbers
    seqs = [p.seq for p in received]
    assert seqs == list(range(len(received)))
    # Verify probe ID
    assert all(p.probe_id == 1 for p in received)
    assert all(p.interface == "sim0" for p in received)
    assert all(p.timestamp_ns > 0 for p in received)


def test_replay_capture_engine_stop_aborts_early():
    """Stopping ReplayCaptureEngine prematurely must cleanly join thread without leaks."""
    pcap_path = DATA_DIR / "sample_tcp.pcap"
    engine = ReplayCaptureEngine(
        pcap_path=pcap_path,
        probe_id=1,
        rate_pps=5.0,  # Slow rate so it runs long enough to test stop()
    )

    engine.start()
    time.sleep(0.05)
    assert engine.is_running

    engine.stop(timeout=1.0)
    assert not engine.is_running
