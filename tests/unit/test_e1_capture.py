"""Engine E1 tests: loading, streaming and typed error handling."""

from __future__ import annotations

import io
import struct

import dpkt
import pytest
from helpers import arp_frame, build_pcap, tcp_frame

from backend.e1_capture import CaptureLoader
from backend.errors import CorruptCaptureError, UnsupportedFormatError


def test_load_capture_returns_ordered_packets(tmp_path):
    frames = [tcp_frame(), arp_frame()]
    path = tmp_path / "two.pcap"
    path.write_bytes(build_pcap(frames, timestamps=[1.5, 2.5]))

    packets = CaptureLoader().load_capture(str(path))

    assert [packet.index for packet in packets] == [0, 1]
    assert [packet.length for packet in packets] == [len(frame) for frame in frames]
    assert packets[0].timestamp == pytest.approx(1.5)
    assert packets[1].timestamp == pytest.approx(2.5)
    assert packets[0].raw_bytes == frames[0]


def test_iter_packets_matches_load_capture(tmp_path):
    path = tmp_path / "three.pcap"
    path.write_bytes(build_pcap([tcp_frame(), tcp_frame(), arp_frame()]))

    streamed = list(CaptureLoader().iter_packets(str(path)))

    assert [packet.index for packet in streamed] == [0, 1, 2]


def test_empty_capture_reports_zero_packets(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(build_pcap([]))

    assert CaptureLoader().load_capture(str(path)) == []


def test_corrupt_truncated_record_raises(tmp_path):
    path = tmp_path / "truncated.pcap"
    path.write_bytes(build_pcap([tcp_frame()])[:-20])  # cut into the frame data

    with pytest.raises(CorruptCaptureError):
        CaptureLoader().load_capture(str(path))


def test_zero_byte_file_raises(tmp_path):
    path = tmp_path / "nothing.pcap"
    path.write_bytes(b"")

    with pytest.raises(CorruptCaptureError):
        CaptureLoader().load_capture(str(path))


def test_unsupported_format_raises(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_bytes(b"GIF89a this is not a capture file at all")

    with pytest.raises(UnsupportedFormatError):
        CaptureLoader().load_capture(str(path))


def test_missing_file_raises_corrupt_error(tmp_path):
    with pytest.raises(CorruptCaptureError):
        CaptureLoader().load_capture(str(tmp_path / "absent.pcap"))


def test_loads_pcapng(tmp_path):
    frames = [tcp_frame(), arp_frame()]
    buffer = io.BytesIO()
    writer = dpkt.pcapng.Writer(buffer)
    for index, frame in enumerate(frames):
        writer.writepkt(frame, ts=float(index + 1))
    path = tmp_path / "capture.pcapng"
    path.write_bytes(buffer.getvalue())

    packets = CaptureLoader().load_capture(str(path))

    assert len(packets) == len(frames)
    assert packets[1].raw_bytes == frames[1]


def test_captured_len_exceeding_wire_len_raises(tmp_path):
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_hdr = struct.pack("<IIII", 1000, 0, 100, 50)  # caplen=100 > wirelen=50
    path = tmp_path / "bad_len.pcap"
    path.write_bytes(global_hdr + record_hdr + b"X" * 100)

    with pytest.raises(CorruptCaptureError) as exc_info:
        CaptureLoader().load_capture(str(path))
    assert "exceeds wire length" in str(exc_info.value)


def test_nanosecond_pcap_timestamp_resolution(tmp_path):
    frame = tcp_frame()
    global_hdr = b"\x4d\x3c\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    record_hdr = struct.pack("<IIII", 100, 500_000_000, len(frame), len(frame))
    path = tmp_path / "nanosec.pcap"
    path.write_bytes(global_hdr + record_hdr + frame)

    packets = CaptureLoader().load_capture(str(path))
    assert len(packets) == 1
    assert packets[0].timestamp == pytest.approx(100.5)

