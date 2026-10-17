"""End-to-end pipeline tests: E1 -> E2 -> E3 -> E4 in one call."""

from __future__ import annotations

import pytest
from helpers import arp_frame, build_pcap, tcp_frame, udp_frame

from backend.e4_query import QueryEngine
from backend.pipeline import analyze, sha256_file


def _write_capture(tmp_path) -> str:
    frames = [
        tcp_frame(src="10.0.0.1", dst="10.0.0.2", dport=80),
        tcp_frame(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=12345),
        udp_frame(dport=53),
        arp_frame(),
    ]
    path = tmp_path / "sample.pcap"
    path.write_bytes(build_pcap(frames))
    return str(path)


def test_analyze_runs_all_engines_in_memory(tmp_path):
    result = analyze(_write_capture(tmp_path))

    assert len(result.packets) == 4
    assert len(result.decoded) == 4
    assert len(result.flows) == 3  # TCP conversation + UDP flow + ungrouped bucket
    assert result.capture_id is None
    assert set(result.statistics) == {"TCP", "UDP", "UNGROUPED"}


def test_analyze_persists_when_given_an_engine(tmp_path):
    engine = QueryEngine(str(tmp_path / "analysis.db"))

    result = analyze(_write_capture(tmp_path), engine=engine, name="sample.pcap")

    assert result.capture_id is not None
    assert len(engine.query("")) == len(result.flows)
    assert len(engine.packets(result.capture_id)) == 4
    assert engine.tree(result.capture_id, 0)  # protocol tree was stored too
    engine.close()


def test_sha256_file_is_stable(tmp_path):
    path = _write_capture(tmp_path)

    assert sha256_file(path) == sha256_file(path)
    assert len(sha256_file(path)) == 64


def test_corrupt_capture_propagates_typed_error(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1 not a real capture")

    from backend.errors import CorruptCaptureError

    with pytest.raises(CorruptCaptureError):
        analyze(path)
