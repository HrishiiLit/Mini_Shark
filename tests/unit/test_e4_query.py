"""Engine E4 tests: storage round-trip, filters, and failure behaviour."""

from __future__ import annotations

import pytest
from helpers import arp_frame, tcp_frame, udp_frame

from backend.e2_dissection import ProtocolDissector
from backend.e3_flows import FlowGrouper
from backend.e4_query import QueryEngine, compile_filter
from backend.errors import FilterSyntaxError
from backend.models import Packet


def _build_analysis():
    frames = [
        tcp_frame(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80),
        tcp_frame(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=12345),
        udp_frame(src="10.0.0.1", dst="10.0.0.3", dport=53),
        arp_frame(),
    ]
    packets = [
        Packet(
            index=index,
            timestamp=float(index + 1),
            length=len(frame),
            raw_bytes=frame,
        )
        for index, frame in enumerate(frames)
    ]
    decoded = ProtocolDissector().dissect(packets)
    flows = FlowGrouper().group(decoded, packets)
    return packets, decoded, flows


def _stored(tmp_path, db_name: str = "mini.db"):
    engine = QueryEngine(str(tmp_path / db_name))
    packets, decoded, flows = _build_analysis()
    capture_id = engine.store(
        flows, packets, name="sample.pcap", file_hash="abc123", decoded=decoded
    )
    return engine, capture_id, flows


def test_store_then_reload_matches_record_counts(tmp_path):
    engine, capture_id, flows = _stored(tmp_path)

    assert capture_id == 1
    assert len(engine.query("")) == len(flows)
    assert len(engine.packets(capture_id)) == 4
    assert len(engine.tree(capture_id, 0)) == 3  # Ethernet / IPv4 / TCP


def test_data_survives_reopening_the_database(tmp_path):
    engine, _capture_id, flows = _stored(tmp_path)
    engine.close()

    reopened = QueryEngine(str(tmp_path / "mini.db"))

    assert len(reopened.query("")) == len(flows)
    reopened.close()


def test_protocol_filter_returns_only_matching_flows(tmp_path):
    engine, _capture_id, _flows = _stored(tmp_path)

    tcp_only = engine.query('protocol == "TCP"')
    udp_only = engine.query("protocol == UDP")  # bare words are literals too

    assert {flow.five_tuple[4] for flow in tcp_only} == {"TCP"}
    assert {flow.five_tuple[4] for flow in udp_only} == {"UDP"}


def test_ip_and_port_filters(tmp_path):
    engine, _capture_id, _flows = _stored(tmp_path)

    by_dst = engine.query("ip.dst == 10.0.0.3")
    on_port = engine.query("tcp.port == 80")
    dns = engine.query("udp.port == 53")

    assert len(by_dst) == 1
    assert by_dst[0].five_tuple[4] == "UDP"
    assert len(on_port) == 1
    assert on_port[0].five_tuple[4] == "TCP"
    assert len(dns) == 1


def test_numeric_and_text_operators(tmp_path):
    engine, _capture_id, _flows = _stored(tmp_path)

    assert all(flow.byte_count > 0 for flow in engine.query("bytes > 0"))
    assert engine.query("bytes < 0") == []
    assert engine.query('ip.dst startswith "10.0.0.2"') != []
    assert engine.query('protocol contains "TC"') != []


def test_empty_result_is_a_list_not_an_error(tmp_path):
    engine, _capture_id, _flows = _stored(tmp_path)

    assert engine.query('protocol == "SCTP"') == []


def test_unknown_field_raises_filter_error(tmp_path):
    engine, _capture_id, _flows = _stored(tmp_path)

    with pytest.raises(FilterSyntaxError, match="unknown field"):
        engine.query("exploit.score == 1")


def test_malformed_filters_raise_instead_of_crashing(tmp_path):
    engine, _capture_id, _flows = _stored(tmp_path)

    for bad in ("ip.src ==", "bytes > &&", "((protocol", "!!!", "protocol >="):
        with pytest.raises(FilterSyntaxError):
            engine.query(bad)


def test_filter_values_are_never_interpolated_into_sql(tmp_path):
    engine, capture_id, flows = _stored(tmp_path)
    payload = "10.0.0.1'; DROP TABLE flows; --"

    result = engine.query(f'ip.src == "{payload}"')

    assert result == []
    assert len(engine.query("")) == len(flows)  # table is intact
    assert engine.packets(capture_id)  # so are the packets


def test_compile_filter_output_is_parameterised():
    where, params = compile_filter('ip.src == "10.0.0.1" && bytes > 100')

    assert "?" in where
    assert "10.0.0.1" not in where
    assert params == ["10.0.0.1", 100]


def test_empty_filter_matches_everything(tmp_path):
    engine, _capture_id, flows = _stored(tmp_path)

    assert compile_filter("   ") == ("", [])
    assert len(engine.query("")) == len(flows)


def test_unknown_flow_lookup_returns_none(tmp_path):
    engine, capture_id, _flows = _stored(tmp_path)

    assert engine.flow(capture_id, 9999) is None
    assert engine.flow(capture_id, 1) is not None
