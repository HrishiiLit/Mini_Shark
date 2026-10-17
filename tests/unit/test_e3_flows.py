"""Engine E3 tests: five-tuple grouping, ungrouped bucket, determinism."""

from __future__ import annotations

import pytest
from helpers import arp_frame, tcp_frame, udp_frame

from backend.e2_dissection import ProtocolDissector
from backend.e3_flows import FlowGrouper
from backend.models import Packet


def _packets(frames: list[bytes], timestamps: list[float]) -> list[Packet]:
    return [
        Packet(index=index, timestamp=stamp, length=len(frame), raw_bytes=frame)
        for index, (frame, stamp) in enumerate(zip(frames, timestamps, strict=True))
    ]


def _group(frames: list[bytes], timestamps: list[float] | None = None):
    stamps = timestamps or [float(index + 1) for index in range(len(frames))]
    packets = _packets(frames, stamps)
    decoded = ProtocolDissector().dissect(packets)
    return FlowGrouper().group(decoded, packets)


def test_bidirectional_conversation_is_one_flow():
    frames = [
        tcp_frame(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80),
        tcp_frame(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=12345),
    ]

    flows = _group(frames, [1.0, 3.0])

    assert len(flows) == 1
    flow = flows[0]
    assert flow.packet_count == 2
    assert flow.packet_indices == [0, 1]
    assert flow.byte_count == sum(len(frame) for frame in frames)
    assert flow.start_ts == 1.0
    assert flow.end_ts == 3.0
    assert flow.duration == pytest.approx(2.0)
    assert flow.five_tuple[4] == "TCP"
    assert flow.five_tuple[:2] == ("10.0.0.1", "10.0.0.2")
    assert flow.five_tuple[2:4] == (12345, 80)


def test_distinct_conversations_produce_distinct_flows():
    frames = [
        tcp_frame(dport=80),
        tcp_frame(dport=443),
        udp_frame(dport=53),
    ]

    flows = _group(frames)

    assert len(flows) == 3
    assert {flow.five_tuple[4] for flow in flows} == {"TCP", "UDP"}


def test_arp_goes_to_the_ungrouped_bucket():
    flows = _group([arp_frame(), tcp_frame()])

    ungrouped = [flow for flow in flows if flow.flow_id == -1]
    assert len(ungrouped) == 1
    assert ungrouped[0].packet_indices == [0]
    assert ungrouped[0].five_tuple[4] == "UNGROUPED"
    assert ungrouped[0].packet_count == 1

    tcp_flows = [flow for flow in flows if flow.five_tuple[4] == "TCP"]
    assert len(tcp_flows) == 1
    assert tcp_flows[0].packet_indices == [1]


def test_flow_ids_follow_first_packet_order():
    frames = [udp_frame(dport=53), tcp_frame(dport=80)]

    flows = _group(frames)

    assert [flow.five_tuple[4] for flow in flows] == ["UDP", "TCP"]
    assert [flow.flow_id for flow in flows] == [1, 2]


def test_grouping_is_deterministic():
    frames = [tcp_frame(), tcp_frame(src="10.0.0.2", dst="10.0.0.1"), arp_frame()]

    first = _group(frames)
    second = _group(frames)

    assert first == second


def test_statistics_share_sums_to_one():
    flows = _group([tcp_frame(), tcp_frame(), udp_frame()])

    stats = FlowGrouper.statistics(flows)

    assert set(stats) == {"TCP", "UDP"}
    assert sum(entry["share"] for entry in stats.values()) == pytest.approx(1.0)
    assert stats["TCP"]["packets"] == 2


def test_group_without_packet_records_still_works():
    packets = _packets([tcp_frame(), tcp_frame()], [1.0, 2.0])
    decoded = ProtocolDissector().dissect(packets)

    flows = FlowGrouper().group(decoded)

    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].byte_count == sum(
        int(layer.fields["total_length"])
        for item in decoded
        for layer in item.layers
        if layer.name == "IPv4"
    )
    assert flows[0].duration is None


def test_empty_input_gives_no_flows():
    assert FlowGrouper().group([]) == []
