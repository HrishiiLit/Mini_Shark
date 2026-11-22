"""Five-tuple flow grouping for Engine E3.

Rules (see ``docs/implementation.md`` and ``docs/data_contract.md``):

- Both directions of a conversation collapse into one flow: the two
  endpoints are normalised into a canonical order before hashing.
- Packets without a usable five-tuple (ARP, bare Ethernet, ...) are kept in
  an explicit "ungrouped" bucket - never dropped.
- Output order is the ascending first-packet index, so two runs on the same
  input produce byte-identical JSON (NFR-07).
- ``byte_count`` and timestamps come from the ``Packet`` records when E3 is
  given them; otherwise they are best-effort values derived from the layers.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from backend.interfaces import EngineE3
from backend.models import DecodedPacket, Flow, Packet

UNGROUPED_FLOW_ID = -1
UNGROUPED_TUPLE: tuple[str, str, int, int, str] = ("", "", 0, 0, "UNGROUPED")

_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

Endpoint = tuple[str, int]
FlowKey = tuple[str, Endpoint, Endpoint]


@dataclass
class _Bucket:
    """Mutable accumulator for one flow while packets stream past."""

    five_tuple: tuple[str, str, int, int, str]
    first_index: int
    packet_indices: list[int] = field(default_factory=list)
    byte_count: int = 0
    start_ts: float | None = None
    end_ts: float | None = None

    def add(self, index: int, size: int, timestamp: float | None) -> None:
        self.packet_indices.append(index)
        self.byte_count += size
        if timestamp is None:
            return
        if self.start_ts is None or timestamp < self.start_ts:
            self.start_ts = timestamp
        if self.end_ts is None or timestamp > self.end_ts:
            self.end_ts = timestamp

    def to_flow(self, flow_id: int) -> Flow:
        duration = None
        if self.start_ts is not None and self.end_ts is not None:
            duration = self.end_ts - self.start_ts
        return Flow(
            flow_id=flow_id,
            five_tuple=self.five_tuple,
            packet_indices=list(self.packet_indices),
            byte_count=self.byte_count,
            start_ts=self.start_ts,
            end_ts=self.end_ts,
            duration=duration,
        )


class FlowGrouper(EngineE3):
    """Default E3 implementation: pure function of the decoded packet list."""

    def group(
        self,
        decoded: Iterable[DecodedPacket],
        packets: Iterable[Packet] | None = None,
    ) -> list[Flow]:
        sizes, stamps = _packet_lookup(packets)
        buckets: dict[FlowKey, _Bucket] = {}
        ungrouped: _Bucket | None = None

        for item in decoded:
            size = sizes.get(item.packet_index)
            if size is None:
                size = _size_from_layers(item)
            stamp = stamps.get(item.packet_index)
            key = _flow_key(item)
            if key is None:
                if ungrouped is None:
                    ungrouped = _Bucket(UNGROUPED_TUPLE, item.packet_index)
                ungrouped.add(item.packet_index, size, stamp)
                continue
            bucket = buckets.get(key)
            if bucket is None:
                bucket = _Bucket(_canonical_tuple(key), item.packet_index)
                buckets[key] = bucket
            bucket.add(item.packet_index, size, stamp)

        return _materialise(buckets.values(), ungrouped)

    @staticmethod
    def statistics(flows: Iterable[Flow]) -> dict[str, dict[str, float]]:
        """Per-protocol packet/byte share over the given flows."""
        buckets: dict[str, list[int]] = {}
        for flow in flows:
            proto = flow.five_tuple[4]
            entry = buckets.setdefault(proto, [0, 0])
            entry[0] += flow.packet_count
            entry[1] += flow.byte_count
        total_bytes = sum(entry[1] for entry in buckets.values()) or 1
        return {
            proto: {
                "packets": counts[0],
                "bytes": counts[1],
                "share": counts[1] / total_bytes,
            }
            for proto, counts in sorted(buckets.items())
        }


def _materialise(buckets: Iterable[_Bucket], ungrouped: _Bucket | None) -> list[Flow]:
    """Sort by first packet index and assign stable flow ids from 1."""
    ordered = sorted(buckets, key=lambda bucket: bucket.first_index)
    if ungrouped is not None:
        ordered.append(ungrouped)
    flows = []
    for position, bucket in enumerate(ordered, start=1):
        flow_id = UNGROUPED_FLOW_ID if bucket is ungrouped else position
        flows.append(bucket.to_flow(flow_id))
    return flows


def _packet_lookup(
    packets: Iterable[Packet] | None,
) -> tuple[dict[int, int], dict[int, float]]:
    if packets is None:
        return {}, {}
    sizes: dict[int, int] = {}
    stamps: dict[int, float] = {}
    for packet in packets:
        sizes[packet.index] = packet.length
        stamps[packet.index] = packet.timestamp
    return sizes, stamps


def _flow_key(item: DecodedPacket) -> FlowKey | None:
    """Canonical (direction-independent) five-tuple, or ``None`` if unusable."""
    endpoints = _endpoints(item)
    if endpoints is None:
        return None
    src, dst = sorted(endpoints)
    protocol = _protocol_name(item)
    if protocol is None:
        return None
    return protocol, src, dst


def _endpoints(item: DecodedPacket) -> tuple[Endpoint, Endpoint] | None:
    addresses: tuple[str, str] | None = None
    ports: tuple[int, int] = (0, 0)
    for layer in item.layers:
        if layer.name in ("IPv4", "IPv6"):
            src, dst = layer.fields.get("src"), layer.fields.get("dst")
            if isinstance(src, str) and isinstance(dst, str):
                addresses = (src, dst)
        elif layer.name in ("TCP", "UDP"):
            src_port = int(layer.fields.get("src_port", 0))
            dst_port = int(layer.fields.get("dst_port", 0))
            ports = (src_port, dst_port)
    if addresses is None:
        return None
    src_ip, dst_ip = addresses
    return (src_ip, ports[0]), (dst_ip, ports[1])


def _protocol_name(item: DecodedPacket) -> str | None:
    for layer in item.layers:
        if layer.name in ("IPv4", "IPv6"):
            number = layer.fields.get("protocol", layer.fields.get("next_header"))
            if number is None:
                return None
            if isinstance(number, int):
                return _PROTOCOL_NAMES.get(number, str(number))
            return str(number)
        if layer.name in ("TCP", "UDP"):
            return layer.name
    return None


def _canonical_tuple(key: FlowKey) -> tuple[str, str, int, int, str]:
    protocol, (src_ip, src_port), (dst_ip, dst_port) = key
    return src_ip, dst_ip, src_port, dst_port, protocol


def _size_from_layers(item: DecodedPacket) -> int:
    """Best-effort byte size when the caller did not pass ``Packet`` records."""
    for layer in item.layers:
        if layer.name == "IPv4":
            return int(layer.fields.get("total_length", 0))
        if layer.name == "IPv6":
            return int(layer.fields.get("payload_length", 0)) + 40
    return 0
