"""Shared data models for Mini Shark.

These dataclasses define the contract between the four engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Packet:
    """Engine E1 - raw packet information.

    index: sequential number starting at 0
    timestamp: epoch seconds as float (or int nanoseconds)
    length: total packet length in bytes
    raw_bytes: bytes of the entire frame
    """

    index: int
    timestamp: float
    length: int
    raw_bytes: bytes


@dataclass(frozen=True)
class Layer:
    """A protocol layer in the decoded packet tree.

    name: protocol name (e.g. 'Ethernet', 'IPv4')
    fields: mapping of field name → value (already parsed)
    undecoded_bytes: any remaining bytes that could not be parsed for this layer
    """

    name: str
    fields: dict[str, Any]
    undecoded_bytes: bytes = b""


@dataclass(frozen=True)
class DecodedPacket:
    """Engine E2 - hierarchical protocol representation.

    packet_index: original Packet.index
    layers: ordered list of Layer objects from lowest (link) to highest (application)
    """

    packet_index: int
    layers: list[Layer] = field(default_factory=list)


@dataclass(frozen=True)
class Flow:
    """Engine E3 - grouping of packets into a flow.

    flow_id: unique identifier for the flow (e.g. UUID or simple int)
    five_tuple: tuple(src_ip, dst_ip, src_port, dst_port, protocol)
    packet_indices: list of packet indexes belonging to this flow
    packet_count: int - derived from len(packet_indices)
    byte_count: int - sum of packet lengths
    start_ts: float - timestamp of first packet in flow
    end_ts: float - timestamp of last packet in flow
    duration: float - end_ts - start_ts
    """

    flow_id: int
    five_tuple: tuple[str, str, int, int, str]
    packet_indices: list[int] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0
    start_ts: float | None = None
    end_ts: float | None = None
    duration: float | None = None

    def __post_init__(self) -> None:
        # Defensive: compute derived fields if not provided
        object.__setattr__(self, "packet_count", len(self.packet_indices))
        # byte_count, start_ts, end_ts, duration are left to the engine to fill
        pass
