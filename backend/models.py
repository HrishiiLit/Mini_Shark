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

    packet_index : original Packet.index
    layers       : ordered list of Layer objects from lowest (link) to highest (application)
    fingerprint  : 64-bit BLAKE2b fingerprint computed from path-invariant fields
                   (None if the packet has no IP layer or is fully malformed)
    dns_entropy  : Shannon entropy H(X) of the first DNS query name in this
                   packet (None if no DNS query is present)
    """

    packet_index: int
    layers: list[Layer] = field(default_factory=list)
    fingerprint: "PacketFingerprint | None" = None
    dns_entropy: "float | None" = None


@dataclass(frozen=True)
class PacketFingerprint:
    """E2 — stable 64-bit fingerprint derived from path-invariant header fields.

    algorithm : always "blake2b-64" for version 1.
    version   : field-set version; bump whenever the input field set changes
                so that E3 can reject cross-version matches.
    value     : the 64-bit (8-byte) digest interpreted as an unsigned integer.
    fields_used: which fields were hashed (debug / telemetry metadata only;
                 not transmitted in the 24-byte wire record).
    """

    algorithm: str
    version: int
    value: int  # uint64 — the raw 8-byte digest as an integer
    fields_used: list[str]


@dataclass(frozen=True)
class ProbeTelemetry:
    """E2 → E3 — 24-byte fixed-size wire record sent over TCP port 9000.

    Wire layout (big-endian, version 1):
      offset  0, 8 bytes : fingerprint  (uint64)
      offset  8, 8 bytes : timestamp_ns (uint64)
      offset 16, 4 bytes : seq          (uint32)
      offset 20, 1 byte  : probe_id     (uint8)
      offset 21, 1 byte  : type_flags   (uint8)
                               bits 0-3 : record type  (1 = packet data)
                               bits 4-7 : format version nibble (0001 = v1)
      offset 22, 2 bytes : captured_len (uint16)
      total  : 24 bytes
    """

    fingerprint: int   # uint64 — PacketFingerprint.value
    timestamp_ns: int  # uint64 — probe-local capture time, ns since epoch
    seq: int           # uint32 — per-probe monotonic packet counter
    probe_id: int      # uint8  — 1-255
    type_flags: int    # uint8  — record type + version nibble
    captured_len: int  # uint16 — captured bytes (evidence only)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def pack(self) -> bytes:
        """Serialize to the 24-byte big-endian wire record."""
        import struct  # local import keeps the dataclass dependency-free

        return struct.pack(
            "!QQIBBH",
            self.fingerprint & 0xFFFFFFFFFFFFFFFF,
            self.timestamp_ns & 0xFFFFFFFFFFFFFFFF,
            self.seq & 0xFFFFFFFF,
            self.probe_id & 0xFF,
            self.type_flags & 0xFF,
            self.captured_len & 0xFFFF,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "ProbeTelemetry":
        """Deserialize from exactly 24 bytes."""
        import struct

        if len(data) != 24:
            raise ValueError(f"ProbeTelemetry.unpack: expected 24 bytes, got {len(data)}")
        fingerprint, timestamp_ns, seq, probe_id, type_flags, captured_len = struct.unpack(
            "!QQIBBH", data
        )
        return cls(
            fingerprint=fingerprint,
            timestamp_ns=timestamp_ns,
            seq=seq,
            probe_id=probe_id,
            type_flags=type_flags,
            captured_len=captured_len,
        )


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
