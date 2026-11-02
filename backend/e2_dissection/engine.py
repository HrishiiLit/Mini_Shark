"""Protocol dissection engine (E2).

The walker starts at the link layer and keeps dispatching until a handler
claims the bytes or no handler is registered. Errors inside a single handler
are contained per packet: the packet keeps the layers decoded so far and the
remainder is preserved as ``undecoded_bytes``.

Phase 3 additions
-----------------
* ``_compute_fingerprint``  — 64-bit BLAKE2b (digest_size=8) over path-invariant
                              header fields selected by ``extract_invariant_fields``.
* ``_dns_shannon_entropy``  — Shannon entropy H(X) = -Σ p·log₂(p) over the
                              characters of the first DNS query name.
* ``_make_telemetry``       — build a ``ProbeTelemetry`` 24-byte wire record from
                              a decoded packet and its capture metadata.
* ``ProtocolDissector.dissect_one`` now attaches ``fingerprint`` and
  ``dns_entropy`` to the returned ``DecodedPacket``.
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
from collections.abc import Iterable

from backend.interfaces import EngineE2
from backend.models import DecodedPacket, Layer, Packet, PacketFingerprint, ProbeTelemetry

from .protocols import build_default_registry, extract_invariant_fields
from .registry import Dispatch, DissectorRegistry

# Errors a damaged header can raise; contained inside a single packet.
_HEADER_ERRORS = (struct.error, ValueError, IndexError, KeyError, UnicodeError)

# ---------------------------------------------------------------------------
# Fingerprint algorithm constants  (data_contract.md §3)
# ---------------------------------------------------------------------------
_FP_ALGORITHM = "blake2b-64"
_FP_VERSION = 1          # bump when the invariant field set changes


# ---------------------------------------------------------------------------
# Layer walker (unchanged from Phase 1)
# ---------------------------------------------------------------------------

def _walk(data: bytes, dispatch: Dispatch, registry: DissectorRegistry) -> list[Layer]:
    """Decode ``data`` layer by layer until the dispatch chain ends."""
    layers: list[Layer] = []
    namespace, candidates = dispatch
    while data:
        entry = registry.lookup(namespace, candidates)
        if entry is None:
            break
        name, handler = entry
        try:
            layer, payload, next_dispatch = handler(data)
        except _HEADER_ERRORS:
            layers.append(Layer(name, {"malformed": True}, undecoded_bytes=data))
            return layers
        layers.append(layer)
        if payload is None:
            return layers
        data = payload
        if next_dispatch is None:
            break
        namespace, candidates = next_dispatch
    if data:
        layers.append(Layer("Payload", {}, undecoded_bytes=data))
    return layers


# ---------------------------------------------------------------------------
# Phase 3 — fingerprinting
# ---------------------------------------------------------------------------

def _compute_fingerprint(layers: list[Layer]) -> PacketFingerprint | None:
    """Compute the 64-bit BLAKE2b fingerprint for a decoded packet.

    Returns ``None`` when the packet has no IP layer (e.g. pure ARP frames),
    since there are no path-invariant transport fields to hash.

    Algorithm (data_contract.md §3, version 1):
      1. Call ``extract_invariant_fields`` to get the ordered, tagged byte blob.
      2. Feed blob into ``hashlib.blake2b(digest_size=8)``.
      3. Interpret the 8-byte digest as a big-endian unsigned 64-bit integer.
    """
    blob, fields_used = extract_invariant_fields(layers)
    if not blob:
        # No IP layer or all IP fields were malformed — cannot fingerprint
        return None

    digest = hashlib.blake2b(blob, digest_size=8).digest()
    value = int.from_bytes(digest, "big")

    return PacketFingerprint(
        algorithm=_FP_ALGORITHM,
        version=_FP_VERSION,
        value=value,
        fields_used=fields_used,
    )


# ---------------------------------------------------------------------------
# Phase 3 — DNS Shannon entropy
# ---------------------------------------------------------------------------

def _dns_shannon_entropy(layers: list[Layer]) -> float | None:
    """Compute Shannon entropy H(X) over characters of the first DNS query name.

    H(X) = -Σ p(c) · log₂(p(c))   for each unique character c in the name.

    Returns ``None`` when no DNS layer with at least one question is present,
    or when the query name is empty.

    The entropy value itself is returned here.  The *classification* threshold
    (H > 4.2 → possible exfiltration) lives in E4 per the data contract.
    """
    for layer in layers:
        if layer.name != "DNS":
            continue
        questions = layer.fields.get("questions", [])
        if not questions:
            return None
        name: str = questions[0].get("name", "")
        # Strip the trailing dot if present (root label)
        name = name.rstrip(".")
        if not name:
            return None

        # Count character frequencies (case-folded; dots are meaningful
        # in DNS names as label separators, so they are included)
        freq: dict[str, int] = {}
        for ch in name:
            freq[ch] = freq.get(ch, 0) + 1

        total = len(name)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    return None


# ---------------------------------------------------------------------------
# Phase 3 — telemetry record builder
# ---------------------------------------------------------------------------

_TELEMETRY_RECORD_TYPE_PACKET = 1   # bits 0-3 of type_flags
_TELEMETRY_FORMAT_VERSION = 1       # bits 4-7 of type_flags (stored as nibble)


def _make_telemetry(
    decoded: DecodedPacket,
    packet: Packet,
    probe_id: int = 1,
    seq: int = 0,
) -> ProbeTelemetry | None:
    """Build a 24-byte ``ProbeTelemetry`` record for this decoded packet.

    Returns ``None`` if no fingerprint is present (e.g. ARP, fully malformed),
    since the fingerprint is the mandatory correlation key.

    Args:
        decoded  : the decoded packet from ``dissect_one``.
        packet   : the originating raw ``Packet`` (for timestamp and length).
        probe_id : probe identity (1–255); defaults to 1 for offline/test mode.
        seq      : per-probe monotonic counter; caller increments between calls.

    Wire format (data_contract.md §4):
        type_flags = (format_version_nibble << 4) | record_type_nibble
    """
    if decoded.fingerprint is None:
        return None

    # Timestamp: use the packet's float timestamp converted to integer nanoseconds.
    # In live mode E1 provides ns-precision uint64; in offline/PCAP mode the
    # timestamp is a float (seconds).  We normalise to ns here.
    ts = packet.timestamp
    if isinstance(ts, float):
        timestamp_ns = int(ts * 1_000_000_000)
    else:
        timestamp_ns = int(ts)

    type_flags = ((_TELEMETRY_FORMAT_VERSION & 0x0F) << 4) | (_TELEMETRY_RECORD_TYPE_PACKET & 0x0F)

    return ProbeTelemetry(
        fingerprint=decoded.fingerprint.value,
        timestamp_ns=timestamp_ns,
        seq=seq & 0xFFFFFFFF,
        probe_id=probe_id & 0xFF,
        type_flags=type_flags,
        captured_len=packet.length & 0xFFFF,
    )


# ---------------------------------------------------------------------------
# ProtocolDissector — the main E2 class
# ---------------------------------------------------------------------------

class ProtocolDissector(EngineE2):
    """Default E2 implementation driven by a :class:`DissectorRegistry`.

    Phase 3 behaviour:
    - ``dissect_one`` now computes a ``PacketFingerprint`` and attaches it to
      the returned ``DecodedPacket``.
    - DNS Shannon entropy is computed and attached to ``DecodedPacket.dns_entropy``.
    - ``make_telemetry`` is a public helper for callers (E1/E2 probe runtime)
      that need the 24-byte wire record.
    """

    def __init__(self, registry: DissectorRegistry | None = None) -> None:
        self._registry = registry if registry is not None else build_default_registry()

    @property
    def registry(self) -> DissectorRegistry:
        return self._registry

    def dissect(self, packets: Iterable[Packet]) -> list[DecodedPacket]:
        """Decode every packet; a bad packet never stops the batch."""
        return [self.dissect_one(packet) for packet in packets]

    def dissect_one(self, packet: Packet) -> DecodedPacket:
        """Build the protocol tree, fingerprint, and DNS entropy for one frame.

        Never raises — all per-packet errors are contained inside the returned
        ``DecodedPacket`` (malformed flags, undecoded_bytes, None fingerprint).
        """
        try:
            layers = _walk(packet.raw_bytes, ("link", (1,)), self._registry)
        except _HEADER_ERRORS:
            layers = [Layer("Undecoded", {}, undecoded_bytes=packet.raw_bytes)]

        # Phase 3 additions — both are safe even for malformed packets
        fingerprint = _compute_fingerprint(layers)
        dns_entropy = _dns_shannon_entropy(layers)

        return DecodedPacket(
            packet_index=packet.index,
            layers=layers,
            fingerprint=fingerprint,
            dns_entropy=dns_entropy,
        )

    def make_telemetry(
        self,
        decoded: DecodedPacket,
        packet: Packet,
        probe_id: int = 1,
        seq: int = 0,
    ) -> ProbeTelemetry | None:
        """Public helper: build the 24-byte telemetry record for one packet.

        Returns ``None`` for packets that have no fingerprint (ARP, malformed).
        Callers in probe-runtime code maintain their own ``seq`` counter and
        pass it here; this class does not track sequence numbers.
        """
        return _make_telemetry(decoded, packet, probe_id=probe_id, seq=seq)
