"""Protocol dissection engine (E2).

The walker starts at the link layer and keeps dispatching until a handler
claims the bytes or no handler is registered. Errors inside a single handler
are contained per packet: the packet keeps the layers decoded so far and the
remainder is preserved as ``undecoded_bytes``.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

from backend.interfaces import EngineE2
from backend.models import DecodedPacket, Layer, Packet

from .protocols import build_default_registry
from .registry import Dispatch, DissectorRegistry

# Errors a damaged header can raise; contained inside a single packet.
_HEADER_ERRORS = (struct.error, ValueError, IndexError, KeyError, UnicodeError)


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


class ProtocolDissector(EngineE2):
    """Default E2 implementation driven by a :class:`DissectorRegistry`."""

    def __init__(self, registry: DissectorRegistry | None = None) -> None:
        self._registry = registry if registry is not None else build_default_registry()

    @property
    def registry(self) -> DissectorRegistry:
        return self._registry

    def dissect(self, packets: Iterable[Packet]) -> list[DecodedPacket]:
        """Decode every packet; a bad packet never stops the batch."""
        return [self.dissect_one(packet) for packet in packets]

    def dissect_one(self, packet: Packet) -> DecodedPacket:
        """Build the protocol tree for a single frame."""
        try:
            layers = _walk(packet.raw_bytes, ("link", (1,)), self._registry)
        except _HEADER_ERRORS:
            layers = [Layer("Undecoded", {}, undecoded_bytes=packet.raw_bytes)]
        return DecodedPacket(packet_index=packet.index, layers=layers)
