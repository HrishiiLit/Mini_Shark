"""Engine E2 - Protocol Dissection.

Turns raw frames from E1 into an ordered protocol tree
(:class:`backend.models.DecodedPacket`).
"""

from __future__ import annotations

from .engine import ProtocolDissector
from .protocols import build_default_registry
from .registry import DissectorRegistry

__all__ = ["DissectorRegistry", "ProtocolDissector", "build_default_registry"]
