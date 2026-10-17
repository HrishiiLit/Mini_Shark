"""Engine E1 - Packet & Frame Processing.

Loads PCAP/PCAPNG capture files and turns every record into a
:class:`backend.models.Packet`.
"""

from __future__ import annotations

from .engine import CaptureLoader

__all__ = ["CaptureLoader"]
