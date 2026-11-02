"""Engine E1 - Packet & Frame Processing.

Loads PCAP/PCAPNG capture files and turns every record into a
:class:`backend.models.Packet`.

Also provides :class:`LiveCapture` for real-time packet capture via
scapy/Npcap (Windows) or libpcap (Linux/macOS).
"""

from __future__ import annotations

from .engine import CaptureLoader
from .live import LiveCapture

__all__ = ["CaptureLoader", "LiveCapture"]
