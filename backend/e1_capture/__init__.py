"""Engine E1 - Packet & Frame Processing.

Provides:
- CaptureLoader: PCAP/PCAPNG capture file streaming.
- BoundedRingBuffer: Thread-safe bounded circular ring buffer with condition variables.
- LiveCaptureEngine: Live OS promiscuous raw socket packet capture.
- ReplayCaptureEngine: Offline PCAP replay driver for testing and multi-probe simulation.
"""

from __future__ import annotations

from .engine import CaptureLoader
from .live import LiveCaptureEngine, ReplayCaptureEngine
from .ring_buffer import BoundedRingBuffer

__all__ = [
    "CaptureLoader",
    "BoundedRingBuffer",
    "LiveCaptureEngine",
    "ReplayCaptureEngine",
]
