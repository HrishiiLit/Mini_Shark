"""Live packet capture for Engine E1 — Windows/Npcap via scapy.

Usage (standalone)::

    from backend.e1_capture.live import LiveCapture

    packets = LiveCapture().capture(count=50, iface="Wi-Fi")
    # returns list[Packet] — same model as offline CaptureLoader

Requirements:
    - Npcap installed  (https://npcap.com)
    - Run as Administrator  (required for raw packet capture on Windows)
    - scapy installed  (pip install scapy)
"""

from __future__ import annotations

import time
from collections.abc import Iterator

from backend.models import Packet

# Scapy import is deferred so that the rest of the project still imports
# correctly on machines where scapy is not installed.
try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.l2 import Ether
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# Default interface preference order for Windows (friendly names)
_WINDOWS_IFACE_HINTS = ["Wi-Fi", "Wireless", "WLAN", "Ethernet", "eth0", "en0"]


def _pick_interface(iface: str | None) -> str:
    """Return the best available scapy network_name for an interface.

    On Windows, scapy uses GUID-style network_names internally but also
    exposes a human-readable ``name`` (friendly name) and ``description``.
    We match against the friendly name so the user can say ``--iface Wi-Fi``
    and get the right GUID automatically.

    If ``iface`` is given explicitly we try to match it against friendly
    names first; if no match is found we pass it through as-is.
    """
    if not _SCAPY_AVAILABLE:
        return iface or "Wi-Fi"

    try:
        from scapy.all import IFACES
        iface_list = list(IFACES.values())
    except Exception:
        return iface or conf.iface

    if iface:
        # Try to match the user's string against friendly name or description
        iface_lower = iface.lower()
        for entry in iface_list:
            name = getattr(entry, "name", "")
            desc = getattr(entry, "description", "")
            if iface_lower in name.lower() or iface_lower in desc.lower():
                return getattr(entry, "network_name", name)
        # No match — pass through as-is (might be a GUID already)
        return iface

    # Auto-select: walk hints and pick the first match
    for hint in _WINDOWS_IFACE_HINTS:
        for entry in iface_list:
            name = getattr(entry, "name", "")
            desc = getattr(entry, "description", "")
            if hint.lower() in name.lower() or hint.lower() in desc.lower():
                network_name = getattr(entry, "network_name", name)
                return network_name

    return conf.iface


class LiveCapture:
    """Capture live packets from a network interface using scapy/Npcap.

    This is the live-mode counterpart of :class:`~backend.e1_capture.engine.CaptureLoader`.
    Both return ``list[Packet]`` so downstream engines (E2, E3, E4) work
    identically regardless of whether data came from a file or the wire.

    Args:
        iface:   Network interface name.  ``None`` → auto-select (prefers Wi-Fi).
        timeout: Max seconds to wait even if ``count`` is not reached.
                 ``None`` → wait until ``count`` packets arrive.
    """

    def __init__(
        self,
        iface: str | None = None,
        timeout: int | None = 15,
    ) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError(
                "scapy is not installed. Run: pip install scapy\n"
                "Also ensure Npcap is installed: https://npcap.com"
            )
        self.iface = _pick_interface(iface)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture(self, count: int = 50, bpf_filter: str = "") -> list[Packet]:
        """Capture ``count`` packets from the live interface.

        Args:
            count:      Number of packets to capture (1–5000).
            bpf_filter: Optional BPF filter string, e.g. ``"tcp"`` or
                        ``"port 53"``.  Empty string = capture everything.

        Returns:
            Ordered ``list[Packet]`` — same model used throughout the pipeline.
        """
        count = max(1, min(count, 5000))
        return list(self._iter_capture(count, bpf_filter))

    def iter_capture(self, count: int = 50, bpf_filter: str = "") -> Iterator[Packet]:
        """Streaming version — yields packets one at a time as they arrive."""
        yield from self._iter_capture(count, bpf_filter)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _iter_capture(self, count: int, bpf_filter: str) -> Iterator[Packet]:
        """Use scapy sniff() and convert each frame to a Packet."""
        kwargs: dict = {
            "iface": self.iface,
            "count": count,
            "store": True,        # collect into a list, then iterate
        }
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        if self.timeout is not None:
            kwargs["timeout"] = self.timeout

        try:
            scapy_packets = sniff(**kwargs)
        except Exception as exc:
            raise RuntimeError(
                f"Live capture failed on interface '{self.iface}': {exc}\n"
                "Make sure Npcap is installed and you are running as Administrator."
            ) from exc

        for index, sp in enumerate(scapy_packets):
            # scapy time is a float (epoch seconds with sub-second precision)
            timestamp: float = float(sp.time) if hasattr(sp, "time") else time.time()

            # Get raw bytes — sp.original is the unmodified captured bytes
            try:
                raw = bytes(sp)
            except Exception:
                continue  # skip unserializable packets

            yield Packet(
                index=index,
                timestamp=timestamp,
                length=len(raw),
                raw_bytes=raw,
            )
