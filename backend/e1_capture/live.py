"""Live packet capture for Engine E1.

Two backends — whichever is available is used automatically:

* **Linux (Ubuntu VMs)**: ``AFPacketCapture`` uses a native ``AF_PACKET``
  raw socket (no external dependencies, requires ``sudo`` / ``CAP_NET_RAW``).
* **Windows (dev machine)**: ``LiveCapture`` uses Scapy + Npcap.

``get_live_capturer(iface)`` returns the right backend for the current OS.

Usage::

    capturer = get_live_capturer("ens33")  # Linux
    capturer = get_live_capturer("Wi-Fi")  # Windows
    packets  = capturer.capture(count=50)  # list[Packet]

Requirements (Windows):
    - Npcap installed  (https://npcap.com)
    - Run as Administrator
    - scapy installed  (pip install scapy)

Requirements (Linux):
    - Run as root or with CAP_NET_RAW:  sudo python run_probe.py ...
"""

from __future__ import annotations

import logging
import os
import platform
import re
import select
import socket
import struct
import subprocess
import time
from collections.abc import Iterator

from backend.models import Packet

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────
# Scapy / Windows path
# ─────────────────────────────────────────────────────────────────

try:
    from scapy.all import conf, sniff, IFACES as _SCAPY_IFACES  # type: ignore

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
        iface_list = list(_SCAPY_IFACES.values())
    except Exception:
        return iface or conf.iface

    if iface:
        iface_lower = iface.lower()
        for entry in iface_list:
            name = getattr(entry, "name", "")
            desc = getattr(entry, "description", "")
            if iface_lower in name.lower() or iface_lower in desc.lower():
                return getattr(entry, "network_name", name)
        return iface

    for hint in _WINDOWS_IFACE_HINTS:
        for entry in iface_list:
            name = getattr(entry, "name", "")
            desc = getattr(entry, "description", "")
            if hint.lower() in name.lower() or hint.lower() in desc.lower():
                return getattr(entry, "network_name", name)

    return conf.iface


class LiveCapture:
    """Capture live packets from a network interface using Scapy/Npcap (Windows).

    Args:
        iface:   Network interface name.  ``None`` → auto-select (prefers Wi-Fi).
        timeout: Max seconds to wait even if ``count`` is not reached.
    """

    def __init__(
        self,
        iface: str | None = None,
        timeout: int | None = 15,
    ) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError(
                "scapy is not installed. Run: pip install scapy\n"
                "Also ensure Npcap is installed: https://npcap.com\n"
                "On Linux, use AFPacketCapture instead (no external deps)."
            )
        self.iface = _pick_interface(iface)
        self.timeout = timeout

    def capture(self, count: int = 50, bpf_filter: str = "") -> list[Packet]:
        """Capture ``count`` packets from the live interface."""
        count = max(1, min(count, 5000))
        return list(self._iter_capture(count, bpf_filter))

    def iter_capture(self, count: int = 50, bpf_filter: str = "") -> Iterator[Packet]:
        """Streaming version — yields packets one at a time as they arrive."""
        yield from self._iter_capture(count, bpf_filter)

    def _iter_capture(self, count: int, bpf_filter: str) -> Iterator[Packet]:
        kwargs: dict = {
            "iface": self.iface,
            "count": count,
            "store": True,
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
            timestamp: float = float(sp.time) if hasattr(sp, "time") else time.time()
            try:
                raw = bytes(sp)
            except Exception:
                continue
            yield Packet(
                index=index,
                timestamp=timestamp,
                length=len(raw),
                raw_bytes=raw,
            )


# ─────────────────────────────────────────────────────────────────
# AF_PACKET / Linux path (no external dependencies)
# ─────────────────────────────────────────────────────────────────

#: True only on Linux kernels that expose AF_PACKET
_AFPACKET_AVAILABLE: bool = (
    platform.system() == "Linux" and hasattr(socket, "AF_PACKET")
)

# ETH_P_ALL in network byte order — capture every ethertype
_ETH_P_ALL = socket.htons(0x0003)

# PACKET_ADD_MEMBERSHIP / PACKET_MR_PROMISC constants (linux/if_packet.h)
_SOL_PACKET = 263  # socket.SOL_PACKET not defined on all Python builds
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_MR_PROMISC = 1


def _linux_interfaces() -> list[str]:
    """Return all non-loopback network interface names present on this Linux host."""
    interfaces: list[str] = []
    if hasattr(socket, "if_nameindex"):
        try:
            interfaces = [name for _, name in socket.if_nameindex() if name != "lo"]
        except Exception:
            pass
    if not interfaces and os.path.exists("/sys/class/net"):
        try:
            interfaces = [
                name for name in os.listdir("/sys/class/net")
                if name != "lo" and not name.startswith(".")
            ]
        except Exception:
            pass
    return interfaces


def _pick_linux_interface(
    iface: str | None = None,
    target_host: str | None = None,
) -> str:
    """Return the best available Linux network interface.

    If ``iface`` is given explicitly and exists on the host, it is used.
    If ``iface`` does not exist or is None:
      1. Tries to determine which interface routes to ``target_host`` (via ``ip route get``).
      2. Tries the default gateway interface from ``/proc/net/route``.
      3. Tries the first non-loopback interface whose operstate is 'up'.
      4. Falls back to the first available non-loopback interface, or 'eth0'.
    """
    available = _linux_interfaces()

    # 1. User gave an explicit interface that exists
    if iface and iface in available:
        return iface

    # 2. Try routing to target_host if specified
    if target_host and target_host not in ("127.0.0.1", "localhost", "::1"):
        try:
            out = subprocess.check_output(
                ["ip", "-o", "-4", "route", "get", target_host],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
            m = re.search(r"dev\s+(\S+)", out)
            if m and m.group(1) in available:
                return m.group(1)
        except Exception:
            pass

    # 3. Default route from /proc/net/route
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == "00000000":
                        candidate = parts[0]
                        if candidate in available:
                            return candidate
    except Exception:
        pass

    # 4. First interface with operstate == up
    for candidate in available:
        try:
            operstate_path = f"/sys/class/net/{candidate}/operstate"
            if os.path.exists(operstate_path):
                with open(operstate_path) as f:
                    if f.read().strip().lower() == "up":
                        return candidate
        except Exception:
            pass

    # 5. First available non-loopback interface
    if available:
        return available[0]

    return iface or "eth0"


def _set_promisc(sock: socket.socket, iface: str) -> None:
    """Best-effort: enable promiscuous mode on *iface* via PACKET_ADD_MEMBERSHIP."""
    try:
        ifindex = socket.if_nametoindex(iface)
        # struct packet_mreq { int mr_ifindex; short mr_type; short mr_alen; char mr_address[8]; }
        mreq = struct.pack("IHH8s", ifindex, _PACKET_MR_PROMISC, 0, b"\x00" * 8)
        sock.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP, mreq)
    except (OSError, struct.error):
        pass  # non-fatal — capture still works without promisc


class AFPacketCapture:
    """Linux AF_PACKET raw socket capture — zero external dependencies.

    Captures every Ethernet frame visible on *iface* (promiscuous mode).
    Requires ``sudo`` or ``CAP_NET_RAW`` capability.

    Args:
        iface:   Network interface name, e.g. ``"eth0"`` or ``"ens33"``.
        timeout: Per-burst select() timeout in seconds (default 2.0).
    """

    def __init__(self, iface: str | None = None, timeout: float = 2.0) -> None:
        if not _AFPACKET_AVAILABLE:
            raise RuntimeError(
                "AFPacketCapture requires Linux with AF_PACKET kernel support.\n"
                "On Windows use LiveCapture (Scapy + Npcap) instead."
            )
        self.iface = _pick_linux_interface(iface)
        self.timeout = timeout

    # ── Public API (same shape as LiveCapture) ──────────────────────

    def capture(self, count: int = 100, bpf_filter: str = "") -> list[Packet]:
        """Capture up to *count* packets; returns when count reached or timeout.

        ``bpf_filter`` is accepted for API compatibility but is NOT applied
        (AF_PACKET does not support BPF natively without libpcap). Use a
        tight ``iface`` selection instead, or post-filter decoded packets.
        """
        count = max(1, min(count, 10_000))
        return list(self._iter_capture(count))

    def iter_capture(self, count: int = 100, bpf_filter: str = "") -> Iterator[Packet]:
        """Streaming version — yields packets as they arrive."""
        yield from self._iter_capture(count)

    # ── Internal ────────────────────────────────────────────────────

    def _iter_capture(self, count: int) -> Iterator[Packet]:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, _ETH_P_ALL)
        try:
            sock.bind((self.iface, 0))
            _set_promisc(sock, self.iface)
            index = 0
            while index < count:
                ready, _, _ = select.select([sock], [], [], self.timeout)
                if not ready:
                    # Timeout slice elapsed — keep looping so caller can
                    # check Ctrl-C in the outer while True loop of run_probe.py
                    break
                try:
                    raw, _ = sock.recvfrom(65_535)
                except OSError:
                    break
                ts = time.time()
                yield Packet(
                    index=index,
                    timestamp=ts,
                    length=len(raw),
                    raw_bytes=raw,
                )
                index += 1
        finally:
            sock.close()


# ─────────────────────────────────────────────────────────────────
# Factory — picks the right backend for the current OS
# ─────────────────────────────────────────────────────────────────

def get_live_capturer(
    iface: str | None = None,
    timeout: float | int | None = 2.0,
    target_host: str | None = None,
) -> AFPacketCapture | LiveCapture:
    """Return the best available capture backend for the current OS.

    * Linux  → ``AFPacketCapture`` (AF_PACKET, no extra deps)
    * Windows → ``LiveCapture`` (Scapy + Npcap)

    Raises ``RuntimeError`` if neither backend is available.
    """
    if _AFPACKET_AVAILABLE:
        resolved = _pick_linux_interface(iface=iface, target_host=target_host)
        return AFPacketCapture(iface=resolved, timeout=float(timeout or 2.0))
    if _SCAPY_AVAILABLE:
        return LiveCapture(iface=iface, timeout=int(timeout) if timeout else 15)
    raise RuntimeError(
        "No packet capture backend available.\n"
        "  Linux : run with sudo / CAP_NET_RAW (AF_PACKET is built-in).\n"
        "  Windows: pip install scapy  and install Npcap from https://npcap.com"
    )
