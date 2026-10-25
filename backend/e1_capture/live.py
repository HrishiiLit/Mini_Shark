"""Live Packet Capture and Producer for Engine E1.

Captures raw link-layer or IP packets from network interfaces and feeds them
into a thread-safe BoundedRingBuffer for downstream protocol dissection (E2).

Key capabilities:
- OS-level raw socket handling with cross-platform support:
  * Linux: AF_PACKET raw socket listening on ETH_P_ALL (promiscuous mode).
  * Windows / Cross-platform fallback: Npcap / Raw socket or Replay Capture.
- Nanosecond-precision timestamping (time.time_ns()).
- Monotonic per-probe sequence numbering.
- Dedicated background worker thread with clean, bounded shutdown.
- BoundedRingBuffer integration ensuring capture never blocks on slow workers.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Callable

from backend.e1_capture.engine import CaptureLoader
from backend.e1_capture.ring_buffer import BoundedRingBuffer
from backend.models import CapturedPacket, Packet

logger = logging.getLogger(__name__)

# Ethernet protocol constant: ETH_P_ALL in network byte order
_ETH_P_ALL = 0x0003


class LiveCaptureEngine:
    """Producer engine capturing raw network frames into a BoundedRingBuffer.

    Attributes:
        probe_id: Identifier of the observing probe (1 = Client, 2 = Server).
        interface: Network interface name or IP.
        ring_buffer: Pre-allocated circular buffer absorbing microbursts.
    """

    def __init__(
        self,
        probe_id: int = 1,
        interface: str = "eth0",
        buffer_capacity: int = 10_000,
        snaplen: int = 65535,
    ) -> None:
        if not (1 <= probe_id <= 255):
            raise ValueError(f"probe_id must be between 1 and 255, got {probe_id}")

        self.probe_id: int = probe_id
        self.interface: str = interface
        self.snaplen: int = snaplen
        self.ring_buffer: BoundedRingBuffer[CapturedPacket] = BoundedRingBuffer(
            capacity=buffer_capacity
        )

        self._seq: int = 0
        self._seq_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running: bool = False
        self._socket: socket.socket | None = None

    @property
    def is_running(self) -> bool:
        """Whether the capture loop is currently active."""
        return self._running

    def _next_seq(self) -> int:
        """Generate the next monotonically increasing 32-bit sequence number."""
        with self._seq_lock:
            seq = self._seq
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            return seq

    def _create_raw_socket(self) -> socket.socket:
        """Create and bind a platform-appropriate raw packet socket.

        Raises:
            OSError: If raw socket permissions are denied or interface is invalid.
        """
        if hasattr(socket, "AF_PACKET"):
            # Linux raw packet socket capturing all link-layer protocols
            raw_sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(_ETH_P_ALL),
            )
            raw_sock.bind((self.interface, 0))
            return raw_sock

        # Windows / Non-Linux raw IP socket fallback
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_sock.bind((self.interface, 0))
        # Include IP headers
        try:
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError:
            pass
        return raw_sock

    def start(self) -> None:
        """Start the live capture thread.

        Raises:
            RuntimeError: If the capture engine is already running.
            OSError: If raw socket initialization fails.
        """
        if self._running:
            raise RuntimeError("LiveCaptureEngine is already running")

        try:
            self._socket = self._create_raw_socket()
            self._socket.settimeout(0.5)  # Periodic timeout to check running state
        except OSError as exc:
            logger.warning(
                "Could not open OS raw socket on '%s' (%s). "
                "Ensure administrative / root privileges are granted.",
                self.interface,
                exc,
            )
            raise

        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop,
            name=f"CaptureThread-{self.interface}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "LiveCaptureEngine started on interface %s (Probe ID: %d)",
            self.interface,
            self.probe_id,
        )

    def _capture_loop(self) -> None:
        """Continuous packet interception loop running in the capture thread."""
        assert self._socket is not None

        while self._running:
            try:
                raw_bytes, _ = self._socket.recvfrom(self.snaplen)
                ts_ns = time.time_ns()
            except socket.timeout:
                continue
            except OSError:
                if not self._running:
                    break
                logger.exception("Unexpected error in raw socket recvfrom")
                break

            seq = self._next_seq()
            frame_len = len(raw_bytes)

            packet = CapturedPacket(
                probe_id=self.probe_id,
                seq=seq,
                timestamp_ns=ts_ns,
                captured_len=frame_len,
                original_len=frame_len,
                data=raw_bytes,
                interface=self.interface,
            )

            # Non-blocking push into ring buffer: drops on saturation to protect socket
            self.ring_buffer.push(packet, block=False)

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the capture thread and close resources gracefully."""
        if not self._running:
            return

        self._running = False

        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            self._thread = None

        self.ring_buffer.close()
        logger.info(
            "LiveCaptureEngine stopped on %s (pushed: %d, dropped: %d)",
            self.interface,
            self.ring_buffer.pushed_count,
            self.ring_buffer.dropped_count,
        )


class ReplayCaptureEngine:
    """Simulated probe capture reading packets from a PCAP/PCAPNG file.

    Feeds packets into a BoundedRingBuffer at wire speed or maximum rate,
    allowing reproducible multi-probe latency and loss benchmarks without
    requiring live network cards or root privileges.
    """

    def __init__(
        self,
        pcap_path: str | Path,
        probe_id: int = 1,
        interface: str = "sim0",
        buffer_capacity: int = 10_000,
        rate_pps: float | None = None,
    ) -> None:
        self.pcap_path = Path(pcap_path)
        self.probe_id: int = probe_id
        self.interface: str = interface
        self.rate_pps: float | None = rate_pps
        self.ring_buffer: BoundedRingBuffer[CapturedPacket] = BoundedRingBuffer(
            capacity=buffer_capacity
        )

        self._loader = CaptureLoader()
        self._running: bool = False
        self._thread: threading.Thread | None = None
        self._seq: int = 0

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start replaying packets from the capture file into the ring buffer."""
        if self._running:
            raise RuntimeError("ReplayCaptureEngine is already running")

        self._running = True
        self._thread = threading.Thread(
            target=self._replay_loop,
            name=f"ReplayThread-{self.pcap_path.name}",
            daemon=True,
        )
        self._thread.start()

    def _replay_loop(self) -> None:
        try:
            delay = 1.0 / self.rate_pps if self.rate_pps and self.rate_pps > 0 else 0.0

            for packet in self._loader.iter_packets(str(self.pcap_path)):
                if not self._running:
                    break

                ts_ns = int(packet.timestamp * 1_000_000_000)
                captured = CapturedPacket(
                    probe_id=self.probe_id,
                    seq=self._seq,
                    timestamp_ns=ts_ns,
                    captured_len=packet.length,
                    original_len=packet.length,
                    data=packet.raw_bytes,
                    interface=self.interface,
                )
                self._seq = (self._seq + 1) & 0xFFFFFFFF

                self.ring_buffer.push(captured, block=True, timeout=1.0)

                if delay > 0:
                    time.sleep(delay)
        finally:
            self._running = False
            self.ring_buffer.close()

    def stop(self, timeout: float = 2.0) -> None:
        """Stop replay and close the ring buffer."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            self._thread = None
        self.ring_buffer.close()
