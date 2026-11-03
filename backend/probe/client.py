"""Telemetry client — connects to the E3 TCP ingestion server on port 9000.

Sends:
  1. 16-byte MSHK preamble (once at connect time)
  2. 24-byte ProbeTelemetry records (one per captured packet, continuously)

Automatically reconnects with exponential backoff if the server drops.
"""

from __future__ import annotations

import socket
import struct
import time
import logging

logger = logging.getLogger(__name__)

_PREAMBLE_MAGIC   = b"MSHK"
_PREAMBLE_VERSION = 1
_RECORD_SIZE      = 24


def build_preamble(probe_id: int) -> bytes:
    """16-byte connection preamble (data_contract.md §4.2)."""
    return struct.pack(
        "!4sBBHI4s",
        _PREAMBLE_MAGIC,
        _PREAMBLE_VERSION,
        _RECORD_SIZE,
        probe_id & 0xFFFF,
        int(time.time()),
        b"\x00" * 4,
    )


class TelemetryClient:
    """Persistent TCP connection to the E3 server.

    Usage::

        client = TelemetryClient(host="192.168.1.20", port=9000, probe_id=1)
        client.connect()          # blocks until connected
        client.send(wire_bytes)   # send one 24-byte record
        client.close()
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        probe_id: int = 1,
        max_retries: int = 10,
    ) -> None:
        self.host       = host
        self.port       = port
        self.probe_id   = probe_id
        self.max_retries = max_retries
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        """Connect to E3 server and send preamble. Retries with backoff."""
        delay = 1.0
        for attempt in range(1, self.max_retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.host, self.port))
                sock.settimeout(None)
                sock.sendall(build_preamble(self.probe_id))
                self._sock = sock
                logger.info(
                    "Probe %d connected to E3 at %s:%d",
                    self.probe_id, self.host, self.port,
                )
                print(
                    f"  [Probe {self.probe_id}] Connected to E3 server "
                    f"at {self.host}:{self.port}"
                )
                return
            except (ConnectionRefusedError, OSError) as exc:
                logger.warning(
                    "Probe %d connection attempt %d/%d failed: %s",
                    self.probe_id, attempt, self.max_retries, exc,
                )
                print(
                    f"  [Probe {self.probe_id}] Attempt {attempt}/{self.max_retries} "
                    f"failed: {exc}. Retrying in {delay:.0f}s..."
                )
                time.sleep(delay)
                delay = min(delay * 2, 30)  # exponential backoff, cap at 30s

        raise ConnectionError(
            f"Probe {self.probe_id}: could not connect to E3 at "
            f"{self.host}:{self.port} after {self.max_retries} attempts.\n"
            f"Is the server running? Start it with: python run_e3_server.py"
        )

    def send(self, wire: bytes) -> bool:
        """Send one 24-byte record. Returns False if connection was lost.

        Caller should reconnect and retry on False.
        """
        if self._sock is None:
            return False
        try:
            self._sock.sendall(wire)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            self._sock = None
            return False

    def send_heartbeat(self, seq: int = 0) -> bool:
        """Send a type-3 heartbeat record to keep the probe marked 'online'.

        Wire format: standard 24-byte ProbeTelemetry with
          fingerprint=0, captured_len=0, type_flags=0x13
          (version nibble=1, record-type nibble=3).

        Returns False if the connection was lost (caller should reconnect).
        """
        import struct as _struct
        # type_flags: version=1 (nibble 4-7=0x10) | type=3 (nibble 0-3=0x03) = 0x13
        _HB_TYPE_FLAGS = (1 << 4) | 3
        now_ns = int(time.time() * 1_000_000_000)
        wire = _struct.pack(
            "!QQIBBH",
            0,                                    # fingerprint = 0
            now_ns & 0xFFFFFFFFFFFFFFFF,          # timestamp_ns
            seq & 0xFFFFFFFF,                     # seq
            self.probe_id & 0xFF,                 # probe_id
            _HB_TYPE_FLAGS,                       # type_flags = 0x13
            0,                                    # captured_len = 0
        )
        return self.send(wire)

    def reconnect(self) -> None:
        """Close and reconnect."""
        self.close()
        self.connect()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
