"""PCAP/PCAPNG loading for Engine E1.

Design notes:

- The file type and byte order are decided by magic bytes, never by the
  file extension.
- Classic PCAP records are read directly so a record whose declared length
  exceeds the bytes actually present raises :class:`CorruptCaptureError`
  instead of silently yielding a short frame. PCAPNG (a block format) is
  parsed with :mod:`dpkt`.
- ``iter_packets`` streams the capture so a 100 MB file never has to fit in
  memory; ``load_capture`` (the contract method) materialises the list.
- An empty-but-valid capture simply yields zero packets.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

import dpkt

from backend.errors import CorruptCaptureError, UnsupportedFormatError
from backend.interfaces import EngineE1
from backend.models import Packet

# magic -> (byte order, ticks per second)
_PCAP_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big endian, nanoseconds
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_GLOBAL_HEADER_LEN = 24
_RECORD_HEADER_LEN = 16
_MAX_RECORD_LEN = 1 << 26  # 64 MiB sanity limit for a single packet

# Errors dpkt can raise while reading a damaged PCAPNG file.
_DPKT_ERRORS = (dpkt.dpkt.Error, ValueError, struct.error, OSError)


class CaptureLoader(EngineE1):
    """Default E1 implementation."""

    def load_capture(self, path: str) -> list[Packet]:
        """Read the whole capture into memory as ``Packet`` records."""
        return list(self.iter_packets(path))

    def iter_packets(self, path: str) -> Iterator[Packet]:
        """Yield packets one at a time (large-file path)."""
        file_path = Path(path)
        try:
            handle = file_path.open("rb")
        except OSError as exc:
            raise CorruptCaptureError(f"{path}: cannot open capture ({exc})") from exc

        with handle:
            yield from _iter_file(handle, path)


def _iter_file(handle: BinaryIO, path: str) -> Iterator[Packet]:
    """Dispatch on the magic bytes and stream the records."""
    magic = handle.read(4)
    handle.seek(0)

    if len(magic) < 4:
        raise CorruptCaptureError(f"{path}: file is empty or shorter than a header")
    if magic in _PCAP_MAGICS:
        endian, ticks = _PCAP_MAGICS[magic]
        yield from _iter_pcap(handle, path, endian, ticks)
        return
    if magic == _PCAPNG_MAGIC:
        yield from _iter_pcapng(handle, path)
        return
    raise UnsupportedFormatError(f"{path}: not a PCAP/PCAPNG file (magic {magic!r})")


def _iter_pcap(
    handle: BinaryIO, path: str, endian: str, ticks_per_second: int
) -> Iterator[Packet]:
    """Stream classic PCAP records, rejecting truncated or absurd lengths."""
    header = handle.read(_GLOBAL_HEADER_LEN)
    if len(header) < _GLOBAL_HEADER_LEN:
        raise CorruptCaptureError(f"{path}: truncated global header")

    index = 0
    while True:
        record = handle.read(_RECORD_HEADER_LEN)
        if not record:
            return
        if len(record) < _RECORD_HEADER_LEN:
            raise CorruptCaptureError(
                f"{path}: truncated record header at packet {index}"
            )
        seconds, fraction, captured_len, original_len = struct.unpack(
            f"{endian}IIII", record
        )
        if captured_len > _MAX_RECORD_LEN:
            raise CorruptCaptureError(
                f"{path}: implausible record length {captured_len} at packet {index}"
            )
        if captured_len > original_len:
            raise CorruptCaptureError(
                f"{path}: captured length {captured_len} exceeds wire length {original_len} at packet {index}"
            )
        buffer = handle.read(captured_len)
        if len(buffer) < captured_len:
            raise CorruptCaptureError(
                f"{path}: truncated record data at packet {index} "
                f"(expected {captured_len} bytes, found {len(buffer)})"
            )
        yield Packet(
            index=index,
            timestamp=seconds + fraction / ticks_per_second,
            length=captured_len,
            raw_bytes=buffer,
        )
        index += 1


def _iter_pcapng(handle: BinaryIO, path: str) -> Iterator[Packet]:
    """Stream PCAPNG blocks through dpkt."""
    try:
        reader = dpkt.pcapng.Reader(handle)
    except _DPKT_ERRORS as exc:
        raise CorruptCaptureError(f"{path}: malformed PCAPNG header ({exc})") from exc

    try:
        for index, (timestamp, buffer) in enumerate(reader):
            raw_bytes = bytes(buffer)
            yield Packet(
                index=index,
                timestamp=float(timestamp),
                length=len(raw_bytes),
                raw_bytes=raw_bytes,
            )
    except _DPKT_ERRORS as exc:
        raise CorruptCaptureError(
            f"{path}: truncated or malformed PCAPNG block ({exc})"
        ) from exc
