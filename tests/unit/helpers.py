"""Byte-level builders shared by the unit tests.

Everything is constructed by hand so the tests do not depend on fixture
captures in git (``*.pcap`` is gitignored) and so every expected value is
obvious from the source.
"""

from __future__ import annotations

import socket
import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_UNKNOWN = 0x88B5


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def ethernet(payload: bytes, ethertype: int) -> bytes:
    return (
        _mac("aa:bb:cc:dd:ee:ff")
        + _mac("11:22:33:44:55:66")
        + struct.pack("!H", ethertype)
        + payload
    )


def ipv4(
    payload: bytes, proto: int, src: str = "10.0.0.1", dst: str = "10.0.0.2"
) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + payload


def tcp(payload: bytes = b"", sport: int = 12345, dport: int = 80) -> bytes:
    offset_flags = (5 << 12) | 0x18  # header length 20 bytes, PSH|ACK
    header = struct.pack(
        "!HHIIHHHH", sport, dport, 1000, 2000, offset_flags, 8192, 0, 0
    )
    return header + payload


def udp(payload: bytes = b"", sport: int = 12345, dport: int = 53) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp_request() -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        ETHERTYPE_IPV4,
        6,
        4,
        1,
        _mac("11:22:33:44:55:66"),
        socket.inet_aton("10.0.0.1"),
        b"\x00\x00\x00\x00\x00\x00",
        socket.inet_aton("10.0.0.99"),
    )


def dns_query(name: str = "example.com") -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    return header + question


def http_request(path: str = "/index.html") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
    ).encode("ascii")


def tcp_frame(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 12345,
    dport: int = 80,
    payload: bytes = b"",
) -> bytes:
    return ethernet(
        ipv4(tcp(payload, sport=sport, dport=dport), 6, src, dst), ETHERTYPE_IPV4
    )


def udp_frame(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 12345,
    dport: int = 53,
    payload: bytes = b"",
) -> bytes:
    return ethernet(
        ipv4(udp(payload, sport=sport, dport=dport), 17, src, dst), ETHERTYPE_IPV4
    )


def arp_frame() -> bytes:
    return ethernet(arp_request(), ETHERTYPE_ARP)


def unknown_frame() -> bytes:
    return ethernet(b"\xde\xad\xbe\xef", ETHERTYPE_UNKNOWN)


def build_pcap(frames: list[bytes], timestamps: list[float] | None = None) -> bytes:
    """Little-endian microsecond PCAP containing ``frames``."""
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        stamp = timestamps[index] if timestamps else float(index + 1)
        seconds, micros = int(stamp), round((stamp - int(stamp)) * 1_000_000)
        out += struct.pack("<IIII", seconds, micros, len(frame), len(frame))
        out += frame
    return bytes(out)
