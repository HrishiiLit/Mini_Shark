"""Built-in protocol dissectors for Engine E2.

Starter coverage: Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP,
ICMP/ICMPv6, DNS and HTTP. Anything else is preserved as ``Payload`` with
``undecoded_bytes`` set - a packet is never dropped or raised on.
"""

from __future__ import annotations

import socket
import struct

from backend.models import Layer

from .registry import Dispatch, DissectorRegistry

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

DLT_EN10MB = 1
DLT_RAW = (101, 12, 228, 229)

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

_HTTP_METHODS = (
    "GET ",
    "POST ",
    "PUT ",
    "HEAD ",
    "DELETE ",
    "OPTIONS ",
    "PATCH ",
    "TRACE ",
    "CONNECT ",
)


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _payload(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """Fallback layer for bytes no registered dissector claimed."""
    return Layer("Payload", {}, undecoded_bytes=data), None, None


def _truncated(name: str, data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    return Layer(name, {"truncated": True}, undecoded_bytes=data), None, None


def ethernet(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """Ethernet II link layer."""
    if len(data) < 14:
        return _truncated("Ethernet", data)
    dst, src, ethertype = struct.unpack_from("!6s6sH", data, 0)
    layer = Layer(
        "Ethernet",
        {"dst": _mac(dst), "src": _mac(src), "ethertype": ethertype},
    )
    return layer, data[14:], ("ethertype", (ethertype,))


def raw_link(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """DLT_RAW style captures that start straight at the IP header."""
    if not data:
        return _truncated("Raw", data)
    version = data[0] >> 4
    if version == 4:
        return Layer("Raw", {"ip_version": 4}), data, ("ethertype", (ETHERTYPE_IPV4,))
    if version == 6:
        return Layer("Raw", {"ip_version": 6}), data, ("ethertype", (ETHERTYPE_IPV6,))
    return _truncated("Raw", data)


def vlan(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """802.1Q VLAN tag; may stack, so dispatch again on the inner type."""
    if len(data) < 4:
        return _truncated("VLAN", data)
    tci, ethertype = struct.unpack_from("!HH", data, 0)
    layer = Layer("VLAN", {"priority": tci >> 13, "vlan_id": tci & 0x0FFF})
    return layer, data[4:], ("ethertype", (ethertype,))


def arp(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """ARP - has no five-tuple, so E3 files it as ungrouped."""
    if len(data) < 8:
        return _truncated("ARP", data)
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, 0)
    body = data[8:]
    if op not in (1, 2) or len(body) < 2 * hlen + 2 * plen:
        layer = Layer("ARP", {"hardware_type": htype, "op": op}, undecoded_bytes=body)
        return layer, None, None
    offset = hlen
    sha = body[:offset]
    spa = body[offset : offset + plen]
    offset += plen
    tha = body[offset : offset + hlen]
    tpa = body[offset + hlen : offset + hlen + plen]
    layer = Layer(
        "ARP",
        {
            "hardware_type": htype,
            "protocol_type": ptype,
            "op": op,
            "src_mac": _mac(sha),
            "src_ip": _inet_ntop(spa),
            "dst_mac": _mac(tha),
            "dst_ip": _inet_ntop(tpa),
        },
    )
    return layer, None, None


def ipv4(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """IPv4 header."""
    if len(data) < 20:
        return _truncated("IPv4", data)
    version_ihl, tos, total_length, ident, flags_frag, ttl, proto = struct.unpack_from(
        "!BBHHHBB", data, 0
    )
    version, header_len = version_ihl >> 4, (version_ihl & 0x0F) * 4
    if version != 4 or header_len < 20 or len(data) < header_len:
        return Layer("IPv4", {"version": version}, undecoded_bytes=data), None, None
    checksum = struct.unpack_from("!H", data, 10)[0]
    layer = Layer(
        "IPv4",
        {
            "version": version,
            "hdr_len": header_len,
            "tos": tos,
            "total_length": total_length,
            "id": ident,
            "flags_frag": flags_frag,
            "ttl": ttl,
            "protocol": proto,
            "checksum": checksum,
            "src": _inet_ntop(data[12:16]),
            "dst": _inet_ntop(data[16:20]),
        },
    )
    end = total_length if header_len <= total_length <= len(data) else len(data)
    return layer, data[header_len:end], ("ipproto", (proto,))


def ipv6(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """IPv6 base header (extension headers are left as payload)."""
    if len(data) < 40:
        return _truncated("IPv6", data)
    version = data[0] >> 4
    if version != 6:
        return Layer("IPv6", {"version": version}, undecoded_bytes=data), None, None
    payload_length, next_header, hop_limit = struct.unpack_from("!HBB", data, 4)
    layer = Layer(
        "IPv6",
        {
            "version": version,
            "payload_length": payload_length,
            "next_header": next_header,
            "hop_limit": hop_limit,
            "src": _inet_ntop(data[8:24]),
            "dst": _inet_ntop(data[24:40]),
        },
    )
    end = 40 + payload_length
    payload = data[40:end] if end <= len(data) else data[40:]
    return layer, payload, ("ipproto", (next_header,))


def tcp(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """TCP header."""
    if len(data) < 20:
        return _truncated("TCP", data)
    src_port, dst_port, seq, ack, offset_flags, window = struct.unpack_from(
        "!HHIIHH", data, 0
    )
    header_len = (offset_flags >> 12) * 4
    flags = offset_flags & 0x01FF
    if header_len < 20 or len(data) < header_len:
        layer = Layer(
            "TCP", {"src_port": src_port, "dst_port": dst_port}, undecoded_bytes=data
        )
        return layer, None, None
    layer = Layer(
        "TCP",
        {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "hdr_len": header_len,
            "window": window,
        },
    )
    return layer, data[header_len:], ("port", (dst_port, src_port))


def udp(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """UDP header."""
    if len(data) < 8:
        return _truncated("UDP", data)
    src_port, dst_port, length, checksum = struct.unpack_from("!HHHH", data, 0)
    layer = Layer(
        "UDP",
        {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "checksum": checksum,
        },
    )
    end = length if 8 <= length <= len(data) else len(data)
    return layer, data[8:end], ("port", (dst_port, src_port))


def icmp(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """ICMP / ICMPv6 - type and code only; the rest stays undecoded."""
    if len(data) < 4:
        return _truncated("ICMP", data)
    icmp_type, code, checksum = struct.unpack_from("!BBH", data, 0)
    layer = Layer(
        "ICMP",
        {"type": icmp_type, "code": code, "checksum": checksum},
        undecoded_bytes=data[4:],
    )
    return layer, None, None


def dns(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """DNS header plus the first questions (names may use compression)."""
    if len(data) < 12:
        return _truncated("DNS", data)
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", data, 0
    )
    fields: dict[str, object] = {
        "tx_id": tx_id,
        "flags": flags,
        "response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0x0F,
        "rcode": flags & 0x000F,
        "answers": ancount,
        "authorities": nscount,
        "additionals": arcount,
        "questions": [],
    }
    offset = 12
    try:
        questions, offset = _dns_questions(data, offset, qdcount)
        fields["questions"] = questions
    except ValueError:
        offset = 12  # malformed: keep header fields, everything below stays undecoded
    layer = Layer("DNS", fields, undecoded_bytes=data[offset:])
    return layer, None, None


def http(data: bytes) -> tuple[Layer, bytes | None, Dispatch | None]:
    """HTTP/1.x request or response; the body is kept as undecoded bytes."""
    header_blob, body = _split_http(data)
    lines = header_blob.decode("ascii", errors="replace").split("\n")
    start_line = lines[0].rstrip("\r")
    if not (start_line.startswith(_HTTP_METHODS) or start_line.startswith("HTTP/")):
        return _payload(data)
    layer = Layer(
        "HTTP",
        {
            "start_line": start_line,
            "headers": _http_headers(lines[1:]),
            "body_length": len(body),
        },
        undecoded_bytes=body,
    )
    return layer, None, None


def _inet_ntop(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _split_http(data: bytes) -> tuple[bytes, bytes]:
    """Split header block and body without decoding the body bytes."""
    index, step = data.find(b"\r\n\r\n"), 4
    if index == -1:
        index, step = data.find(b"\n\n"), 2
    if index == -1:
        return data, b""
    return data[:index], data[index + step :]


def _http_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition(":")
        if not separator or not line.strip():
            break
        headers[key.strip().lower()] = value.strip().rstrip("\r")
    return headers


def _dns_questions(
    data: bytes, offset: int, count: int
) -> tuple[list[dict[str, int | str]], int]:
    questions: list[dict[str, int | str]] = []
    for _ in range(count):
        name, offset = _dns_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("truncated DNS question")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    return questions, offset


def _dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly compressed DNS name; returns (name, next offset)."""
    labels: list[str] = []
    end = offset
    jumps = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), (end if jumps else offset + 1)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data) or jumps >= 16:
                raise ValueError("bad DNS name pointer")
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            continue
        if length & 0xC0 or offset + 1 + length > len(data):
            raise ValueError("bad DNS label")
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += 1 + length
        if not jumps:
            end = offset
    raise ValueError("unterminated DNS name")


def build_default_registry() -> DissectorRegistry:
    """Registry with the starter protocol set installed."""
    registry = DissectorRegistry()
    registry.register("link", DLT_EN10MB, "Ethernet", ethernet)
    for dlt in DLT_RAW:
        registry.register("link", dlt, "Raw", raw_link)

    registry.register("ethertype", ETHERTYPE_IPV4, "IPv4", ipv4)
    registry.register("ethertype", ETHERTYPE_IPV6, "IPv6", ipv6)
    registry.register("ethertype", ETHERTYPE_ARP, "ARP", arp)
    registry.register("ethertype", ETHERTYPE_VLAN, "VLAN", vlan)

    registry.register("ipproto", IPPROTO_TCP, "TCP", tcp)
    registry.register("ipproto", IPPROTO_UDP, "UDP", udp)
    registry.register("ipproto", IPPROTO_ICMP, "ICMP", icmp)
    registry.register("ipproto", IPPROTO_ICMPV6, "ICMPv6", icmp)

    registry.register("port", 53, "DNS", dns)
    registry.register("port", 80, "HTTP", http)
    registry.register("port", 8080, "HTTP", http)
    registry.register("port", 8000, "HTTP", http)
    return registry


# ---------------------------------------------------------------------------
# Invariant field extraction — Phase 3
# ---------------------------------------------------------------------------
# Rules (from data_contract.md §3):
#   INCLUDED  : IP src/dst, IP protocol/next-header, IPv4 ID,
#               TCP seq, UDP src+dst ports + length,
#               ICMP type + code + identifier/sequence
#   EXCLUDED  : TTL / Hop Limit (decremented per hop),
#               MAC addresses (rewritten per hop),
#               all IP/transport checksums (recalculated per hop)
#
# The extractor walks the already-decoded layer list produced by _walk() and
# builds a deterministic list of (field_name, encoded_bytes) pairs.  These are
# then concatenated and hashed by the engine.  Using a name-tagged encoding
# prevents accidental collisions between fields of different protocols that
# happen to share the same byte representation.
# ---------------------------------------------------------------------------

def _encode_field(name: str, value: object) -> bytes:
    """Encode a single (name, value) pair as length-prefixed bytes.

    Format: <1-byte name-length><name-bytes><encoded-value>
    Value encoding rules:
      - int  → 8-byte big-endian uint64 (covers all header ints safely)
      - str  → UTF-8 bytes
      - bytes → raw bytes
    The name prefix makes the encoding unambiguous across protocols.
    """
    name_bytes = name.encode()
    if isinstance(value, int):
        val_bytes = value.to_bytes(8, "big")
    elif isinstance(value, str):
        val_bytes = value.encode()
    elif isinstance(value, (bytes, bytearray)):
        val_bytes = bytes(value)
    else:
        val_bytes = str(value).encode()
    return bytes([len(name_bytes)]) + name_bytes + val_bytes


def extract_invariant_fields(layers: list[Layer]) -> tuple[bytes, list[str]]:
    """Return ``(blob, fields_used)`` for fingerprinting.

    ``blob``        — deterministic byte sequence to feed into BLAKE2b.
    ``fields_used`` — human-readable list of field names that were included
                      (for debugging / data-contract documentation).

    Returns ``(b"", [])`` when no IP layer is present (e.g. pure ARP).
    """
    parts: list[bytes] = []
    fields_used: list[str] = []

    def add(name: str, value: object) -> None:
        parts.append(_encode_field(name, value))
        fields_used.append(name)

    layer_map: dict[str, Layer] = {layer.name: layer for layer in layers}

    # ---- IP layer (required; no fingerprint without it) ----
    if "IPv4" in layer_map:
        ip = layer_map["IPv4"]
        f = ip.fields
        # Included: src, dst, protocol, identification
        # Excluded: ttl, checksum, tos, flags_frag (mutable), total_length
        if not f.get("malformed") and not f.get("truncated"):
            add("ip.src", f.get("src", ""))
            add("ip.dst", f.get("dst", ""))
            add("ip.proto", f.get("protocol", 0))
            add("ip.id", f.get("id", 0))
    elif "IPv6" in layer_map:
        ip = layer_map["IPv6"]
        f = ip.fields
        # Included: src, dst, next_header
        # Excluded: hop_limit (equivalent to TTL), flow_label (can change)
        if not f.get("malformed") and not f.get("truncated"):
            add("ip6.src", f.get("src", ""))
            add("ip6.dst", f.get("dst", ""))
            add("ip6.next_header", f.get("next_header", 0))
    else:
        # No IP layer — cannot produce a meaningful cross-probe fingerprint
        return b"", []

    # ---- Transport layer ----
    if "TCP" in layer_map:
        tcp_layer = layer_map["TCP"]
        f = tcp_layer.fields
        # Included: seq (stable end-to-end for a given segment)
        # Excluded: ack (changes in responses), flags (can differ at probes in
        #           edge cases), window, checksum, src/dst ports (NAT-rewritten
        #           on some deployments — kept here per data contract §3 which
        #           does NOT list ports as excluded; they are stable within a
        #           same-admin-domain deployment)
        if not f.get("malformed") and not f.get("truncated"):
            add("tcp.src_port", f.get("src_port", 0))
            add("tcp.dst_port", f.get("dst_port", 0))
            add("tcp.seq", f.get("seq", 0))

    elif "UDP" in layer_map:
        udp_layer = layer_map["UDP"]
        f = udp_layer.fields
        # Included: src port, dst port, length (no sequence number in UDP)
        # Excluded: checksum (recalculated per hop due to TTL in pseudo-header)
        if not f.get("malformed") and not f.get("truncated"):
            add("udp.src_port", f.get("src_port", 0))
            add("udp.dst_port", f.get("dst_port", 0))
            add("udp.length", f.get("length", 0))

    elif "ICMP" in layer_map:
        icmp_layer = layer_map["ICMP"]
        f = icmp_layer.fields
        # Included: type, code
        # Excluded: checksum
        if not f.get("malformed") and not f.get("truncated"):
            add("icmp.type", f.get("type", 0))
            add("icmp.code", f.get("code", 0))

    if not parts:
        # IP layer was malformed/truncated — no usable fields
        return b"", []

    return b"".join(parts), fields_used
