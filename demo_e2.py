"""
Mini-Shark E2 — Phase 3 Live Demo
===================================
Runs the dissection engine on hand-crafted packets and prints:
  - Protocol layers decoded
  - 64-bit BLAKE2b fingerprint (with fields used)
  - DNS Shannon entropy (where applicable)
  - 24-byte ProbeTelemetry wire record
"""

import hashlib
import socket
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from backend.e2_dissection.engine import ProtocolDissector
from backend.models import Packet

dissector = ProtocolDissector()

# ── helpers to build raw frames ────────────────────────────────────────────

def _mac(s):
    return bytes.fromhex(s.replace(":", ""))

def eth(payload, ethertype):
    return _mac("aa:bb:cc:dd:ee:ff") + _mac("11:22:33:44:55:66") + struct.pack("!H", ethertype) + payload

def ip4(payload, proto, src="10.0.0.1", dst="10.0.0.2", ttl=64, ip_id=0x1234):
    tlen = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, tlen, ip_id, 0, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload

def tcp_seg(sport=12345, dport=80, seq=1000, payload=b""):
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, 2000, (5<<12)|0x18, 8192, 0, 0)
    return hdr + payload

def udp_seg(sport=54321, dport=53, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8+len(payload), 0) + payload

def dns_qry(name="example.com"):
    hdr = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(l)]) + l.encode() for l in name.split("."))
    return hdr + labels + b"\x00" + struct.pack("!HH", 1, 1)

def http_req():
    return b"GET /api/data HTTP/1.1\r\nHost: server.local\r\nAccept: */*\r\n\r\n"

def make_packet(raw, index, ts=1_700_000_000.0):
    return Packet(index=index, timestamp=ts, length=len(raw), raw_bytes=raw)

# ── build demo packets ──────────────────────────────────────────────────────

packets = [
    ("TCP  (port 443, HTTPS-like)",
     make_packet(eth(ip4(tcp_seg(dport=443, seq=0xDEADBEEF), 6), 0x0800), 0, 1_700_000_000.100)),

    ("TCP  (same flow, 1 hop later — TTL 63, same MACs rewritten)",
     make_packet(
         _mac("cc:dd:ee:ff:00:11") + _mac("00:11:22:33:44:55") +  # different MACs
         struct.pack("!H", 0x0800) +
         ip4(tcp_seg(dport=443, seq=0xDEADBEEF), 6, ttl=63),       # TTL decremented
         1, 1_700_000_000.102)),

    ("UDP/DNS query — example.com",
     make_packet(eth(ip4(udp_seg(dport=53, payload=dns_qry("example.com")), 17), 0x0800), 2, 1_700_000_000.200)),

    ("UDP/DNS query — HIGH ENTROPY (possible tunnel)",
     make_packet(eth(ip4(udp_seg(dport=53, payload=dns_qry("xk2m9pqvzjrfhbtw.exfil.attacker.io")), 17), 0x0800), 3, 1_700_000_000.201)),

    ("TCP/HTTP GET request",
     make_packet(eth(ip4(tcp_seg(dport=80, seq=5000, payload=http_req()), 6), 0x0800), 4, 1_700_000_000.300)),
]

# ── pretty printer ───────────────────────────────────────────────────────────

SEP  = "─" * 70
SEP2 = "═" * 70

print(f"\n{SEP2}")
print("  Mini-Shark E2  ·  Phase 3 Demo  ·  ProtocolDissector")
print(f"{SEP2}\n")

seq_counter = 0
for label, pkt in packets:
    decoded  = dissector.dissect_one(pkt)
    telemetry = dissector.make_telemetry(decoded, pkt, probe_id=1, seq=seq_counter)
    if telemetry:
        seq_counter += 1

    print(f"┌─  Packet #{pkt.index}  {label}")
    print(f"│   Timestamp : {pkt.timestamp:.3f}s   Length : {pkt.length} bytes")

    # layers
    layer_names = " → ".join(l.name for l in decoded.layers)
    print(f"│   Layers    : {layer_names}")

    # fingerprint
    if decoded.fingerprint:
        fp = decoded.fingerprint
        print(f"│   Fingerprint  : 0x{fp.value:016X}  ({fp.algorithm} v{fp.version})")
        print(f"│   Fields used  : {', '.join(fp.fields_used)}")
    else:
        print(f"│   Fingerprint  : ✗ none (no IP layer or fully malformed)")

    # dns entropy
    if decoded.dns_entropy is not None:
        H = decoded.dns_entropy
        flag = "  ⚠  H > 4.2 → possible DNS tunnel (E4 will alert)" if H > 4.2 else ""
        print(f"│   DNS entropy  : H = {H:.4f} bits{flag}")

    # telemetry wire record
    if telemetry:
        raw = telemetry.pack()
        hex_str = " ".join(f"{b:02X}" for b in raw)
        print(f"│   Telemetry    : [{hex_str}]  ({len(raw)} bytes)")
        ver  = (telemetry.type_flags >> 4) & 0x0F
        rtype = telemetry.type_flags & 0x0F
        print(f"│                  seq={telemetry.seq}  probe_id={telemetry.probe_id}"
              f"  fmt_v={ver}  rec_type={rtype}")
    else:
        print(f"│   Telemetry    : ✗ not emitted (no fingerprint)")

    print(f"└{SEP[1:]}\n")

# ── stability check: packets 0 and 1 must share fingerprint ─────────────────
print(f"{SEP}")
print("  Fingerprint stability check (same TCP segment, TTL 64 vs 63, different MACs)")
print(f"{SEP}")
d0 = dissector.dissect_one(packets[0][1])
d1 = dissector.dissect_one(packets[1][1])
fp0 = d0.fingerprint.value if d0.fingerprint else None
fp1 = d1.fingerprint.value if d1.fingerprint else None
match = fp0 == fp1
print(f"  Probe 1 (TTL=64)  fingerprint : 0x{fp0:016X}")
print(f"  Probe 2 (TTL=63)  fingerprint : 0x{fp1:016X}")
print(f"  Match             : {'✓  IDENTICAL — E3 will correlate these' if match else '✗  DIFFERENT (bug!)'}")
print(f"{SEP}\n")
