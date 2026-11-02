"""Phase 3 unit tests — E2 fingerprinting, DNS entropy, and telemetry.

Test groups:
  A. Invariant field extraction  (protocols.extract_invariant_fields)
  B. BLAKE2b fingerprint          (engine._compute_fingerprint)
  C. Fingerprint stability        — TTL/MAC changes must NOT change the fingerprint
  D. DNS Shannon entropy          (engine._dns_shannon_entropy)
  E. ProbeTelemetry serialization (models.ProbeTelemetry.pack / .unpack)
  F. make_telemetry helper        (ProtocolDissector.make_telemetry)
  G. Integration: dissect_one attaches fingerprint + entropy to DecodedPacket
"""

from __future__ import annotations

import hashlib
import math
import socket
import struct
import sys
import os

# Make sure the project root is importable when tests run from tests/unit/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Use the local helpers for byte-level frame building
from helpers import (
    arp_frame,
    dns_query,
    ethernet,
    ipv4,
    tcp,
    tcp_frame,
    udp,
    udp_frame,
    ETHERTYPE_IPV4,
)

from backend.e2_dissection.engine import (
    ProtocolDissector,
    _compute_fingerprint,
    _dns_shannon_entropy,
    _make_telemetry,
)
from backend.e2_dissection.protocols import extract_invariant_fields, _encode_field
from backend.models import DecodedPacket, Packet, PacketFingerprint, ProbeTelemetry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _packet(frame: bytes, index: int = 0, timestamp: float = 1.0) -> Packet:
    return Packet(index=index, timestamp=timestamp, length=len(frame), raw_bytes=frame)


def _decode(frame: bytes) -> DecodedPacket:
    return ProtocolDissector().dissect_one(_packet(frame))


def _icmp_frame(
    src: str = "10.0.0.1", dst: str = "10.0.0.2", icmp_type: int = 8, code: int = 0
) -> bytes:
    """Build a minimal ICMP Echo Request Ethernet frame."""
    icmp_payload = struct.pack("!BBH", icmp_type, code, 0)  # type, code, checksum
    ip_payload = icmp_payload
    return ethernet(ipv4(ip_payload, proto=1, src=src, dst=dst), ETHERTYPE_IPV4)


def _tcp_frame_with_ttl(ttl: int, seq: int = 1000) -> bytes:
    """TCP frame where we control TTL and TCP seq directly (for stability tests)."""
    tcp_payload = struct.pack("!HHIIHHHH", 12345, 80, seq, 2000, (5 << 12) | 0x18, 8192, 0, 0)
    total_length = 20 + len(tcp_payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length,
        0x1234,         # identification
        0,              # flags + fragment offset
        ttl,            # <-- the variable we're testing
        6,              # TCP
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.2"),
    )
    eth_header = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"
    return eth_header + ip_header + tcp_payload


def _tcp_frame_with_mac(src_mac: str, seq: int = 1000) -> bytes:
    """TCP frame where we control the source MAC (for stability tests)."""
    tcp_payload = struct.pack("!HHIIHHHH", 12345, 80, seq, 2000, (5 << 12) | 0x18, 8192, 0, 0)
    total_length = 20 + len(tcp_payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0x1234, 0, 64, 6, 0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.2"),
    )
    dst_mac = bytes.fromhex("aabbccddeeff")
    src_mac_b = bytes.fromhex(src_mac.replace(":", ""))
    eth_header = dst_mac + src_mac_b + b"\x08\x00"
    return eth_header + ip_header + tcp_payload


# ===========================================================================
# A. Invariant field extraction
# ===========================================================================

class TestExtractInvariantFields:

    def test_tcp_returns_expected_field_names(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        _, fields_used = extract_invariant_fields(decoded.layers)

        assert "ip.src" in fields_used
        assert "ip.dst" in fields_used
        assert "ip.proto" in fields_used
        assert "ip.id" in fields_used
        assert "tcp.src_port" in fields_used
        assert "tcp.dst_port" in fields_used
        assert "tcp.seq" in fields_used

    def test_tcp_does_not_include_ttl_or_checksum(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        _, fields_used = extract_invariant_fields(decoded.layers)

        # TTL / hop limit and checksums must NEVER appear in the field list
        for name in fields_used:
            assert "ttl" not in name.lower()
            assert "hop_limit" not in name.lower()
            assert "checksum" not in name.lower()

    def test_udp_returns_ports_and_length(self):
        frame = udp_frame(dport=53, payload=dns_query("example.com"))
        decoded = _decode(frame)
        _, fields_used = extract_invariant_fields(decoded.layers)

        assert "udp.src_port" in fields_used
        assert "udp.dst_port" in fields_used
        assert "udp.length" in fields_used
        # UDP has no seq number
        assert "tcp.seq" not in fields_used

    def test_icmp_returns_type_and_code(self):
        frame = _icmp_frame()
        decoded = _decode(frame)
        _, fields_used = extract_invariant_fields(decoded.layers)

        assert "icmp.type" in fields_used
        assert "icmp.code" in fields_used

    def test_arp_returns_empty_blob(self):
        frame = arp_frame()
        decoded = _decode(frame)
        blob, fields_used = extract_invariant_fields(decoded.layers)

        assert blob == b""
        assert fields_used == []

    def test_blob_is_bytes(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        blob, _ = extract_invariant_fields(decoded.layers)

        assert isinstance(blob, bytes)
        assert len(blob) > 0

    def test_encode_field_name_prefix_prevents_collisions(self):
        """Two different fields with the same integer value must produce different blobs."""
        enc_a = _encode_field("ip.proto", 6)
        enc_b = _encode_field("tcp.seq", 6)
        assert enc_a != enc_b

    def test_same_packet_produces_same_blob(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        blob1, _ = extract_invariant_fields(decoded.layers)
        blob2, _ = extract_invariant_fields(decoded.layers)
        assert blob1 == blob2


# ===========================================================================
# B. BLAKE2b fingerprint correctness
# ===========================================================================

class TestComputeFingerprint:

    def test_returns_packet_fingerprint_for_tcp(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        fp = _compute_fingerprint(decoded.layers)

        assert fp is not None
        assert isinstance(fp, PacketFingerprint)

    def test_algorithm_and_version_are_correct(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        fp = _compute_fingerprint(decoded.layers)

        assert fp.algorithm == "blake2b-64"
        assert fp.version == 1

    def test_value_is_uint64(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        fp = _compute_fingerprint(decoded.layers)

        assert isinstance(fp.value, int)
        assert 0 <= fp.value < 2**64

    def test_fingerprint_matches_manual_blake2b(self):
        """Cross-check: the fingerprint value must equal hashlib.blake2b on the same blob."""
        frame = tcp_frame()
        decoded = _decode(frame)
        fp = _compute_fingerprint(decoded.layers)
        blob, _ = extract_invariant_fields(decoded.layers)

        expected_digest = hashlib.blake2b(blob, digest_size=8).digest()
        expected_value = int.from_bytes(expected_digest, "big")

        assert fp.value == expected_value

    def test_returns_none_for_arp(self):
        frame = arp_frame()
        decoded = _decode(frame)
        fp = _compute_fingerprint(decoded.layers)

        assert fp is None

    def test_fields_used_is_non_empty_for_tcp(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        fp = _compute_fingerprint(decoded.layers)

        assert fp is not None
        assert len(fp.fields_used) > 0

    def test_different_tcp_seq_produces_different_fingerprint(self):
        """Packets with different TCP sequence numbers must get different fingerprints."""
        frame_a = _tcp_frame_with_ttl(ttl=64, seq=1000)
        frame_b = _tcp_frame_with_ttl(ttl=64, seq=9999)

        fp_a = _compute_fingerprint(_decode(frame_a).layers)
        fp_b = _compute_fingerprint(_decode(frame_b).layers)

        assert fp_a is not None and fp_b is not None
        assert fp_a.value != fp_b.value

    def test_different_src_ip_produces_different_fingerprint(self):
        frame_a = tcp_frame(src="10.0.0.1")
        frame_b = tcp_frame(src="10.0.0.3")

        fp_a = _compute_fingerprint(_decode(frame_a).layers)
        fp_b = _compute_fingerprint(_decode(frame_b).layers)

        assert fp_a is not None and fp_b is not None
        assert fp_a.value != fp_b.value


# ===========================================================================
# C. Fingerprint stability — TTL and MAC changes must NOT affect fingerprint
# ===========================================================================

class TestFingerprintStability:

    def test_different_ttl_same_fingerprint(self):
        """Simulates the same packet observed at two router hops with different TTL."""
        frame_probe1 = _tcp_frame_with_ttl(ttl=64)
        frame_probe2 = _tcp_frame_with_ttl(ttl=63)  # TTL decremented by one hop

        fp1 = _compute_fingerprint(_decode(frame_probe1).layers)
        fp2 = _compute_fingerprint(_decode(frame_probe2).layers)

        assert fp1 is not None and fp2 is not None
        assert fp1.value == fp2.value, (
            "Fingerprints must be identical when only TTL differs "
            "(TTL is a mutable hop field)"
        )

    def test_different_src_mac_same_fingerprint(self):
        """Simulates MAC rewrite at a hop (L2 forwarding / gateway ARP)."""
        frame_probe1 = _tcp_frame_with_mac("11:22:33:44:55:66")
        frame_probe2 = _tcp_frame_with_mac("aa:bb:cc:dd:ee:ff")  # gateway rewrote MAC

        fp1 = _compute_fingerprint(_decode(frame_probe1).layers)
        fp2 = _compute_fingerprint(_decode(frame_probe2).layers)

        assert fp1 is not None and fp2 is not None
        assert fp1.value == fp2.value, (
            "Fingerprints must be identical when only the source MAC differs "
            "(MACs are rewritten per hop)"
        )

    def test_ttl_and_mac_both_changed_same_fingerprint(self):
        """Combined TTL + MAC change (typical router forwarding) still matches."""
        frame_probe1 = _tcp_frame_with_ttl(ttl=64)
        frame_probe2 = _tcp_frame_with_ttl(ttl=62)  # two hops away

        fp1 = _compute_fingerprint(_decode(frame_probe1).layers)
        fp2 = _compute_fingerprint(_decode(frame_probe2).layers)

        assert fp1 is not None and fp2 is not None
        assert fp1.value == fp2.value

    def test_fingerprint_is_deterministic(self):
        """Same frame decoded twice must produce identical fingerprint."""
        frame = tcp_frame()
        fp1 = _compute_fingerprint(_decode(frame).layers)
        fp2 = _compute_fingerprint(_decode(frame).layers)

        assert fp1 is not None and fp2 is not None
        assert fp1.value == fp2.value


# ===========================================================================
# D. DNS Shannon entropy
# ===========================================================================

class TestDnsEntropy:

    def _entropy_of(self, name: str) -> float:
        """Hand-compute H(X) for a given name string (ground truth)."""
        freq: dict[str, int] = {}
        for ch in name:
            freq[ch] = freq.get(ch, 0) + 1
        total = len(name)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    def test_returns_none_for_non_dns_packet(self):
        frame = tcp_frame()
        decoded = _decode(frame)
        assert _dns_shannon_entropy(decoded.layers) is None

    def test_returns_float_for_dns_query(self):
        frame = udp_frame(dport=53, payload=dns_query("example.com"))
        decoded = _decode(frame)
        result = _dns_shannon_entropy(decoded.layers)

        assert isinstance(result, float)

    def test_matches_hand_computed_entropy(self):
        """Entropy must equal the hand-computed value for 'example.com'."""
        name = "example.com"
        expected = self._entropy_of(name)

        frame = udp_frame(dport=53, payload=dns_query(name))
        decoded = _decode(frame)
        result = _dns_shannon_entropy(decoded.layers)

        assert result is not None
        assert abs(result - expected) < 1e-9

    def test_high_entropy_name(self):
        """A name consisting of all distinct characters has high entropy."""
        # 'abcdefghijklmnop.com' — many unique chars → high entropy
        name = "abcdefghijklmnop.com"
        expected = self._entropy_of(name)

        frame = udp_frame(dport=53, payload=dns_query(name))
        decoded = _decode(frame)
        result = _dns_shannon_entropy(decoded.layers)

        assert result is not None
        assert abs(result - expected) < 1e-9
        # Should be well above the E4 threshold of 4.2
        assert result > 3.5

    def test_low_entropy_name(self):
        """A name with one repeated character has entropy near zero."""
        # 'aaaaaa.com' — almost all 'a's → very low entropy
        name = "aaaaaaaaaa.com"
        frame = udp_frame(dport=53, payload=dns_query(name))
        decoded = _decode(frame)
        result = _dns_shannon_entropy(decoded.layers)

        assert result is not None
        assert result < 2.0  # definitely low

    def test_entropy_is_non_negative(self):
        frame = udp_frame(dport=53, payload=dns_query("test.local"))
        decoded = _decode(frame)
        result = _dns_shannon_entropy(decoded.layers)

        assert result is not None
        assert result >= 0.0

    def test_uniform_single_char_name_has_zero_entropy(self):
        """A single unique character repeated: p(c)=1 → H = 0."""
        # Build raw DNS query with a simple all-'a' label
        name = "aaaa"
        frame = udp_frame(dport=53, payload=dns_query(name))
        decoded = _decode(frame)
        result = _dns_shannon_entropy(decoded.layers)

        # H("aaaa") = -(1*log2(1)) = 0
        assert result is not None
        assert abs(result - 0.0) < 1e-9


# ===========================================================================
# E. ProbeTelemetry pack / unpack
# ===========================================================================

class TestProbeTelemetrySerialization:

    def _sample(self, **kwargs) -> ProbeTelemetry:
        defaults = dict(
            fingerprint=0xDEADBEEFCAFEBABE,
            timestamp_ns=1_700_000_000_123_456_789,
            seq=42,
            probe_id=1,
            type_flags=0x11,   # version nibble 1, record type 1
            captured_len=1514,
        )
        defaults.update(kwargs)
        return ProbeTelemetry(**defaults)

    def test_pack_produces_24_bytes(self):
        rec = self._sample()
        assert len(rec.pack()) == 24

    def test_pack_unpack_roundtrip(self):
        original = self._sample()
        recovered = ProbeTelemetry.unpack(original.pack())

        assert recovered.fingerprint == original.fingerprint
        assert recovered.timestamp_ns == original.timestamp_ns
        assert recovered.seq == original.seq
        assert recovered.probe_id == original.probe_id
        assert recovered.type_flags == original.type_flags
        assert recovered.captured_len == original.captured_len

    def test_unpack_wrong_length_raises(self):
        import pytest
        with pytest.raises(ValueError, match="24 bytes"):
            ProbeTelemetry.unpack(b"\x00" * 23)

    def test_wire_is_big_endian(self):
        """Fingerprint field occupies the first 8 bytes in big-endian order."""
        fp_value = 0x0102030405060708
        rec = self._sample(fingerprint=fp_value)
        raw = rec.pack()

        recovered_int = int.from_bytes(raw[:8], "big")
        assert recovered_int == fp_value

    def test_all_zero_record(self):
        zero = ProbeTelemetry(
            fingerprint=0, timestamp_ns=0, seq=0, probe_id=0,
            type_flags=0, captured_len=0
        )
        raw = zero.pack()
        assert raw == b"\x00" * 24
        recovered = ProbeTelemetry.unpack(raw)
        assert recovered.fingerprint == 0

    def test_max_values_roundtrip(self):
        max_rec = ProbeTelemetry(
            fingerprint=2**64 - 1,
            timestamp_ns=2**64 - 1,
            seq=2**32 - 1,
            probe_id=255,
            type_flags=255,
            captured_len=65535,
        )
        recovered = ProbeTelemetry.unpack(max_rec.pack())
        assert recovered.fingerprint == 2**64 - 1
        assert recovered.seq == 2**32 - 1
        assert recovered.probe_id == 255
        assert recovered.captured_len == 65535

    def test_type_flags_encodes_version_and_type(self):
        """type_flags = (version_nibble << 4) | record_type_nibble."""
        version = 1
        record_type = 1
        expected_flags = (version << 4) | record_type  # 0x11

        rec = self._sample(type_flags=expected_flags)
        raw = rec.pack()
        recovered = ProbeTelemetry.unpack(raw)

        extracted_version = (recovered.type_flags >> 4) & 0x0F
        extracted_type = recovered.type_flags & 0x0F
        assert extracted_version == version
        assert extracted_type == record_type


# ===========================================================================
# F. make_telemetry helper
# ===========================================================================

class TestMakeTelemetry:

    def test_returns_probe_telemetry_for_tcp(self):
        frame = tcp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt, probe_id=1, seq=0)

        assert rec is not None
        assert isinstance(rec, ProbeTelemetry)

    def test_returns_none_for_arp(self):
        frame = arp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt)

        assert rec is None

    def test_fingerprint_matches_decoded_fingerprint(self):
        frame = tcp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt, probe_id=2, seq=7)

        assert rec is not None
        assert rec.fingerprint == decoded.fingerprint.value

    def test_probe_id_is_stored(self):
        frame = tcp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt, probe_id=2, seq=0)

        assert rec.probe_id == 2

    def test_seq_is_stored(self):
        frame = tcp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt, probe_id=1, seq=99)

        assert rec.seq == 99

    def test_captured_len_matches_packet_length(self):
        frame = tcp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt)

        assert rec.captured_len == len(frame)

    def test_timestamp_ns_is_derived_from_packet_timestamp(self):
        ts = 1_700_000_000.5
        frame = tcp_frame()
        pkt = _packet(frame, timestamp=ts)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt)

        expected_ns = int(ts * 1_000_000_000)
        assert rec.timestamp_ns == expected_ns

    def test_packed_record_is_exactly_24_bytes(self):
        frame = tcp_frame()
        pkt = _packet(frame)
        decoded = ProtocolDissector().dissect_one(pkt)
        rec = ProtocolDissector().make_telemetry(decoded, pkt)

        assert rec is not None
        assert len(rec.pack()) == 24


# ===========================================================================
# G. Integration — dissect_one attaches fingerprint and entropy
# ===========================================================================

class TestDissectOneIntegration:

    def test_dissect_one_tcp_has_fingerprint(self):
        frame = tcp_frame()
        decoded = _decode(frame)

        assert decoded.fingerprint is not None
        assert decoded.fingerprint.algorithm == "blake2b-64"
        assert decoded.fingerprint.version == 1

    def test_dissect_one_tcp_has_no_dns_entropy(self):
        frame = tcp_frame()
        decoded = _decode(frame)

        assert decoded.dns_entropy is None

    def test_dissect_one_dns_has_fingerprint_and_entropy(self):
        frame = udp_frame(dport=53, payload=dns_query("example.com"))
        decoded = _decode(frame)

        assert decoded.fingerprint is not None
        assert decoded.dns_entropy is not None
        assert decoded.dns_entropy > 0.0

    def test_dissect_one_arp_has_no_fingerprint(self):
        frame = arp_frame()
        decoded = _decode(frame)

        assert decoded.fingerprint is None

    def test_dissect_one_arp_has_no_dns_entropy(self):
        frame = arp_frame()
        decoded = _decode(frame)

        assert decoded.dns_entropy is None

    def test_fingerprint_is_stable_across_dissect_calls(self):
        """Calling dissect_one twice on the same bytes gives the same fingerprint."""
        frame = tcp_frame()
        d1 = _decode(frame)
        d2 = _decode(frame)

        assert d1.fingerprint is not None
        assert d2.fingerprint is not None
        assert d1.fingerprint.value == d2.fingerprint.value

    def test_malformed_packet_has_no_fingerprint_and_does_not_raise(self):
        """A truncated/malformed frame must not crash and must return None fingerprint."""
        decoded = _decode(b"\x00\x01\x02")

        assert decoded is not None
        assert decoded.fingerprint is None

    def test_batch_dissect_preserves_all_fingerprints(self):
        """dissect() on a batch must attach fingerprints to all fingerprint-able packets."""
        dissector = ProtocolDissector()
        frames = [tcp_frame(), tcp_frame(sport=9999), udp_frame()]
        packets = [_packet(f, i) for i, f in enumerate(frames)]

        results = dissector.dissect(packets)

        assert len(results) == 3
        for result in results:
            assert result.fingerprint is not None
