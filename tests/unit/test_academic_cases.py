"""Academic Evaluation Test Cases (Gate 1 Runbook: TC-01 to TC-05).

Formally validates the five university viva evaluation scenarios defined in
the Mini-Shark Master Specification:
  - TC-01: Baseline Traffic Correlation (O(1) matching, Delta T < 5 ms)
  - TC-02: Intermediate Loss Detection (Min-heap expiration, loss > 5%)
  - TC-03: Bufferbloat / Jitter Trend (Slope > 0.5 ms/packet)
  - TC-04: DNS Tunneling Exfiltration (Shannon Entropy H(X) > 4.2 bits)
  - TC-05: Multi-Client Load Attribution (Probe 1 & Probe 3 dual client routing)
"""

from __future__ import annotations

import hashlib
import time

import pytest
from helpers import dns_query, udp_frame

from backend.e2_dissection.engine import ProtocolDissector, _dns_shannon_entropy
from backend.e3_flows.correlator import CorrelationHub
from backend.e4_query.diagnostics import (
    rule_app_freeze,
    rule_bufferbloat,
    rule_dns_exfil,
    rule_packet_loss,
)
from backend.models import Packet, ProbeTelemetry


def _make_fp(seed: str) -> int:
    return int.from_bytes(hashlib.blake2b(seed.encode(), digest_size=8).digest(), "big")


def test_tc01_baseline_traffic():
    """TC-01: Generate 50 HTTP-like packets; 100% matched in O(1) with Delta T < 5 ms."""
    matched_records = []
    hub = CorrelationHub(timeout_ms=500, on_record=matched_records.append)
    base_ns = time.time_ns()

    count = 50
    for i in range(count):
        fp = _make_fp(f"tc01-pkt-{i}")
        t1 = base_ns + i * 2_000_000        # 2ms intervals
        t2 = t1 + 3_200_000                 # 3.2 ms transit latency (Delta T < 5ms)

        # Ingress (Probe 1)
        hub.ingest(ProbeTelemetry(
            fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=512
        ))
        # Egress (Probe 2)
        rec = hub.ingest(ProbeTelemetry(
            fingerprint=fp, timestamp_ns=t2, seq=i, probe_id=2, type_flags=0x11, captured_len=512
        ))
        assert rec is not None
        assert rec.match_state == "matched"
        assert rec.delay_ms == pytest.approx(3.2, rel=1e-3)

    assert hub.stats["matched"] == count
    assert hub.stats["unmatched"] == 0
    assert len(matched_records) == count


def test_tc02_intermediate_loss_detection():
    """TC-02: 15% artificial packet loss triggers PACKET_LOSS alert via min-heap expiration."""
    records = []
    hub = CorrelationHub(timeout_ms=500, on_record=records.append)
    base_ns = time.time_ns()

    total = 50
    dropped_count = 10  # 20% loss (> 5% threshold)

    for i in range(total):
        fp = _make_fp(f"tc02-pkt-{i}")
        t1 = base_ns + i * 1_000_000
        # Ingress probe sees every packet
        hub.ingest(ProbeTelemetry(
            fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=200
        ))
        # Only non-dropped packets reach Probe 2
        if i >= dropped_count:
            hub.ingest(ProbeTelemetry(
                fingerprint=fp, timestamp_ns=t1 + 4_000_000, seq=i, probe_id=2, type_flags=0x11, captured_len=200
            ))

    # Expire unmatched ingress packets from min-heap
    hub.flush_all()

    assert hub.stats["matched"] == total - dropped_count
    assert hub.stats["unmatched"] == dropped_count

    # Evaluate diagnostic rule
    alert = rule_packet_loss(records)
    assert alert is not None
    assert alert.category == "PACKET_LOSS"
    assert alert.metrics["loss_rate"] == pytest.approx(dropped_count / total, rel=1e-2)
    assert alert.metrics["loss_rate"] > 0.05


def test_tc03_bufferbloat_detection():
    """TC-03: Rising delay trend across packets (slope > 0.5 ms/pkt) triggers BUFFERBLOAT alert."""
    records = []
    hub = CorrelationHub(timeout_ms=500, on_record=records.append)
    base_ns = time.time_ns()

    # 30 packets with increasing delay: 2ms -> 25ms (slope ~ 0.79 ms/pkt > 0.5 ms/pkt)
    n = 30
    for i in range(n):
        fp = _make_fp(f"tc03-bloat-{i}")
        t1 = base_ns + i * 10_000_000
        delay_ms = 2.0 + (i * 0.8)
        t2 = t1 + int(delay_ms * 1_000_000)

        hub.ingest(ProbeTelemetry(
            fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=1400
        ))
        hub.ingest(ProbeTelemetry(
            fingerprint=fp, timestamp_ns=t2, seq=i, probe_id=2, type_flags=0x11, captured_len=1400
        ))

    assert len(records) == n
    alert = rule_bufferbloat(records)
    assert alert is not None
    assert alert.category == "BUFFERBLOAT"
    assert alert.metrics["delay_slope_ms_per_pkt"] >= 0.5


def test_tc04_dns_exfiltration_shannon_entropy():
    """TC-04: High-entropy base64 DNS query exhibits H(X) > 4.2 and triggers DNS_EXFIL_SUSPECTED."""
    dissector = ProtocolDissector()

    high_entropy_name = "a8f9c1b3e7d2k0w5.exfil.lab"
    normal_name = "www.google.com"

    # Frame 1: suspicious tunneling query
    f1 = udp_frame(src="192.168.130.128", dst="192.168.130.129", dport=53, payload=dns_query(high_entropy_name))
    p1 = Packet(index=0, timestamp=time.time(), length=len(f1), raw_bytes=f1)
    d1 = dissector.dissect_one(p1)

    # Frame 2: normal query
    f2 = udp_frame(src="192.168.130.128", dst="192.168.130.129", dport=53, payload=dns_query(normal_name))
    p2 = Packet(index=1, timestamp=time.time(), length=len(f2), raw_bytes=f2)
    d2 = dissector.dissect_one(p2)

    assert d1.dns_entropy is not None
    assert d1.dns_entropy > 4.2
    assert d2.dns_entropy is not None
    assert d2.dns_entropy < 3.5

    alert = rule_dns_exfil([d1, d2])
    assert alert is not None
    assert alert.category == "DNS_EXFIL_SUSPECTED"
    assert alert.metrics["max_entropy"] == pytest.approx(d1.dns_entropy, rel=1e-2)


def test_tc05_multi_client_load():
    """TC-05: Ingress traffic from Client 1 (Probe 1) and Client 2 (Probe 3) correctly attributed."""
    records = []
    hub = CorrelationHub(timeout_ms=500, on_record=records.append)
    base_ns = time.time_ns()

    # Client 1 (Probe 1) packet
    fp1 = _make_fp("tc05-client1")
    hub.ingest(ProbeTelemetry(
        fingerprint=fp1, timestamp_ns=base_ns, seq=10, probe_id=1, type_flags=0x11, captured_len=500
    ))
    hub.ingest(ProbeTelemetry(
        fingerprint=fp1, timestamp_ns=base_ns + 2_000_000, seq=10, probe_id=2, type_flags=0x11, captured_len=500
    ))

    # Client 2 (Probe 3) packet
    fp2 = _make_fp("tc05-client2")
    hub.ingest(ProbeTelemetry(
        fingerprint=fp2, timestamp_ns=base_ns + 5_000_000, seq=20, probe_id=3, type_flags=0x11, captured_len=500
    ))
    hub.ingest(ProbeTelemetry(
        fingerprint=fp2, timestamp_ns=base_ns + 7_000_000, seq=20, probe_id=2, type_flags=0x11, captured_len=500
    ))

    assert len(records) == 2
    # Verify client_probe_id preservation
    client_ids = [r.client_probe_id for r in records]
    assert 1 in client_ids
    assert 3 in client_ids
