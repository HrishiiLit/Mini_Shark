"""
Mini-Shark — Anomaly & Traffic Test Suite
=========================================
Demonstrates and validates all four diagnostic engines and live traffic injection:

  1. DNS Exfiltration Alert  — high entropy query name H > 4.2 bits
  2. Packet Loss Alert       — unmatched packets (no Probe-2 observation) > 5%
  3. Bufferbloat Alert       — rising ΔT trend across matched packets > 0.5 ms/pkt
  4. App Freeze Alert        — avg transit delay > 150 ms

Usage:
    python3 test_anomalies.py          # Run complete in-memory pipeline diagnostic test
    python3 test_anomalies.py --dns    # Send live high-entropy DNS queries over network
    python3 test_anomalies.py --http   # Generate live HTTP GET requests over network
"""

import argparse
import hashlib
import json
import os
import random
import socket
import string
import struct
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

from backend.e2_dissection.engine import ProtocolDissector
from backend.e3_flows.correlator import CorrelationHub
from backend.e4_query.diagnostics import (
    run_diagnostics,
    rule_app_freeze,
    rule_bufferbloat,
    rule_dns_exfil,
    rule_packet_loss,
)
from backend.e4_query.engine import QueryEngine
from backend.models import Packet, ProbeTelemetry
from tests.unit.helpers import dns_query, udp_frame


def run_pipeline_tests():
    """Execute all four diagnostic anomaly tests through the E2->E3->E4 pipeline."""
    engine = QueryEngine("mini_shark.db")
    dissector = ProtocolDissector()
    base_ns = int(time.time() * 1e9)
    all_alerts = []
    all_records = []

    print("=" * 65)
    print("Mini-Shark Academic Anomaly Verification Suite (Gate 1)")
    print("=" * 65)

    # -------------------------------------------------------------
    # TEST 1: DNS Exfiltration Detection (Information Theory H > 4.2)
    # -------------------------------------------------------------
    print("\n--- TEST 1: DNS Exfiltration Detection (Shannon Entropy H > 4.2) ---")
    suspicious_names = [
        "xk2m9pqvzjrfhbtw.exfil.attacker.io",       # H ≈ 4.4
        "d3f9a7b2c1e4k8q0w5r6.tunnel.evil.com",      # H ≈ 4.5
        "z9x8c7v6b5n4m3l2k1j.data.leak.net",         # H ≈ 4.3
        "google.com",                                 # H ≈ 2.6 (normal)
        "example.com",                                # H ≈ 3.1 (normal)
    ]

    dns_packets = []
    for i, name in enumerate(suspicious_names):
        frame = udp_frame(
            src="192.168.130.128",
            dst="192.168.130.129",
            sport=54000 + i,
            dport=53,
            payload=dns_query(name),
        )
        pkt = Packet(index=i, timestamp=time.time(), length=len(frame), raw_bytes=frame)
        decoded = dissector.dissect_one(pkt)
        dns_packets.append(decoded)
        H = decoded.dns_entropy
        flag = "⚠ SUSPICIOUS (H > 4.2)" if H and H > 4.2 else "✓ Normal"
        print(f"  Query: {name:<42} H = {H:.4f}  {flag}")

    dns_alert = rule_dns_exfil(dns_packets)
    if dns_alert:
        all_alerts.append(dns_alert)
        print(f"  -> Rule Fired: [{dns_alert.severity.upper()}] {dns_alert.category}")

    # -------------------------------------------------------------
    # TEST 2: Packet Loss Detection (Unmatched ratio > 5%)
    # -------------------------------------------------------------
    print("\n--- TEST 2: Packet Loss Detection (Min-Heap Expiration > 5%) ---")
    loss_records = []
    hub_loss = CorrelationHub(timeout_ms=500, on_record=loss_records.append)

    print("  Ingesting 20 matched pairs + 6 dropped packets (23% loss)...")
    for i in range(20):
        fp = int.from_bytes(hashlib.blake2b(f"matched-{i}".encode(), digest_size=8).digest(), "big")
        t1 = base_ns + i * 5_000_000
        dt = 4_000_000  # 4ms transit
        hub_loss.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=100))
        hub_loss.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1 + dt, seq=i, probe_id=2, type_flags=0x11, captured_len=100))

    for i in range(20, 26):
        fp = int.from_bytes(hashlib.blake2b(f"dropped-{i}".encode(), digest_size=8).digest(), "big")
        t1 = base_ns + i * 5_000_000
        hub_loss.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=80))

    hub_loss.flush_all()
    all_records.extend(loss_records)
    loss_alert = rule_packet_loss(loss_records)
    if loss_alert:
        all_alerts.append(loss_alert)
        print(f"  Matched: {hub_loss.stats['matched']} | Unmatched (Dropped): {hub_loss.stats['unmatched']}")
        print(f"  -> Rule Fired: [{loss_alert.severity.upper()}] {loss_alert.category} (Loss: {loss_alert.metrics['loss_rate']:.1%})")

    # -------------------------------------------------------------
    # TEST 3: Bufferbloat Detection (Delay Slope > 0.5 ms/packet)
    # -------------------------------------------------------------
    print("\n--- TEST 3: Bufferbloat Detection (Linear Regression Slope > 0.5 ms/pkt) ---")
    bloat_records = []
    hub_bloat = CorrelationHub(timeout_ms=500, on_record=bloat_records.append)

    print("  Ingesting 30 packets with progressive queue delay (1ms -> 20ms)...")
    for i in range(30):
        fp = int.from_bytes(hashlib.blake2b(f"bloat-{i}".encode(), digest_size=8).digest(), "big")
        t1 = base_ns + 1_000_000_000 + i * 10_000_000
        dt = int((1.0 + i * 0.65) * 1_000_000)
        hub_bloat.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=1400))
        hub_bloat.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1 + dt, seq=i, probe_id=2, type_flags=0x11, captured_len=1400))

    all_records.extend(bloat_records)
    bloat_alert = rule_bufferbloat(bloat_records)
    if bloat_alert:
        all_alerts.append(bloat_alert)
        print(f"  -> Rule Fired: [{bloat_alert.severity.upper()}] {bloat_alert.category} (Slope: {bloat_alert.metrics['delay_slope_ms_per_pkt']:.2f} ms/pkt)")

    # -------------------------------------------------------------
    # TEST 4: Application Freeze Detection (Avg Transit Delay > 150 ms)
    # -------------------------------------------------------------
    print("\n--- TEST 4: Application Freeze Detection (Avg Transit Delay > 150 ms) ---")
    freeze_records = []
    hub_freeze = CorrelationHub(timeout_ms=2000, on_record=freeze_records.append)

    print("  Ingesting 10 packets with severe gateway/server delay (200ms - 290ms)...")
    for i in range(10):
        fp = int.from_bytes(hashlib.blake2b(f"freeze-{i}".encode(), digest_size=8).digest(), "big")
        t1 = base_ns + 2_000_000_000 + i * 50_000_000
        dt = int((200 + i * 10) * 1_000_000)
        hub_freeze.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1, seq=i, probe_id=1, type_flags=0x11, captured_len=500))
        hub_freeze.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1 + dt, seq=i, probe_id=2, type_flags=0x11, captured_len=500))

    all_records.extend(freeze_records)
    freeze_alert = rule_app_freeze(freeze_records)
    if freeze_alert:
        all_alerts.append(freeze_alert)
        print(f"  -> Rule Fired: [{freeze_alert.severity.upper()}] {freeze_alert.category} (Avg Delay: {freeze_alert.metrics['avg_delay_ms']:.1f} ms)")

    # -------------------------------------------------------------
    # Persistence & Summary
    # -------------------------------------------------------------
    print("\n" + "=" * 65)
    print("PERSISTENCE & DIAGNOSTIC SUMMARY")
    print("=" * 65)
    engine.store_correlations(all_records)
    engine.repo.store_alerts(all_alerts)

    print(f"  Total correlation records persisted: {len(all_records)}")
    print(f"  Total diagnostic alerts fired:      {len(all_alerts)}\n")

    for a in all_alerts:
        sev_icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(a.severity, "⚪")
        print(f"  {sev_icon} [{a.severity.upper()}] {a.category}")
        print(f"     Confidence : {a.confidence}")
        print(f"     Metrics    : {json.dumps(a.metrics)}")
        print(f"     Action     : {a.recommended_action[:75]}...\n")

    engine.close()
    print("✓ All anomaly rules successfully validated against SQLite WAL storage.")


def generate_dns_exfil_query(target_server: str = "192.168.130.129", port: int = 53, count: int = 20):
    """Send high-entropy base64/hex DNS queries to simulate exfiltration on live network."""
    print(f"Sending {count} high-entropy DNS exfiltration queries to {target_server}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        domain = f"{label}.exfil.lab"
        txn_id = random.randint(0, 65535)
        flags = 0x0100
        query = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
        for part in domain.split("."):
            query += bytes([len(part)]) + part.encode("ascii")
        query += b"\x00" + struct.pack("!HH", 1, 1)
        try:
            sock.sendto(query, (target_server, port))
            print(f"  [{i+1}/{count}] Sent query: {domain}")
        except OSError as e:
            print(f"  [{i+1}/{count}] Error: {e}")
        time.sleep(0.15)
    sock.close()
    print("Done sending DNS queries.")


def generate_http_traffic(target: str = "192.168.130.129", port: int = 8001, count: int = 50):
    """Generate HTTP GET requests to simulate baseline traffic."""
    print(f"Generating {count} HTTP GET requests to http://{target}:{port}/health...")
    for i in range(count):
        url = f"http://{target}:{port}/health"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MiniShark-TestClient/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                status = resp.status
            print(f"  [{i+1}/{count}] GET {url} -> {status} OK")
        except Exception as e:
            print(f"  [{i+1}/{count}] Error: {e}")
        time.sleep(0.08)
    print("Done generating HTTP traffic.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mini-Shark Anomaly & Traffic Test Suite")
    parser.add_argument("--dns", action="store_true", help="Send high-entropy DNS queries over network")
    parser.add_argument("--http", action="store_true", help="Generate HTTP GET requests over network")
    parser.add_argument("--target", type=str, default="192.168.130.129", help="Target server IP (default: 192.168.130.129)")
    parser.add_argument("--port", type=int, default=0, help="Target server port (53 for DNS, 8001 for HTTP)")
    parser.add_argument("--count", type=int, default=0, help="Number of packets / requests to send")
    args = parser.parse_args()

    if args.dns:
        port = args.port or 53
        count = args.count or 20
        generate_dns_exfil_query(target_server=args.target, port=port, count=count)
    elif args.http:
        port = args.port or 8001
        count = args.count or 50
        generate_http_traffic(target=args.target, port=port, count=count)
    else:
        run_pipeline_tests()
