"""
Mini-Shark — Anomaly Demo
=========================
Injects test packets through the full E1→E2→E3→E4 pipeline to trigger:

  1. DNS Exfiltration Alert  — high entropy query name H > 4.2
  2. Packet Loss Alert       — unmatched packets (no Probe-2 observation)
  3. Bufferbloat Alert       — rising ΔT trend across matched packets
  4. App Freeze Alert        — avg delay > 150ms

Run while the server is on port 3000 — results appear in the dashboard.

    python test_anomalies.py
"""

import sys, os, time, hashlib, json
sys.path.insert(0, os.path.dirname(__file__))

from backend.e2_dissection.engine import ProtocolDissector
from backend.e3_flows.correlator import CorrelationHub
from backend.e4_query.engine import QueryEngine
from backend.models import Packet, ProbeTelemetry
from tests.unit.helpers import (
    tcp_frame, udp_frame, dns_query, http_request,
    tcp_frame as make_tcp, arp_frame
)

engine    = QueryEngine('mini_shark.db')
dissector = ProtocolDissector()
records   = []

def on_record(rec):
    records.append(rec)

hub = CorrelationHub(timeout_ms=500, on_record=on_record)

SEP  = "─" * 60
SEP2 = "═" * 60
base_ns = int(time.time() * 1e9)

print(f"\n{SEP2}")
print("  Mini-Shark — Anomaly Test Suite")
print(SEP2)

# ──────────────────────────────────────────────────────────────────
# TEST 1: DNS Exfiltration (high entropy query names)
# ──────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("TEST 1: DNS Exfiltration Detection")
print(SEP)

suspicious_names = [
    "xk2m9pqvzjrfhbtw.exfil.attacker.io",          # H ≈ 4.4
    "d3f9a7b2c1e4k8q0w5r6.tunnel.evil.com",         # H ≈ 4.5
    "z9x8c7v6b5n4m3l2k1j.data.leak.net",            # H ≈ 4.3
    "google.com",                                    # H ≈ 3.0 (normal)
    "example.com",                                   # H ≈ 3.1 (normal)
]

dns_packets = []
for i, name in enumerate(suspicious_names):
    frame = udp_frame(src='192.168.1.10', dst='8.8.8.8',
                      sport=54000+i, dport=53,
                      payload=dns_query(name))
    pkt = Packet(index=i, timestamp=time.time(), length=len(frame), raw_bytes=frame)
    decoded = dissector.dissect_one(pkt)
    dns_packets.append(decoded)

    H = decoded.dns_entropy
    flag = "⚠  SUSPICIOUS" if H and H > 4.2 else "✓  Normal"
    print(f"  Query: {name[:45]:<45}  H = {H:.4f}  {flag}" if H else
          f"  Query: {name:<45}  H = N/A")

# ──────────────────────────────────────────────────────────────────
# TEST 2: Packet Loss (unmatched packets — no Probe 2 observation)
# ──────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("TEST 2: Packet Loss Detection")
print(SEP)

print("  Sending 20 matched packets + 6 lost packets...")
for i in range(20):
    blob = f"matched-{i}".encode()
    fp   = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')
    t1   = base_ns + i * 5_000_000   # 5ms apart
    dt   = 4_000_000                  # 4ms delay (normal)

    hub.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1,
                               seq=i, probe_id=1, type_flags=0x11, captured_len=100))
    hub.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1+dt,
                               seq=i, probe_id=2, type_flags=0x11, captured_len=100))

# 6 packets sent from Probe 1 but never arrive at Probe 2 = LOST
for i in range(20, 26):
    blob = f"lost-{i}".encode()
    fp   = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')
    t1   = base_ns + i * 5_000_000
    hub.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1,
                               seq=i, probe_id=1, type_flags=0x11, captured_len=80))

hub.flush_all()   # expire unmatched packets
loss_rate = hub.stats['unmatched'] / (hub.stats['matched'] + hub.stats['unmatched']) * 100
print(f"  Matched  : {hub.stats['matched']}")
print(f"  Unmatched: {hub.stats['unmatched']}  → Loss rate: {loss_rate:.1f}%")
print(f"  Expected alert: PACKET_LOSS (threshold > 5%)")

# ──────────────────────────────────────────────────────────────────
# TEST 3: Bufferbloat (rising ΔT trend)
# ──────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("TEST 3: Bufferbloat Detection (rising delay trend)")
print(SEP)

hub2 = CorrelationHub(timeout_ms=500, on_record=on_record)
print("  Sending 30 packets with rising ΔT (1ms → 20ms):")
for i in range(30):
    blob = f"bloat-{i}".encode()
    fp   = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')
    t1   = base_ns + 1_000_000_000 + i * 10_000_000
    dt   = int((1 + i * 0.65) * 1_000_000)   # 1ms rising to ~20ms = bufferbloat

    hub2.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1,
                                seq=i, probe_id=1, type_flags=0x11, captured_len=1400))
    hub2.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1+dt,
                                seq=i, probe_id=2, type_flags=0x11, captured_len=1400))
    if i % 10 == 9:
        print(f"    pkt {i:2d}: ΔT = {dt/1e6:.2f} ms")

# ──────────────────────────────────────────────────────────────────
# TEST 4: App Freeze (avg ΔT > 150ms)
# ──────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("TEST 4: Application Freeze Detection (avg delay > 150ms)")
print(SEP)

hub3 = CorrelationHub(timeout_ms=1000, on_record=on_record)
print("  Sending 10 packets with 200ms+ delay (server not responding fast):")
for i in range(10):
    blob = f"freeze-{i}".encode()
    fp   = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')
    t1   = base_ns + 2_000_000_000 + i * 50_000_000
    dt   = 200_000_000 + i * 10_000_000   # 200ms → 290ms

    hub3.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1,
                                seq=i, probe_id=1, type_flags=0x11, captured_len=500))
    hub3.ingest(ProbeTelemetry(fingerprint=fp, timestamp_ns=t1+dt,
                                seq=i, probe_id=2, type_flags=0x11, captured_len=500))
    print(f"    pkt {i}: ΔT = {dt/1e6:.0f} ms")

# ──────────────────────────────────────────────────────────────────
# Run diagnostics and store everything
# ──────────────────────────────────────────────────────────────────
print(f"\n{SEP2}")
print("  Running Diagnostic Rules on all records...")
print(SEP2)

engine.store_correlations(records)

from backend.e4_query.diagnostics import run_diagnostics
alerts = run_diagnostics(records, decoded_packets=dns_packets)
engine.repo.store_alerts(alerts)

print(f"\n  Total correlation records : {len(records)}")
print(f"  Alerts fired              : {len(alerts)}\n")

for a in alerts:
    sev_color = {'critical':'🔴','warning':'🟡','info':'🔵'}.get(a.severity,'⚪')
    print(f"  {sev_color} [{a.severity.upper()}] {a.category}")
    print(f"     Confidence : {a.confidence}")
    print(f"     Metrics    : {json.dumps(a.metrics, indent=0)}")
    print(f"     Action     : {a.recommended_action[:80]}...")
    print()

print(SEP2)
print("  Done — open http://127.0.0.1:5173 → Stats tab to see alerts in dashboard")
print(SEP2)
engine.close()
