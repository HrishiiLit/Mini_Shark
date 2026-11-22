"""Populate mini_shark.db with demo correlation records and diagnostic alerts.

Simulates what E3 would produce during a live two-probe session:
  - 40 matched packets with realistic ΔT values
  -  5 unmatched (lost) packets
  -  2 late arrivals
  -  1 suspicious DNS query (high entropy)
Then runs the diagnostic rule engine and stores the resulting alerts.
"""

import sys, os, time, socket, struct
sys.path.insert(0, os.path.dirname(__file__))

from backend.e3_flows.correlator import CorrelationHub
from backend.e4_query.engine import QueryEngine
from backend.e4_query.diagnostics import run_diagnostics
from backend.models import ProbeTelemetry, DecodedPacket, Layer, PacketFingerprint, Packet
from backend.e2_dissection.engine import ProtocolDissector
from tests.unit.helpers import (
    tcp_frame, udp_frame, dns_query, build_pcap
)

engine = QueryEngine('mini_shark.db')
records = []

def on_record(rec):
    records.append(rec)

hub = CorrelationHub(timeout_ms=500, on_record=on_record, probe1_id=1, probe2_id=2)

base_ns = int(time.time() * 1e9)

print("Simulating 40 matched packets (probe1 -> probe2)...")
for i in range(40):
    # Build a realistic fingerprint from a real TCP frame
    import hashlib
    blob = f"pkt-{i}-192.168.1.10-10.0.0.1-6-{i*1000}".encode()
    fp = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')

    t1_ns = base_ns + i * 10_000_000          # 10ms apart
    delay_ns = 3_000_000 + i * 50_000          # 3ms + slight bufferbloat trend

    # Probe 1 record
    p1 = ProbeTelemetry(
        fingerprint=fp, timestamp_ns=t1_ns,
        seq=i, probe_id=1, type_flags=0x11, captured_len=100
    )
    hub.ingest(p1)

    # Probe 2 record (arrives with ΔT delay)
    p2 = ProbeTelemetry(
        fingerprint=fp, timestamp_ns=t1_ns + delay_ns,
        seq=i, probe_id=2, type_flags=0x11, captured_len=100
    )
    hub.ingest(p2)

print(f"  Matched so far: {hub.stats['matched']}")

print("Simulating 5 unmatched (lost) packets...")
for i in range(40, 45):
    blob = f"lost-{i}".encode()
    fp = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')
    t1_ns = base_ns + i * 10_000_000
    p1 = ProbeTelemetry(
        fingerprint=fp, timestamp_ns=t1_ns,
        seq=i, probe_id=1, type_flags=0x11, captured_len=80
    )
    hub.ingest(p1)

# Force expire unmatched
hub.flush_all()
print(f"  Unmatched: {hub.stats['unmatched']}")

print("Simulating 2 late arrivals...")
for i in range(45, 47):
    blob = f"late-{i}".encode()
    fp = int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), 'big')
    t1_ns = base_ns + i * 10_000_000

    # Probe 1 arrives, then we flush (marks as unmatched), then Probe 2 arrives late
    p1 = ProbeTelemetry(fingerprint=fp, timestamp_ns=t1_ns, seq=i, probe_id=1, type_flags=0x11, captured_len=60)
    hub.ingest(p1)
    hub.flush_all()   # expire it

    p2 = ProbeTelemetry(fingerprint=fp, timestamp_ns=t1_ns + 600_000_000, seq=i, probe_id=2, type_flags=0x11, captured_len=60)
    hub.ingest(p2)

print(f"  Late: {hub.stats['late']}")

# Store all correlation records
print(f"\nStoring {len(records)} correlation records...")
engine.store_correlations(records)

# Build a DNS packet with high entropy for DNS exfil test
print("Adding high-entropy DNS packet for DNS exfil rule...")
dns_frame = udp_frame(src='192.168.1.10', dst='8.8.8.8', sport=54399, dport=53,
                       payload=dns_query('xk2m9pqvzjrfhbtw.exfil.attacker.io'))
pkt = Packet(index=0, timestamp=time.time(), length=len(dns_frame), raw_bytes=dns_frame)
decoded = ProtocolDissector().dissect([pkt])

# Run all diagnostic rules
print("Running diagnostic rules...")
alerts = run_diagnostics(records, decoded_packets=decoded)
engine.repo.store_alerts(alerts)
print(f"  Alerts generated: {len(alerts)}")
for a in alerts:
    print(f"    [{a.severity.upper()}] {a.category}  confidence={a.confidence}")
    print(f"      {list(a.metrics.items())[:3]}")

engine.close()
print("\nDone. Database populated.")
