"""
Mini-Shark E3 — Phase 4 Live Demonstration
==========================================
Demonstrates the central Correlation Hub (Engine E3) and TCP ingestion:
  1. Starts the asyncio TelemetryServer on TCP port 9000.
  2. Connects two synthetic probes using TelemetryClient.
  3. Demonstrates real scenarios:
     - Normal packet transit with one-way delay calculation (ΔT = T2 - T1).
     - Link packet loss: Probe 1 sees packet, Probe 2 does not -> timeout -> UNMATCHED.
     - Late arrival: Probe 2 arrives after the demo's 300ms timeout -> LATE.
     - Clock skew: Negative delay flagged with CLOCK_SKEW_SUSPECT.
     - Duplicate suppression: Repeated telemetry delivery is ignored.
  4. Displays live correlation statistics (p50, p95, in-flight, loss rate).
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from contextlib import suppress

sys.path.insert(0, os.path.dirname(__file__))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    with suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")

from backend.e3_flows import CorrelationEngine, TelemetryClient, TelemetryServer
from backend.models import (
    CorrelationFlags,
    CorrelationRecord,
    MatchState,
    ProbeTelemetry,
)

SEP = "─" * 72
SEP2 = "═" * 72


def _make_telemetry(
    fingerprint: int,
    timestamp_ns: int,
    seq: int,
    probe_id: int,
    length: int = 64,
) -> ProbeTelemetry:
    return ProbeTelemetry(
        fingerprint=fingerprint,
        timestamp_ns=timestamp_ns,
        seq=seq,
        probe_id=probe_id,
        type_flags=0x11,  # v1, type 1 (packet)
        captured_len=length,
    )


def event_printer(rec: CorrelationRecord) -> None:
    """Pretty-print correlation records as they are emitted."""
    fp_hex = f"0x{rec.fingerprint:016X}"

    if rec.match_state == MatchState.MATCHED.value:
        skew_str = (
            " ⚠ [CLOCK_SKEW_SUSPECT]"
            if (rec.flags & CorrelationFlags.CLOCK_SKEW_SUSPECT)
            else ""
        )
        print(
            f"  [MATCHED]    {fp_hex} | ΔT = {rec.delay_ms:+7.2f} ms | "
            f"P1_seq={rec.probe1_seq} P2_seq={rec.probe2_seq}{skew_str}"
        )
    elif rec.match_state == MatchState.UNMATCHED.value:
        print(
            f"  [UNMATCHED]  {fp_hex} | Missing or delayed beyond window | "
            f"P1_seq={rec.probe1_seq}"
        )
    elif rec.match_state == MatchState.LATE.value:
        print(
            f"  [LATE]       {fp_hex} | ΔT = {rec.delay_ms:+7.2f} ms | "
            f"P1_seq={rec.probe1_seq} P2_seq={rec.probe2_seq}"
        )
    elif rec.match_state == MatchState.PROBE2_ONLY.value:
        print(f"  [PROBE2_ONLY]{fp_hex} | Missed Probe 1 | P2_seq={rec.probe2_seq}")


async def run_demo() -> None:
    print(f"\n{SEP2}")
    print("  Mini-Shark E3 · Phase 4 Demo · Central Correlation Hub (Port 9000)")
    print(f"{SEP2}\n")

    port = 9000
    engine = CorrelationEngine(timeout_ms=300)  # 300 ms timeout for fast demo
    server = TelemetryServer(
        engine=engine, host="127.0.0.1", port=port, expire_interval_ms=25
    )

    engine.subscribe(event_printer)

    try:
        await server.start()
        print(f"✓ TelemetryServer listening on 127.0.0.1:{port} (TCP)")
    except OSError:
        print(f"Note: Port {port} busy, using fallback ephemeral port...")
        server.port = 0
        await server.start()

    actual_port = server.port

    # Connect two synthetic probe clients
    client1 = TelemetryClient(host="127.0.0.1", port=actual_port, probe_id=1)
    client2 = TelemetryClient(host="127.0.0.1", port=actual_port, probe_id=2)

    await client1.connect()
    await client2.connect()
    print("✓ Probe 1 (Client-side) connected and sent 16B preamble")
    print("✓ Probe 2 (Server-side) connected and sent 16B preamble\n")
    print(f"{SEP}")
    print("  Streaming synthetic telemetry across Probes 1 & 2:")
    print(f"{SEP}")

    # 1. Normal traffic (packets 1 to 4 with transit delays)
    delays_ms = [4.2, 5.8, 3.9, 12.4]
    base_fp = 0xAA00BB00CC000000
    first_probe2_record = None

    for i, delay in enumerate(delays_ms, start=1):
        fp = base_fp + i
        t1 = time.time_ns()
        t2 = t1 + int(delay * 1_000_000)

        await client1.send_record(
            _make_telemetry(fp, t1, seq=i, probe_id=1, length=1200)
        )
        await asyncio.sleep(0.01)  # brief network transit
        probe2_record = _make_telemetry(fp, t2, seq=i, probe_id=2, length=1200)
        if first_probe2_record is None:
            first_probe2_record = probe2_record
        await client2.send_record(probe2_record)
        await asyncio.sleep(0.02)

    # 2. Simulated packet drop (Probe 1 sees it, Probe 2 never does)
    drop_fp = base_fp + 99
    drop_t1 = time.time_ns()
    print("\n* Injecting dropped packet (Probe 1 captures seq=5, dropped on link)...")
    await client1.send_record(
        _make_telemetry(drop_fp, drop_t1, seq=5, probe_id=1, length=500)
    )
    # Wait for the 300 ms timeout to expire
    await asyncio.sleep(0.40)

    # 3. Simulated late-arriving packet (T2 arrives after timeout)
    late_fp = base_fp + 100
    late_t1 = time.time_ns()
    print("\n* Injecting severely delayed packet (arrives after 300ms timeout)...")
    await client1.send_record(_make_telemetry(late_fp, late_t1, seq=6, probe_id=1))
    await asyncio.sleep(0.35)  # Let it expire to UNMATCHED
    late_t2 = late_t1 + 380_000_000  # Arrives 380 ms later
    await client2.send_record(_make_telemetry(late_fp, late_t2, seq=6, probe_id=2))
    await asyncio.sleep(0.05)

    # 4. Clock skew anomaly (T2 < T1)
    skew_fp = base_fp + 101
    now = time.time_ns()
    print("\n* Injecting clock skew packet (Probe 2 clock lagging Probe 1)...")
    await client1.send_record(_make_telemetry(skew_fp, now, seq=7, probe_id=1))
    await client2.send_record(
        _make_telemetry(skew_fp, now - 15_000_000, seq=7, probe_id=2)
    )  # -15 ms
    await asyncio.sleep(0.05)

    # 5. Duplicate packet suppression
    print("\n* Re-delivering identical Probe 2 telemetry...")
    await client2.send_record(first_probe2_record)
    await asyncio.sleep(0.05)

    # Print summary statistics
    stats = engine.get_stats()
    corr = stats["correlation"]
    lat = stats["latency"]

    print(f"\n{SEP}")
    print("  Engine E3 Correlation Summary:")
    print(f"{SEP}")
    print(f"  Matched Packets       : {corr['matched_total']}")
    print(f"  Timeout Events        : {corr['unmatched_total']}")
    print(f"  Uncorrected Unmatched : {corr['uncorrected_unmatched_total']}")
    print(f"  Late Recoveries       : {corr['late_total']}")
    print(f"  Duplicates Suppressed : {corr['duplicates_ignored']}")
    print(f"  Clock Skew Flags      : {corr['clock_suspect_flags']}")
    if lat["count"]:
        print(f"  Transit Delay (p50)   : {lat['p50_ms']} ms")
        print(f"  Transit Delay (p95)   : {lat['p95_ms']} ms")
        print(f"  Transit Delay (min/max: {lat['min_ms']} / {lat['max_ms']} ms")
    print(f"{SEP2}\n")

    await client1.close()
    await client2.close()
    await server.stop()


if __name__ == "__main__":
    asyncio.run(run_demo())
