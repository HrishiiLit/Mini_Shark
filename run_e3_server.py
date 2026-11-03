"""
E3 Correlation Hub — standalone TCP ingestion server.

Run this FIRST on Machine 2 (the central hub / router VM) before starting
any probes.

    python run_e3_server.py

Listens on TCP port 9000.  Both probes connect, send the 16-byte MSHK
preamble, then stream 24-byte ProbeTelemetry records continuously.
Matched packets are stored in mini_shark.db and diagnostic alerts are fired.

Architecture note
-----------------
This script now uses the production-grade ``TelemetryServer`` (ingestion.py)
backed by ``CorrelationEngine`` (correlation.py) rather than the older
``CorrelationHub`` (correlator.py).  Key improvements:
  - Proper per-key FIFO matching (not just fingerprint — disambiguates collisions)
  - Bounded in-memory table (heap_cap=200 000, eviction via _maybe_evict)
  - Duplicate detection via recent-seen LRU cache
  - Late-recovery: Probe-2 arrivals that beat the expiry timer are matched
  - Correct clock-skew flag: set only after both T1 and T2 are available
"""

import asyncio
import json
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from backend.e3_flows.correlation import CorrelationEngine
from backend.e3_flows.ingestion import TelemetryServer
from backend.e4_query.engine import QueryEngine
from backend.e4_query.diagnostics import run_diagnostics
from backend.models import CorrelationRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
)
logger = logging.getLogger("minishark.e3.server")

# ── Persistence & diagnostics ─────────────────────────────────────────────────
engine          = QueryEngine("mini_shark.db")
records_buffer: list[CorrelationRecord] = []
FLUSH_EVERY     = 10

SEP  = "─" * 62
SEP2 = "═" * 62


def on_record(rec: CorrelationRecord) -> None:
    """Called by CorrelationEngine for every emitted CorrelationRecord."""
    records_buffer.append(rec)

    icon = {
        "matched":     "✓ MATCHED   ",
        "unmatched":   "✗ LOST      ",
        "late":        "⏱ LATE      ",
        "probe2_only": "? P2-ONLY   ",
    }.get(rec.match_state, "?           ")

    delay_str = ""
    if rec.delay_ns is not None:
        ms = rec.delay_ns / 1_000_000
        delay_str = f"  ΔT = {ms:7.3f} ms"
        if rec.flags & 1:
            delay_str += "  ⚠ CLOCK SKEW"

    print(f"  {icon}  fp=0x{rec.fingerprint:016X}{delay_str}")

    # Persist + diagnose every FLUSH_EVERY records
    if len(records_buffer) % FLUSH_EVERY == 0:
        try:
            engine.store_correlations(records_buffer[-FLUSH_EVERY:])
            alerts = run_diagnostics(records_buffer)
            if alerts:
                engine.repo.store_alerts(alerts)
                print()
                for a in alerts:
                    sev = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(
                        a.severity, "⚪"
                    )
                    print(f"  {sev} ALERT [{a.severity.upper()}] {a.category}")
                    print(f"     confidence : {a.confidence}")
                    for k, v in list(a.metrics.items())[:3]:
                        print(f"     {k} : {v}")
                    print(f"     action : {a.recommended_action[:70]}...")
                print()
        except Exception as exc:
            print(f"  [storage] {exc}")


# ── Build correlation engine and telemetry server ─────────────────────────────
corr_engine = CorrelationEngine(
    timeout_ms=500,
    probe1_id=1,
    probe2_id=2,
)
corr_engine.subscribe(on_record)

server = TelemetryServer(
    engine=corr_engine,
    host="0.0.0.0",
    port=9000,
    expire_interval_ms=200,   # check for expired 500ms deadlines every 200ms
    idle_timeout_s=30.0,
    max_connections=8,
    clock_tolerance_s=60.0,
)


async def main() -> None:
    print(f"\n{SEP2}")
    print("  Mini-Shark  ·  E3 Multi-Point Correlation Hub")
    print(SEP2)
    print("  Port       : 9000 (TCP)")
    print("  Timeout    : 500 ms per packet")
    print("  Probe 1    : client / source side  (ID=1)")
    print("  Probe 2    : server / gateway side (ID=2)")
    print("  Database   : mini_shark.db")
    print("  Engine     : TelemetryServer + CorrelationEngine (production path)")
    print(f"{SEP}")
    print("  Waiting for probes to connect...\n")

    await server.start()
    logger.info("E3 server started on 0.0.0.0:9000")

    try:
        # Run until Ctrl-C
        while True:
            await asyncio.sleep(1)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{SEP}")
        print("  Shutting down — flushing remaining entries...")

        # Force-expire everything still in the correlator
        remaining = corr_engine.expire_deadlines()

        if records_buffer:
            try:
                engine.store_correlations(records_buffer)
            except Exception as exc:
                print(f"  [storage] flush error: {exc}")

        s = corr_engine.get_stats()["correlation"]
        total    = s["matched_total"] + s["unmatched_total"]
        loss_pct = s["unmatched_total"] / max(1, total) * 100

        print(f"\n  Session summary:")
        print(f"    Matched          : {s['matched_total']}")
        print(f"    Unmatched (lost) : {s['unmatched_total']}")
        print(f"    Late recoveries  : {s['late_recoveries']}")
        print(f"    Loss rate        : {loss_pct:.1f}%")
        print(f"    Clock suspects   : {s['clock_suspect_flags']}")
        print(f"{SEP2}")

        engine.close()
