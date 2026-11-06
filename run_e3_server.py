"""Standalone E3 telemetry ingestion server.

Listens on TCP port 9000, receives packet fingerprints from probes,
matches them, and stores correlation records into mini_shark.db.
"""

from __future__ import annotations

import asyncio
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
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger("minishark.e3.server")

# Database storage and batching
engine = QueryEngine("mini_shark.db")
records_buffer: list[CorrelationRecord] = []
FLUSH_EVERY = 10


def on_record(rec: CorrelationRecord) -> None:
    """Callback for each correlated packet record."""
    records_buffer.append(rec)

    icon = {
        "matched": "[MATCHED]",
        "unmatched": "[LOST]   ",
        "late": "[LATE]   ",
        "probe2_only": "[P2-ONLY]",
    }.get(rec.match_state, "[?]      ")

    delay_str = ""
    if rec.delay_ns is not None:
        ms = rec.delay_ns / 1_000_000
        delay_str = f"  delay={ms:.3f}ms"
        if rec.flags & 1:
            delay_str += " (skew flag)"

    print(f"  {icon} fp=0x{rec.fingerprint:016X}{delay_str}")

    # Persist and run diagnostics in batches
    if len(records_buffer) % FLUSH_EVERY == 0:
        try:
            engine.store_correlations(records_buffer[-FLUSH_EVERY:])
            alerts = run_diagnostics(records_buffer)
            if alerts:
                engine.repo.store_alerts(alerts)
                for a in alerts:
                    print(f"  [ALERT] {a.category} ({a.severity}): {a.recommended_action[:60]}...")
        except Exception as exc:
            logger.warning("Storage error: %s", exc)


# Initialize correlation engine and telemetry server
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
    expire_interval_ms=200,
    idle_timeout_s=30.0,
    max_connections=8,
    clock_tolerance_s=60.0,
)


async def main() -> None:
    """Run E3 ingestion server."""
    print("Mini-Shark E3 Telemetry Server listening on port 9000...")
    await server.start()

    try:
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
        print("\nShutting down E3 server...")
        corr_engine.expire_deadlines()

        if records_buffer:
            try:
                engine.store_correlations(records_buffer)
            except Exception as exc:
                logger.warning("Flush error: %s", exc)

        s = corr_engine.get_stats()["correlation"]
        total = s["matched_total"] + s["unmatched_total"]
        loss_pct = (s["unmatched_total"] / max(1, total)) * 100

        print(f"Summary: Matched={s['matched_total']} Lost={s['unmatched_total']} ({loss_pct:.1f}% loss)")
        engine.close()
