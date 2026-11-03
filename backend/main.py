"""Mini-Shark — FastAPI entry point.

On startup, automatically launches the E3 TCP ingestion server on port 9000
as a background asyncio task. This means running one command:

    uvicorn backend.main:app --reload --port 8001

...starts BOTH the REST/WebSocket API (port 8001) AND the E3 probe
ingestion server (port 9000) in a single process, sharing one
CorrelationHub instance.

Probes then connect to port 9000 and the dashboard connects to port 8001.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router, get_hub, get_engine
from .e4_query.diagnostics import run_diagnostics

logger = logging.getLogger(__name__)

E3_HOST = os.environ.get("MINISHARK_TELEMETRY_HOST", "0.0.0.0")
E3_PORT = int(os.environ.get("MINISHARK_TELEMETRY_PORT", "9000"))


# ── Lifespan: start E3 server when FastAPI starts ────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start E3 TCP server on port 9000 alongside the FastAPI server."""

    hub  = get_hub()     # shared hub — same object used by API routes
    task = asyncio.create_task(
        hub.start_server(host=E3_HOST, port=E3_PORT),
        name="e3-tcp-server",
    )
    logger.info("E3 telemetry ingestion server started on %s:%d", E3_HOST, E3_PORT)
    print(f"\n  [E3] TCP ingestion server listening on {E3_HOST}:{E3_PORT}")
    print(f"  [E3] Probes should connect to this port")
    print(f"  [API] REST + WebSocket available on port 8001\n")

    yield   # FastAPI runs here

    # Shutdown
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Final flush + diagnostics
    remaining = hub.flush_all()
    records   = hub.records
    if records:
        try:
            engine = get_engine()
            engine.store_correlations(records)
            alerts = run_diagnostics(records)
            if alerts:
                engine.repo.store_alerts(alerts)
        except Exception as exc:
            logger.warning("Shutdown persistence error: %s", exc)

    logger.info("E3 server stopped. Stats: %s", hub.stats)
    print(f"\n  [E3] Shutdown complete. Session stats: {hub.stats}")


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Mini Shark",
    description=(
        "Distributed Multi-Point Latency & Packet Loss Tracing System. "
        "E3 TCP ingestion: port 9000. REST/WebSocket API: port 8001."
    ),
    version="0.4.0",
    lifespan=lifespan,
)

# Allow the React dashboard (port 5173) and any other origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
async def health_check() -> dict:
    hub    = get_hub()
    engine = get_engine()
    stats  = hub.stats
    total  = stats["matched"] + stats["unmatched"]
    return {
        "status":    "ok",
        "version":   "0.4.0",
        "e3_server": f"{E3_HOST}:{E3_PORT}",
        "probes_connected": 0,   # TODO: track active connections in hub
        "correlation_stats": {
            "matched":   stats["matched"],
            "unmatched": stats["unmatched"],
            "late":      stats["late"],
            "loss_rate": round(stats["unmatched"] / max(1, total), 4),
        },
    }


@app.get("/status")
async def system_status() -> dict:
    """Full system status — which probes are connected, DB stats, etc."""
    hub    = get_hub()
    engine = get_engine()

    db_stats = engine.correlation_stats()
    alerts   = engine.alerts(limit=5)

    return {
        "api_port":  8001,
        "e3_port":   E3_PORT,
        "hub_stats": hub.stats,
        "database":  db_stats,
        "recent_alerts": [
            {
                "category":  a.category,
                "severity":  a.severity,
                "confidence": a.confidence,
            }
            for a in alerts
        ],
    }
