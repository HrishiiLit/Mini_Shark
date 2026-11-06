"""FastAPI application entry point for Mini-Shark.

Runs both the REST/WebSocket API (port 8001) and the background E3 TCP telemetry
ingestion server (port 9000).
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router, get_hub, get_engine, _get_probes_status
from .e4_query.diagnostics import run_diagnostics

logger = logging.getLogger(__name__)

E3_HOST = os.environ.get("MINISHARK_TELEMETRY_HOST", "0.0.0.0")
E3_PORT = int(os.environ.get("MINISHARK_TELEMETRY_PORT", "9000"))


# Lifespan context to run E3 server alongside FastAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start E3 TCP server on port 9000 alongside the FastAPI server."""
    hub = get_hub()
    task = asyncio.create_task(
        hub.start_server(host=E3_HOST, port=E3_PORT),
        name="e3-tcp-server",
    )
    logger.info("E3 telemetry ingestion server started on %s:%d", E3_HOST, E3_PORT)

    yield

    # Shutdown and flush remaining observations
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    records = hub.records
    if records:
        try:
            engine = get_engine()
            engine.store_correlations(records)
            alerts = run_diagnostics(records)
            if alerts:
                engine.repo.store_alerts(alerts)
        except Exception as exc:
            logger.warning("Shutdown persistence error: %s", exc)


app = FastAPI(
    title="Mini Shark",
    description="Distributed Multi-Point Latency & Packet Loss Tracing System.",
    version="0.4.0",
    lifespan=lifespan,
)

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
    """Basic health check and correlation statistics."""
    hub = get_hub()
    stats = hub.stats
    total = stats["matched"] + stats["unmatched"]
    probes = hub.probe_status()
    return {
        "status": "ok",
        "version": "0.4.0",
        "e3_server": f"{E3_HOST}:{E3_PORT}",
        "probes_connected": probes["total_connected"],
        "correlation_stats": {
            "matched": stats["matched"],
            "unmatched": stats["unmatched"],
            "late": stats["late"],
            "loss_rate": round(stats["unmatched"] / max(1, total), 4),
        },
    }


@app.get("/status")
async def system_status() -> dict:
    """Full system and database status."""
    hub = get_hub()
    engine = get_engine()

    db_stats = engine.correlation_stats()
    alerts = engine.alerts(limit=5)

    return {
        "api_port": 8001,
        "e3_port": E3_PORT,
        "hub_stats": hub.stats,
        "database": db_stats,
        "recent_alerts": [
            {
                "category": a.category,
                "severity": a.severity,
                "confidence": a.confidence,
            }
            for a in alerts
        ],
    }
