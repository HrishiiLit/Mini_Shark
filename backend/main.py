"""FastAPI entry point: ``uvicorn backend.main:app --reload``."""

from __future__ import annotations

from fastapi import FastAPI

from .api.routes import router

app = FastAPI(
    title="Mini Shark",
    description="Network Traffic Analyzer and Protocol Analysis System",
    version="0.2.0",
)

app.include_router(router)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
