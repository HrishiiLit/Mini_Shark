"""FastAPI presentation layer: thin routes that only call the engines."""

from __future__ import annotations

from .routes import get_engine, router

__all__ = ["get_engine", "router"]
