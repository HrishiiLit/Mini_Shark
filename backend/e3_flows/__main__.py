"""Run the standalone telemetry hub: python -m backend.e3_flows --help."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from contextlib import suppress
from dataclasses import asdict

from .correlation import CorrelationEngine
from .ingestion import TelemetryServer


async def serve(args: argparse.Namespace) -> None:
    engine = CorrelationEngine(timeout_ms=args.timeout_ms, heap_cap=args.capacity)
    engine.subscribe(lambda record: print(json.dumps(asdict(record)), flush=True))
    server = TelemetryServer(engine, host=args.host, port=args.port)
    await server.start()
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini-Shark TCP telemetry hub")
    parser.add_argument(
        "--host", default=os.getenv("MINISHARK_TELEMETRY_HOST", "0.0.0.0")
    )
    parser.add_argument(
        "--port", type=int, default=os.getenv("MINISHARK_TELEMETRY_PORT", "9000")
    )
    parser.add_argument(
        "--timeout-ms", type=int, default=os.getenv("MINISHARK_MATCH_TIMEOUT_MS", "500")
    )
    parser.add_argument("--capacity", type=int, default=200_000)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    with suppress(KeyboardInterrupt):
        asyncio.run(serve(args))


if __name__ == "__main__":
    main()
