"""Reproducible E3 synthetic benchmark: python benchmark_e3.py --packets 20000.

Reports packet-pair rates (two telemetry records per pair). Socket throughput
includes packing, sending and receipt; direct throughput excludes transport.
Memory is Python-traced peak allocation, not process RSS or a capture benchmark.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import time
import tracemalloc

from backend.e3_flows import CorrelationEngine, TelemetryClient, TelemetryServer
from backend.models import ProbeTelemetry


def observation(index: int, probe: int, stamp: int) -> ProbeTelemetry:
    return ProbeTelemetry(index, stamp + probe * 1_000_000, index, probe, 0x11, 1200)


def direct(packets: int) -> float:
    engine = CorrelationEngine(clock_ns=lambda: 0)
    start = time.perf_counter()
    for index in range(packets):
        engine.process_telemetry(observation(index, 1, 1_000_000_000))
        engine.process_telemetry(observation(index, 2, 1_000_000_000))
    elapsed = time.perf_counter() - start
    assert engine.matched_total == packets
    assert engine.get_stats()["structures"]["heap_entries"] == 0
    return packets / elapsed


def flood(packets: int) -> dict:
    engine = CorrelationEngine(
        heap_cap=1024, recent_cache_size=1024, clock_ns=lambda: 0
    )
    tracemalloc.start()
    for index in range(packets):
        engine.process_telemetry(observation(index, 2, 1_000_000_000))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    structures = engine.get_stats()["structures"]
    assert structures["hash_entries"] <= 1024
    assert structures["heap_entries"] <= 2048
    return {
        "python_peak_bytes": peak,
        "structures": structures,
        "capacity_evictions": engine.heap_cap_hits,
    }


async def network(packets: int) -> float:
    engine = CorrelationEngine()
    received = asyncio.Event()
    target = 0

    def on_match(_record):
        if engine.matched_total >= target:
            received.set()

    engine.subscribe(on_match)
    server = TelemetryServer(engine, host="127.0.0.1", port=0)
    await server.start()
    clients = [TelemetryClient(server.host, server.port, probe_id=i) for i in (1, 2)]
    try:
        for client in clients:
            await client.connect()
        start = time.perf_counter()
        for offset in range(0, packets, 100):
            target = min(offset + 100, packets)
            received.clear()
            stamp = time.time_ns()
            for probe, client in enumerate(clients, 1):
                await client.send_batch(
                    [
                        observation(index, probe, stamp)
                        for index in range(offset, min(offset + 100, packets))
                    ]
                )
            async with asyncio.timeout(5):
                await received.wait()
        assert engine.matched_total == packets
        return packets / (time.perf_counter() - start)
    except TimeoutError as exc:
        raise RuntimeError(json.dumps(engine.get_stats())) from exc
    finally:
        for client in clients:
            await client.close()
        await server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=20_000)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if args.packets <= 0 or args.runs <= 0:
        parser.error("packets and runs must be positive")
    direct_rates = [direct(args.packets) for _ in range(args.runs)]
    network_rates = [asyncio.run(network(args.packets)) for _ in range(args.runs)]
    print(
        json.dumps(
            {
                "python": platform.python_version(),
                "os": platform.system(),
                "packet_pairs_per_run": args.packets,
                "runs": args.runs,
                "direct_pairs_per_second": direct_rates,
                "tcp_pairs_per_second": network_rates,
                "direct_median_pairs_per_second": statistics.median(direct_rates),
                "tcp_median_pairs_per_second": statistics.median(network_rates),
                "tcp_timeout_ms": 500,
                "tcp_max_in_flight_pairs": 100,
                "flood": flood(args.packets),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
