"""
E3 Correlation Hub — standalone TCP ingestion server.

Run this FIRST on Machine 2 (the central server) before starting any probes.

    python run_e3_server.py

Listens on TCP port 9000. Both probes connect, send the 16-byte MSHK
preamble, then stream 24-byte ProbeTelemetry records continuously.
Matched packets are stored in mini_shark.db and diagnostic alerts are fired.
"""

import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from backend.e3_flows.correlator import CorrelationHub
from backend.e4_query.engine import QueryEngine
from backend.e4_query.diagnostics import run_diagnostics
from backend.models import CorrelationRecord

engine  = QueryEngine('mini_shark.db')
records_buffer: list[CorrelationRecord] = []
FLUSH_EVERY = 10

SEP  = "─" * 62
SEP2 = "═" * 62


def on_record(rec: CorrelationRecord) -> None:
    """Called by the hub for every correlation event."""
    records_buffer.append(rec)

    icon = {
        'matched':    '✓ MATCHED   ',
        'unmatched':  '✗ LOST      ',
        'late':       '⏱ LATE      ',
        'probe2_only':'? P2-ONLY   ',
    }.get(rec.match_state, '?           ')

    delay_str = ''
    if rec.delay_ns is not None:
        ms = rec.delay_ns / 1_000_000
        delay_str = f'  ΔT = {ms:7.3f} ms'
        if rec.flags & 1:
            delay_str += '  ⚠ CLOCK SKEW'

    print(f'  {icon}  fp=0x{rec.fingerprint:016X}{delay_str}')

    # Persist + diagnose every FLUSH_EVERY records
    if len(records_buffer) % FLUSH_EVERY == 0:
        try:
            engine.store_correlations(records_buffer[-FLUSH_EVERY:])
            alerts = run_diagnostics(records_buffer)
            if alerts:
                engine.repo.store_alerts(alerts)
                print()
                for a in alerts:
                    sev = {'critical':'🔴','warning':'🟡','info':'🔵'}.get(a.severity,'⚪')
                    print(f'  {sev} ALERT [{a.severity.upper()}] {a.category}')
                    print(f'     confidence : {a.confidence}')
                    for k, v in list(a.metrics.items())[:3]:
                        print(f'     {k} : {v}')
                    print(f'     action : {a.recommended_action[:70]}...')
                print()
        except Exception as e:
            print(f'  [storage] {e}')


hub = CorrelationHub(
    timeout_ms=500,
    on_record=on_record,
    probe1_id=1,
    probe2_id=2,
)


async def main() -> None:
    print(f'\n{SEP2}')
    print('  Mini-Shark  ·  E3 Multi-Point Correlation Hub')
    print(SEP2)
    print('  Port     : 9000 (TCP)')
    print('  Timeout  : 500 ms per packet')
    print('  Probe 1  : client / source side')
    print('  Probe 2  : server / gateway side')
    print('  Database : mini_shark.db')
    print(f'{SEP}')
    print('  Waiting for probes to connect...\n')

    async def expire_loop() -> None:
        while True:
            hub.flush_expired()
            await asyncio.sleep(0.2)

    asyncio.create_task(expire_loop())
    await hub.start_server(host='0.0.0.0', port=9000)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f'\n{SEP}')
        print('  Shutting down — flushing remaining entries...')
        hub.flush_all()
        if records_buffer:
            try:
                engine.store_correlations(records_buffer)
            except Exception:
                pass
        s = hub.stats
        total = s['matched'] + s['unmatched']
        loss  = s['unmatched'] / max(1, total) * 100
        print(f'\n  Session summary:')
        print(f'    Matched   : {s["matched"]}')
        print(f'    Unmatched : {s["unmatched"]}')
        print(f'    Late      : {s["late"]}')
        print(f'    Loss rate : {loss:.1f}%')
        print(f'{SEP2}')
        engine.close()
