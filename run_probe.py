"""
Mini-Shark — Probe Runner (E1 + E2 + Telemetry Sender)
=======================================================
Run this on EACH probe machine after the central server is started.

    Probe 1 (client machine):
        python run_probe.py --probe-id 1 --server 192.168.1.20:9000

    Probe 2 (server/gateway machine — same box as central server):
        python run_probe.py --probe-id 2 --server 127.0.0.1:9000

    With BPF filter (capture only DNS + TCP):
        python run_probe.py --probe-id 1 --server 192.168.1.20:9000 --filter "tcp or port 53"

Connection flow:
    Probe → TCP connect to port 9000 → send MSHK preamble → stream 24-byte records

Requires:
    - Npcap installed (Windows)
    - Run as Administrator
    - Central server already running (uvicorn backend.main:app --port 3000)
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from backend.e1_capture.live import LiveCapture, _pick_interface
from backend.e2_dissection.engine import ProtocolDissector
from backend.probe.client import TelemetryClient
from backend.models import Packet

SEP  = "─" * 62
SEP2 = "═" * 62


def run_probe(
    probe_id: int,
    host: str,
    port: int,
    iface: str | None,
    bpf_filter: str,
) -> None:

    dissector = ProtocolDissector()
    iface_name = _pick_interface(iface)

    print(f"\n{SEP2}")
    print(f"  Mini-Shark  ·  Probe {probe_id}")
    print(SEP2)
    print(f"  Interface   : {iface_name}")
    print(f"  E3 Server   : {host}:{port}")
    print(f"  BPF filter  : {bpf_filter or '(none — capture everything)'}")
    print(f"  Algorithm   : BLAKE2b-64  |  Timeout: 500ms")
    print(f"{SEP}")

    # ── Connect to E3 ──────────────────────────────────────────────────────
    client = TelemetryClient(host=host, port=port, probe_id=probe_id)
    client.connect()

    # ── Start live capture ────────────────────────────────────────────────
    print(f"\n  [Probe {probe_id}] Starting continuous live capture...")
    print(f"  [Probe {probe_id}] Press Ctrl+C to stop\n")
    print(f"  {'#':<8} {'Layers':<38} {'Fingerprint':<20} {'Info'}")
    print(f"  {'-'*8} {'-'*38} {'-'*20} {'-'*30}")

    seq   = 0
    sent  = 0
    skipped = 0

    try:
        from scapy.all import sniff

        while True:
            # Capture in 2-second bursts so we can check for Ctrl+C
            try:
                raw_pkts = sniff(
                    iface=iface_name,
                    count=100,
                    timeout=2,
                    filter=bpf_filter if bpf_filter else None,
                    store=True,
                )
            except Exception as exc:
                print(f"  [Probe {probe_id}] Capture error: {exc}")
                time.sleep(1)
                continue

            for sp in raw_pkts:
                try:
                    raw = bytes(sp)
                    ts  = float(sp.time) if hasattr(sp, "time") else time.time()
                except Exception:
                    continue

                pkt     = Packet(
                    index=seq, timestamp=ts,
                    length=len(raw), raw_bytes=raw,
                )
                decoded = dissector.dissect_one(pkt)

                # Skip packets we can't fingerprint (ARP etc.)
                if decoded.fingerprint is None:
                    skipped += 1
                    continue

                telemetry = dissector.make_telemetry(
                    decoded, pkt,
                    probe_id=probe_id,
                    seq=seq,
                )
                if telemetry is None:
                    skipped += 1
                    continue

                wire = telemetry.pack()

                # Send — reconnect if connection dropped
                ok = client.send(wire)
                if not ok:
                    print(f"\n  [Probe {probe_id}] Lost connection. Reconnecting...")
                    client.reconnect()
                    client.send(wire)  # retry once

                sent += 1
                seq  += 1

                # Print every 5th packet
                if sent % 5 == 1:
                    layers  = " > ".join(l.name for l in decoded.layers)
                    fp_short = f"0x{decoded.fingerprint.value:016X}"
                    info     = ""
                    for layer in decoded.layers:
                        if layer.name == "DNS":
                            qs   = layer.fields.get("questions", [])
                            name = qs[0].get("name", "") if qs else ""
                            H    = decoded.dns_entropy
                            info = f"DNS: {name[:25]}"
                            if H and H > 4.2:
                                info += f" ⚠ H={H:.2f}"
                            break
                        if layer.name == "HTTP":
                            info = layer.fields.get("start_line", "")[:30]
                            break
                        if layer.name == "TCP":
                            info = (
                                f"{layer.fields.get('src_port','')} → "
                                f"{layer.fields.get('dst_port','')}"
                            )
                    print(
                        f"  {sent:<8} {layers[:38]:<38} "
                        f"{fp_short:<20} {info}"
                    )

    except KeyboardInterrupt:
        print(f"\n{SEP}")
        print(f"  [Probe {probe_id}] Stopped by user.")
        print(f"  Packets sent    : {sent}")
        print(f"  Skipped (no fp) : {skipped}")
        print(f"  Total captured  : {seq}")
        print(f"{SEP2}\n")

    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini-Shark Probe Runner — E1 + E2 + telemetry sender"
    )
    parser.add_argument(
        "--probe-id", type=int, required=True, choices=[1, 2],
        help="Probe identity: 1=client side, 2=server/gateway side",
    )
    parser.add_argument(
        "--server", type=str, default="127.0.0.1:9000",
        help="Central server address as host:port (default: 127.0.0.1:9000)",
    )
    parser.add_argument(
        "--iface", type=str, default=None,
        help="Network interface (default: auto-detect Wi-Fi)",
    )
    parser.add_argument(
        "--filter", type=str, default="",
        help='BPF filter e.g. "tcp" or "port 53" (default: capture all)',
    )
    args = parser.parse_args()

    parts = args.server.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        print("Error: --server must be host:port  e.g. 192.168.1.20:9000")
        sys.exit(1)

    host, port = parts[0], int(parts[1])
    run_probe(
        probe_id=args.probe_id,
        host=host,
        port=port,
        iface=args.iface,
        bpf_filter=args.filter,
    )


if __name__ == "__main__":
    main()
