"""
Mini-Shark — Probe Runner (E1 + E2 + Telemetry Sender)
=======================================================
Run this on EACH probe machine AFTER the central server is started.

    Probe 1 (Client VM  192.168.10.11):
        sudo python run_probe.py --probe-id 1 --server 192.168.10.1:9000 --iface ens33

    Probe 2 (Server VM  192.168.20.20):
        sudo python run_probe.py --probe-id 2 --server 192.168.10.1:9000 --iface ens33

    Windows dev machine (single-host test):
        python run_probe.py --probe-id 1 --server 127.0.0.1:9000

    With BPF / interface filter:
        sudo python run_probe.py --probe-id 1 --server 192.168.10.1:9000 \\
            --iface ens33 --filter "tcp or port 53"

Capture backend selection (automatic):
    Linux   → AF_PACKET raw socket (zero extra deps, requires sudo/CAP_NET_RAW)
    Windows → Scapy + Npcap  (pip install scapy, Npcap from https://npcap.com)

Connection flow:
    Probe → TCP connect to port 9000 → MSHK preamble → 24-byte records (+ heartbeats)
"""

from __future__ import annotations

import argparse
import platform
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from backend.e1_capture.live import get_live_capturer, _pick_interface
from backend.e2_dissection.engine import ProtocolDissector
from backend.probe.client import TelemetryClient
from backend.models import Packet

SEP  = "─" * 62
SEP2 = "═" * 62

_HEARTBEAT_INTERVAL_S = 5.0   # send a heartbeat every N seconds of idle traffic


# ─────────────────────────────────────────────────────────────────
# Startup guard — warn when connecting to loopback in multi-VM mode
# ─────────────────────────────────────────────────────────────────

def _warn_if_loopback(host: str, probe_id: int) -> None:
    """Print a prominent warning when the server address resolves to loopback."""
    if host in ("127.0.0.1", "::1", "localhost"):
        print(
            f"\n  ⚠  WARNING: Probe {probe_id} is connecting to loopback ({host}).\n"
            f"     This is fine for single-machine testing, but in a multi-VM\n"
            f"     deployment you almost certainly want:\n"
            f"       --server 192.168.10.1:9000  (the hub VM's IP address)\n"
        )


# ─────────────────────────────────────────────────────────────────
# Main probe loop
# ─────────────────────────────────────────────────────────────────

def run_probe(
    probe_id: int,
    host: str,
    port: int,
    iface: str | None,
    bpf_filter: str,
) -> None:

    _warn_if_loopback(host, probe_id)

    dissector = ProtocolDissector()

    # Resolve interface name (Windows scapy GUID lookup; on Linux pass-through)
    if platform.system() == "Windows":
        iface_name = _pick_interface(iface)
    else:
        iface_name = iface or "eth0"

    print(f"\n{SEP2}")
    print(f"  Mini-Shark  ·  Probe {probe_id}")
    print(SEP2)
    print(f"  OS          : {platform.system()}")
    print(f"  Interface   : {iface_name}")
    print(f"  E3 Server   : {host}:{port}")
    print(f"  BPF filter  : {bpf_filter or '(none — capture everything)'}")
    print(f"  Algorithm   : BLAKE2b-64  |  Timeout: 500 ms")
    print(f"{SEP}")

    # ── Connect to E3 ──────────────────────────────────────────────
    client = TelemetryClient(host=host, port=port, probe_id=probe_id)
    client.connect()

    # ── Build capture backend ──────────────────────────────────────
    capturer = get_live_capturer(iface=iface_name, timeout=2.0)

    print(f"\n  [Probe {probe_id}] Backend    : {type(capturer).__name__}")
    print(f"  [Probe {probe_id}] Starting continuous live capture...")
    print(f"  [Probe {probe_id}] Press Ctrl+C to stop\n")
    print(f"  {'#':<8} {'Layers':<38} {'Fingerprint':<20} {'Info'}")
    print(f"  {'-'*8} {'-'*38} {'-'*20} {'-'*30}")

    seq      = 0
    sent     = 0
    skipped  = 0
    fragments = 0
    last_hb  = time.time()

    try:
        while True:
            # ── Heartbeat (before capture burst so idle probes stay alive) ──
            if time.time() - last_hb >= _HEARTBEAT_INTERVAL_S:
                ok = client.send_heartbeat(seq=seq)
                if not ok:
                    print(f"\n  [Probe {probe_id}] Lost connection (heartbeat). Reconnecting...")
                    client.reconnect()
                last_hb = time.time()

            # ── Capture a 2-second burst ────────────────────────────
            try:
                raw_pkts = capturer.capture(count=100, bpf_filter=bpf_filter)
            except Exception as exc:
                print(f"  [Probe {probe_id}] Capture error: {exc}")
                time.sleep(1)
                continue

            for sp in raw_pkts:
                # sp is already a Packet from AFPacketCapture / LiveCapture
                pkt = sp

                decoded = dissector.dissect_one(pkt)

                # Skip probe telemetry and web traffic to avoid sniffer feedback loop
                is_internal = False
                for layer in decoded.layers:
                    if layer.name in ("TCP", "UDP"):
                        sp_p = layer.fields.get("src_port")
                        dp_p = layer.fields.get("dst_port")
                        if sp_p in (port, 8001, 5173) or dp_p in (port, 8001, 5173):
                            is_internal = True
                            break
                if is_internal:
                    continue

                # Detect IP fragments (no fingerprint possible)
                is_frag = any(
                    layer.fields.get("fragment")
                    for layer in decoded.layers
                    if layer.name == "IPv4"
                )

                if decoded.fingerprint is None:
                    if is_frag:
                        fragments += 1
                    else:
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

                # Send with auto-reconnect on failure
                ok = client.send(wire)
                if not ok:
                    print(f"\n  [Probe {probe_id}] Lost connection. Reconnecting...")
                    client.reconnect()
                    client.send(wire)   # retry once after reconnect

                sent += 1
                seq  += 1

                # ── Console output every 5th packet ────────────────
                if sent % 5 == 1:
                    layers    = " > ".join(l.name for l in decoded.layers)
                    fp_short  = f"0x{decoded.fingerprint.value:016X}"
                    info      = ""
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

            # Reset heartbeat timer after any burst that produced packets
            if raw_pkts:
                last_hb = time.time()

    except KeyboardInterrupt:
        print(f"\n{SEP}")
        print(f"  [Probe {probe_id}] Stopped by user.")
        print(f"  Packets sent      : {sent}")
        print(f"  Skipped (no fp)   : {skipped}")
        print(f"  Fragments (no fp) : {fragments}")
        print(f"  Total captured    : {seq}")
        print(f"{SEP2}\n")

    finally:
        client.close()


# ─────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini-Shark Probe Runner — E1 + E2 + telemetry sender",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  Linux  (Probe 1): sudo python run_probe.py --probe-id 1 "
            "--server 192.168.10.1:9000 --iface ens33\n"
            "  Windows (Probe 1): python run_probe.py --probe-id 1 "
            "--server 192.168.10.1:9000 --iface Wi-Fi\n"
        ),
    )
    parser.add_argument(
        "--probe-id", type=int, required=True, choices=[1, 2],
        help="Probe identity: 1=client side, 2=server/gateway side",
    )
    parser.add_argument(
        "--server", type=str, default="127.0.0.1:9000",
        help="Central hub address as host:port (default: 127.0.0.1:9000). "
             "In multi-VM deployment use the hub VM IP, e.g. 192.168.10.1:9000",
    )
    parser.add_argument(
        "--iface", type=str, default=None,
        help="Network interface (Linux: eth0/ens33; Windows: Wi-Fi/Ethernet). "
             "Default: eth0 on Linux, auto-detect Wi-Fi on Windows.",
    )
    parser.add_argument(
        "--filter", type=str, default="",
        dest="bpf_filter",
        help='BPF filter string, e.g. "tcp" or "port 53" (Windows/Scapy only).',
    )
    args = parser.parse_args()

    parts = args.server.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        print("Error: --server must be host:port  e.g. 192.168.10.1:9000")
        sys.exit(1)

    host, port = parts[0], int(parts[1])
    run_probe(
        probe_id=args.probe_id,
        host=host,
        port=port,
        iface=args.iface,
        bpf_filter=args.bpf_filter,
    )


if __name__ == "__main__":
    main()
