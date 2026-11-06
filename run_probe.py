"""Mini-Shark live probe runner.

Captures packets on a specified network interface (E1), extracts invariant
packet header fields to compute 64-bit BLAKE2b fingerprints (E2), and streams
24-byte telemetry records to the central correlation hub on port 9000.
"""

from __future__ import annotations

import argparse
import platform
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from backend.e1_capture.live import get_live_capturer, _pick_interface, _pick_linux_interface
from backend.e2_dissection.engine import ProtocolDissector
from backend.probe.client import TelemetryClient
from backend.models import Packet

SEP = "─" * 60
_HEARTBEAT_INTERVAL_S = 5.0


def _warn_if_loopback(host: str, probe_id: int) -> None:
    """Warn when probe is connecting to loopback during multi-host deployments."""
    if host in ("127.0.0.1", "::1", "localhost"):
        print(
            f"\n  [Notice] Probe {probe_id} connecting to loopback ({host}).\n"
            f"  For multi-machine setups, specify the central server IP (e.g. --server 10.108.157.2:9000).\n"
        )


def run_probe(
    probe_id: int,
    host: str,
    port: int,
    iface: str | None,
    bpf_filter: str,
) -> None:
    """Run live capture loop and stream packet fingerprints to E3 server."""
    _warn_if_loopback(host, probe_id)

    dissector = ProtocolDissector()

    # Resolve capture interface
    if platform.system() == "Windows":
        iface_name = _pick_interface(iface)
    else:
        iface_name = _pick_linux_interface(iface, target_host=host)

    if iface and iface != iface_name:
        print(f"  [Probe {probe_id}] Notice: interface '{iface}' unavailable; using '{iface_name}'")

    print(f"\n{SEP}")
    print(f"  Mini-Shark Probe {probe_id}")
    print(SEP)
    print(f"  OS          : {platform.system()}")
    print(f"  Interface   : {iface_name}")
    print(f"  E3 Server   : {host}:{port}")
    print(f"  BPF filter  : {bpf_filter or '(none — capture everything)'}")
    print(f"  Algorithm   : BLAKE2b-64")
    print(f"{SEP}")

    # Connect to telemetry server
    client = TelemetryClient(host=host, port=port, probe_id=probe_id)
    client.connect()

    capturer = get_live_capturer(iface=iface_name, timeout=1.0, target_host=host)

    print(f"\n  [Probe {probe_id}] Backend    : {type(capturer).__name__}")
    print(f"  [Probe {probe_id}] Live capture started. Press Ctrl+C to stop.\n")
    print(f"  {'#':<8} {'Layers':<38} {'Fingerprint':<20} {'Info'}")
    print(f"  {'-'*8} {'-'*38} {'-'*20} {'-'*30}")

    seq = 0
    sent = 0
    skipped = 0
    fragments = 0
    last_hb = time.time()
    last_packet_time = time.time()

    try:
        while True:
            # Idle keepalive heartbeat
            now = time.time()
            if now - last_packet_time >= _HEARTBEAT_INTERVAL_S and now - last_hb >= _HEARTBEAT_INTERVAL_S:
                ok = client.send_heartbeat(seq=seq)
                if not ok:
                    print(f"\n  [Probe {probe_id}] Reconnecting...")
                    client.reconnect()
                last_hb = now

            try:
                raw_pkts = capturer.capture(count=100, bpf_filter=bpf_filter)
            except Exception as exc:
                print(f"  [Probe {probe_id}] Capture error: {exc}")
                time.sleep(1)
                continue

            for pkt in raw_pkts:
                decoded = dissector.dissect_one(pkt)

                # Ignore probe telemetry traffic (port 9000), backend API/WS traffic (port 8001), and SSH (port 22)
                # to prevent positive feedback loops and management traffic flooding
                is_infra = False
                for layer in decoded.layers:
                    if layer.name in ("TCP", "UDP"):
                        sport = layer.fields.get("src_port")
                        dport = layer.fields.get("dst_port")
                        if sport in (port, 8001, 22) or dport in (port, 8001, 22):
                            is_infra = True
                            break
                if is_infra:
                    continue

                # Protocol post-filtering
                if bpf_filter:
                    filt = bpf_filter.strip().lower()
                    layer_names = [l.name.lower() for l in decoded.layers]
                    if filt in ("icmp", "ping") and "icmp" not in layer_names and "icmpv6" not in layer_names:
                        continue
                    if filt in ("tcp",) and "tcp" not in layer_names:
                        continue
                    if filt in ("udp",) and "udp" not in layer_names:
                        continue
                    if filt in ("dns",) and "dns" not in layer_names:
                        continue

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
                    decoded,
                    pkt,
                    probe_id=probe_id,
                    seq=seq,
                )
                if telemetry is None:
                    skipped += 1
                    continue

                wire = telemetry.pack()

                ok = client.send(wire)
                if not ok:
                    print(f"\n  [Probe {probe_id}] Connection lost, reconnecting...")
                    client.reconnect()
                    client.send(wire)

                sent += 1
                seq += 1
                last_packet_time = time.time()

                # Print sample output every 5th packet
                if sent % 5 == 1:
                    layers = " > ".join(l.name for l in decoded.layers)
                    fp_short = f"0x{decoded.fingerprint.value:016X}"
                    info = ""
                    for layer in decoded.layers:
                        if layer.name == "DNS":
                            qs = layer.fields.get("questions", [])
                            name = qs[0].get("name", "") if qs else ""
                            H = decoded.dns_entropy
                            info = f"DNS: {name[:25]}"
                            if H and H > 4.2:
                                info += f" [H={H:.2f}]"
                            break
                        if layer.name == "HTTP":
                            info = layer.fields.get("start_line", "")[:30]
                            break
                        if layer.name == "TCP":
                            info = f"{layer.fields.get('src_port','')} → {layer.fields.get('dst_port','')}"
                    print(f"  {sent:<8} {layers[:38]:<38} {fp_short:<20} {info}")

    except KeyboardInterrupt:
        print(f"\n\n{SEP}")
        print(f"  Probe {probe_id} stopped")
        print(f"  Sent records      : {sent}")
        print(f"  Skipped packets   : {skipped}")
        print(f"  Fragments (no fp) : {fragments}")
        print(f"  Total captured    : {seq}")
        print(f"{SEP}\n")

    finally:
        client.close()


def main() -> None:
    """CLI entry point for running a probe."""
    parser = argparse.ArgumentParser(
        description="Mini-Shark live probe runner (E1 capture + E2 fingerprinting)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--probe-id",
        type=int,
        required=True,
        help="Probe identity: 1=client side, 2=server side, 3+=additional clients",
    )
    parser.add_argument(
        "--server",
        type=str,
        default="127.0.0.1:9000",
        help="Central hub host:port (default: 127.0.0.1:9000)",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface to capture (auto-detected if omitted)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="",
        dest="bpf_filter",
        help="BPF filter expression (e.g. 'host 10.108.157.2')",
    )
    args = parser.parse_args()

    parts = args.server.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        print("Error: --server must be host:port format, e.g. 10.108.157.2:9000")
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
