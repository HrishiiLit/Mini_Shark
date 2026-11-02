"""
Mini-Shark — Live Capture Demo
================================
Captures real packets from your Wi-Fi adapter, runs them through E2
(protocol dissection + BLAKE2b fingerprint + DNS entropy), and prints
a live summary — exactly what happens in the distributed pipeline.

Run as Administrator in the project root:

    .venv\Scripts\python.exe live_demo.py
    .venv\Scripts\python.exe live_demo.py --count 30 --filter "port 53"
    .venv\Scripts\python.exe live_demo.py --count 20 --filter "tcp"
    .venv\Scripts\python.exe live_demo.py --iface "Ethernet"
"""

from __future__ import annotations

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from backend.e1_capture.live import LiveCapture, _pick_interface
from backend.e2_dissection.engine import ProtocolDissector
from backend.e3_flows.engine import FlowGrouper

DNS_EXFIL_THRESHOLD = 4.2
SEP  = "─" * 68
SEP2 = "═" * 68


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Mini-Shark live capture demo")
    p.add_argument("--count",  type=int, default=20,   help="Packets to capture (default 20)")
    p.add_argument("--iface",  type=str, default=None, help="Interface name (default: Wi-Fi)")
    p.add_argument("--filter", type=str, default="",   help="BPF filter e.g. 'tcp' or 'port 53'")
    p.add_argument("--timeout",type=int, default=20,   help="Capture timeout seconds (default 20)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    iface = _pick_interface(args.iface)

    # Get friendly name for display
    try:
        from scapy.all import IFACES
        friendly = next(
            (getattr(e, "name", iface) for e in IFACES.values()
             if getattr(e, "network_name", "") == iface),
            iface
        )
    except Exception:
        friendly = iface

    print(f"\n{SEP2}")
    print("  Mini-Shark  |  Live Capture Demo  |  Engine E1 + E2")
    print(SEP2)
    print(f"  Interface : {friendly}  ({iface})")
    print(f"  Capturing : {args.count} packets", end="")
    if args.filter:
        print(f"  (filter: {args.filter})", end="")
    print(f"\n  Timeout   : {args.timeout}s")
    print(f"{SEP}")
    print("  Generating some traffic helps: open a browser, ping, browse YouTube...")
    print(f"{SEP}\n")

    # ── E1: Live Capture ────────────────────────────────────────────────
    print("  [E1] Starting live capture... (Ctrl+C to stop early)\n")
    t_start = time.time()

    try:
        capturer = LiveCapture(iface=iface, timeout=args.timeout)
        packets  = capturer.capture(count=args.count, bpf_filter=args.filter)
    except RuntimeError as exc:
        print(f"\n  ERROR: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Capture interrupted by user.")
        sys.exit(0)

    elapsed = time.time() - t_start
    print(f"  [E1] Captured {len(packets)} packets in {elapsed:.1f}s\n")

    if not packets:
        print("  No packets captured. Try generating some traffic or change the interface.")
        sys.exit(0)

    # ── E2: Dissect + Fingerprint + Entropy ─────────────────────────────
    print("  [E2] Dissecting packets...\n")
    dissector = ProtocolDissector()
    decoded   = dissector.dissect(packets)

    # ── E3: Flow grouping ───────────────────────────────────────────────
    flows = FlowGrouper().group(decoded, packets)
    stats = FlowGrouper.statistics(flows)

    # ── Print per-packet results ────────────────────────────────────────
    dns_alerts  = []
    fingerprints_seen: set[int] = set()

    for pkt, dec in zip(packets, decoded):
        layer_names = " > ".join(l.name for l in dec.layers)
        ts = time.strftime("%H:%M:%S", time.localtime(pkt.timestamp))

        fp_str = f"0x{dec.fingerprint.value:016X}" if dec.fingerprint else "none"

        print(f"  [{ts}]  #{pkt.index:<3}  {pkt.length:>5}B  {layer_names}")
        print(f"           fingerprint: {fp_str}")

        if dec.dns_entropy is not None:
            flag = "  *** HIGH ENTROPY — possible DNS tunnel!" if dec.dns_entropy > DNS_EXFIL_THRESHOLD else ""
            print(f"           DNS entropy: H = {dec.dns_entropy:.4f}{flag}")
            if dec.dns_entropy > DNS_EXFIL_THRESHOLD:
                # find the query name for the alert
                for layer in dec.layers:
                    if layer.name == "DNS":
                        qs = layer.fields.get("questions", [])
                        if qs:
                            dns_alerts.append((pkt.index, qs[0].get("name","?"), dec.dns_entropy))

        if dec.fingerprint:
            fingerprints_seen.add(dec.fingerprint.value)

        # Build telemetry record
        telemetry = dissector.make_telemetry(dec, pkt, probe_id=1, seq=pkt.index)
        if telemetry:
            raw = telemetry.pack()
            print(f"           telemetry : [{raw.hex(' ').upper()}]  (24B -> E3)")

        print()

    # ── Summary ─────────────────────────────────────────────────────────
    print(SEP2)
    print("  SUMMARY")
    print(SEP2)
    print(f"  Packets captured    : {len(packets)}")
    print(f"  Unique fingerprints : {len(fingerprints_seen)}")
    print(f"  Flows detected      : {len([f for f in flows if f.flow_id != -1])}")
    print(f"  Ungrouped (ARP etc) : {len([f for f in flows if f.flow_id == -1])}")
    print()

    # Protocol breakdown
    print("  Protocol breakdown:")
    for proto, s in stats.items():
        bar = "#" * int(s["share"] * 30)
        print(f"    {proto:<12} {s['packets']:>4} pkts  {s['bytes']:>7}B  [{bar:<30}] {s['share']*100:.1f}%")
    print()

    # DNS alerts
    if dns_alerts:
        print(f"  *** DNS EXFILTRATION ALERTS (H > {DNS_EXFIL_THRESHOLD}) ***")
        for idx, name, H in dns_alerts:
            print(f"    Packet #{idx}  name='{name}'  H={H:.4f}")
        print()
    else:
        print("  No DNS exfiltration signals detected.")

    # Flow list
    print()
    print("  Flows:")
    for flow in flows:
        if flow.flow_id == -1:
            continue
        src, dst, sp, dp, proto = flow.five_tuple
        print(f"    [{proto}] {src}:{sp} -> {dst}:{dp}  "
              f"{flow.packet_count} pkts  {flow.byte_count}B  "
              f"duration={flow.duration:.3f}s")

    print(f"\n{SEP2}\n")


if __name__ == "__main__":
    main()
