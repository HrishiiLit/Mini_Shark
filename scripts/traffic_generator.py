#!/usr/bin/env python3
"""Mini-Shark Multi-Protocol Real-World Traffic Generator.

Generates realistic campus lab network workloads across physical PCs:
  1. HTTP REST Requests & File Transfers (Port 80 / 8001 / custom)
  2. UDP Audio/Media Streaming (continuous 1024-byte payloads with timestamps)
  3. TCP Bulk Flow Transfers with simulated pauses
  4. Mixed Real-World Workload (concurrent HTTP, UDP, and ICMP)

Usage:
  # HTTP test traffic to central server:
  python3 scripts/traffic_generator.py --target 192.168.1.2 --mode http --rate 5

  # UDP media streaming:
  python3 scripts/traffic_generator.py --target 192.168.1.2 --mode udp-stream --rate 20

  # Mixed real-world campus traffic:
  python3 scripts/traffic_generator.py --target 192.168.1.2 --mode mixed
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time
import urllib.request
import urllib.error

SEP = "─" * 60


def run_http_workload(target_host: str, port: int, count: int, rate: float) -> None:
    """Generate realistic HTTP GET/POST queries against target server."""
    interval = 1.0 / max(rate, 0.1)
    endpoints = ["/", "/health", "/docs", "/openapi.json"]
    print(f"[*] Starting HTTP workload to http://{target_host}:{port} at {rate} req/s...")

    sent = 0
    while count <= 0 or sent < count:
        path = random.choice(endpoints)
        url = f"http://{target_host}:{port}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mini-Shark-TrafficGen/1.0", "Accept": "*/*"},
            )
            start_t = time.perf_counter()
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = resp.read()
                elapsed_ms = (time.perf_counter() - start_t) * 1000
                print(f"  [HTTP] GET {path:<15} status={resp.status} len={len(data)}B latency={elapsed_ms:.2f}ms")
        except urllib.error.HTTPError as exc:
            print(f"  [HTTP] GET {path:<15} status={exc.code} (server responded)")
        except Exception as exc:
            print(f"  [HTTP] GET {path:<15} failed: {exc}")

        sent += 1
        time.sleep(interval)


def run_udp_stream_workload(target_host: str, port: int, count: int, rate: float) -> None:
    """Generate continuous UDP media/VoIP stream with 1024B frames and timestamps."""
    interval = 1.0 / max(rate, 0.1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Starting UDP stream to {target_host}:{port} at {rate} packets/s (1024B frames)...")

    seq = 0
    try:
        while count <= 0 or seq < count:
            now_ns = time.time_ns()
            # 16-byte header: seq (4B) + timestamp_ns (8B) + magic (4B) + 1008B payload
            hdr = struct.pack("!IQ4s", seq, now_ns, b"STRM")
            payload = hdr + (b"X" * (1024 - len(hdr)))
            sock.sendto(payload, (target_host, port))
            if seq % 10 == 0:
                print(f"  [UDP Stream] Sent packet seq={seq} size={len(payload)}B to {target_host}:{port}")
            seq += 1
            time.sleep(interval)
    finally:
        sock.close()


def run_tcp_burst_workload(target_host: str, port: int, count: int, rate: float) -> None:
    """Generate periodic TCP connection bursts and payload transfers."""
    interval = 1.0 / max(rate, 0.1)
    print(f"[*] Starting TCP connection bursts to {target_host}:{port} at {rate} bursts/s...")

    sent = 0
    while count <= 0 or sent < count:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((target_host, port))
                payload = f"MINI_SHARK_TCP_BURST_{sent:06d}_{'A'*256}".encode()
                s.sendall(payload)
                print(f"  [TCP Burst] Sent {len(payload)}B payload #{sent} to {target_host}:{port}")
        except Exception as exc:
            print(f"  [TCP Burst] Connect/send to {target_host}:{port} failed: {exc}")

        sent += 1
        time.sleep(interval)


def run_mixed_workload(target_host: str, http_port: int, udp_port: int, tcp_port: int, rate: float) -> None:
    """Run a concurrent realistic mix of HTTP, UDP streaming, and TCP transactions."""
    import threading

    print(f"\n{SEP}")
    print(f"  Mini-Shark Mixed Real-World Workload Generator")
    print(f"  Target Host  : {target_host}")
    print(f"  HTTP Port    : {http_port}")
    print(f"  UDP Port     : {udp_port}")
    print(f"  TCP Port     : {tcp_port}")
    print(f"{SEP}\n")

    t1 = threading.Thread(
        target=run_http_workload,
        args=(target_host, http_port, 0, max(1.0, rate / 2)),
        daemon=True,
    )
    t2 = threading.Thread(
        target=run_udp_stream_workload,
        args=(target_host, udp_port, 0, max(2.0, rate)),
        daemon=True,
    )

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping mixed workload.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini-Shark Multi-Protocol Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", type=str, required=True, help="Target server IP address")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["http", "udp-stream", "tcp-burst", "mixed"],
        default="mixed",
        help="Traffic mode to generate (default: mixed)",
    )
    parser.add_argument("--http-port", type=int, default=8001, help="HTTP target port (default: 8001)")
    parser.add_argument("--udp-port", type=int, default=9500, help="UDP target port (default: 9500)")
    parser.add_argument("--tcp-port", type=int, default=8001, help="TCP target port (default: 8001)")
    parser.add_argument("--rate", type=float, default=5.0, help="Packets or requests per second (default: 5.0)")
    parser.add_argument("--count", type=int, default=0, help="Total packets to send (0 = infinite)")
    args = parser.parse_args()

    if args.mode == "http":
        run_http_workload(args.target, args.http_port, args.count, args.rate)
    elif args.mode == "udp-stream":
        run_udp_stream_workload(args.target, args.udp_port, args.count, args.rate)
    elif args.mode == "tcp-burst":
        run_tcp_burst_workload(args.target, args.tcp_port, args.count, args.rate)
    elif args.mode == "mixed":
        run_mixed_workload(args.target, args.http_port, args.udp_port, args.tcp_port, args.rate)


if __name__ == "__main__":
    main()
