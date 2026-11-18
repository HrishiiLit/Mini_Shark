#!/usr/bin/env python3
"""Mini-Shark Multi-Protocol Traffic Receiver.

Runs on Destination Nodes (e.g., Client 2 / Laptop 2) to receive and acknowledge:
  1. HTTP GET/POST queries on port 8000 (and 8001)
  2. UDP media/audio streams on port 9500
  3. Displays live packet arrival receipts directly in the console with counters.

Usage:
  python scripts/traffic_receiver.py --http-port 8000 --udp-port 9500
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

CLR_RESET = "\033[0m"
CLR_GREEN = "\033[0;32m"
CLR_CYAN = "\033[0;36m"
CLR_YELLOW = "\033[1;33m"
CLR_MAGENTA = "\033[0;35m"

http_count = 0
udp_count = 0
stats_lock = threading.Lock()


class MiniSharkHTTPHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests from traffic generators and sends 200 OK responses."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default werkzeug/BaseHTTPRequestHandler stderr logging."""
        pass

    def do_GET(self) -> None:
        global http_count
        with stats_lock:
            http_count += 1
            cur_count = http_count

        client_ip = self.client_address[0]
        now_str = time.strftime("%H:%M:%S")
        print(
            f"[{now_str}] {CLR_GREEN}[HTTP GET #{cur_count}]{CLR_RESET} "
            f"from {CLR_CYAN}{client_ip}{CLR_RESET} -> path: {self.path} (200 OK)",
            flush=True,
        )

        resp_data = json.dumps({
            "status": "ok",
            "receiver": "Mini-Shark Destination (Probe 2)",
            "packet_count": cur_count,
            "timestamp": time.time(),
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(resp_data)

    def do_POST(self) -> None:
        global http_count
        with stats_lock:
            http_count += 1
            cur_count = http_count

        client_ip = self.client_address[0]
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b""
        now_str = time.strftime("%H:%M:%S")

        print(
            f"[{now_str}] {CLR_GREEN}[HTTP POST #{cur_count}]{CLR_RESET} "
            f"from {CLR_CYAN}{client_ip}{CLR_RESET} -> len: {len(post_data)}B (200 OK)",
            flush=True,
        )

        resp_data = json.dumps({
            "status": "ok",
            "receiver": "Mini-Shark Destination (Probe 2)",
            "packet_count": cur_count,
            "received_bytes": len(post_data),
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_data)))
        self.end_headers()
        self.wfile.write(resp_data)


def run_http_server(bind_ip: str, port: int) -> None:
    """Run persistent HTTP receiver."""
    try:
        server = HTTPServer((bind_ip, port), MiniSharkHTTPHandler)
        print(f"  [✓] HTTP Service active on {bind_ip}:{port}", flush=True)
        server.serve_forever()
    except Exception as exc:
        print(f"  [!] HTTP Server error on {bind_ip}:{port}: {exc}", flush=True)


def run_udp_server(bind_ip: str, port: int) -> None:
    """Run persistent UDP stream receiver."""
    global udp_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((bind_ip, port))
        print(f"  [✓] UDP Service active on {bind_ip}:{port} (listening for streams)", flush=True)
        while True:
            data, addr = sock.recvfrom(2048)
            with stats_lock:
                udp_count += 1
                cur_count = udp_count

            now_str = time.strftime("%H:%M:%S")
            seq_str = ""
            if len(data) >= 16 and data[12:16] == b"STRM":
                seq, ts_ns = struct.unpack("!IQ", data[:12])
                seq_str = f" seq={seq}"

            if cur_count % 5 == 1 or cur_count <= 10:
                print(
                    f"[{now_str}] {CLR_MAGENTA}[UDP Stream #{cur_count}]{CLR_RESET} "
                    f"from {CLR_CYAN}{addr[0]}:{addr[1]}{CLR_RESET}{seq_str} ({len(data)}B)",
                    flush=True,
                )
    except Exception as exc:
        print(f"  [!] UDP Server error on {bind_ip}:{port}: {exc}", flush=True)
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini-Shark Destination Traffic Receiver (HTTP + UDP)",
    )
    parser.add_argument("--bind", type=str, default="0.0.0.0", help="Bind IP address (default: 0.0.0.0)")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP listening port (default: 8000)")
    parser.add_argument("--udp-port", type=int, default=9500, help="UDP listening port (default: 9500)")
    args = parser.parse_args()

    print("\n" + "═" * 65, flush=True)
    print("   MINI-SHARK MULTI-PROTOCOL DESTINATION TRAFFIC RECEIVER", flush=True)
    print("═" * 65, flush=True)
    print(f"  Bind Address : {args.bind}", flush=True)
    print(f"  HTTP Port    : {args.http_port}", flush=True)
    print(f"  UDP Port     : {args.udp_port}", flush=True)
    print("  Logs packets received from Client 1 in real-time.", flush=True)
    print("═" * 65 + "\n", flush=True)

    t_http = threading.Thread(target=run_http_server, args=(args.bind, args.http_port), daemon=True)
    t_udp = threading.Thread(target=run_udp_server, args=(args.bind, args.udp_port), daemon=True)

    t_http.start()
    t_udp.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping traffic receiver.", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    main()
