"""
Mini-Shark Probe Runner — E1 + E2 + telemetry sender.

Run this on each probe machine AFTER the E3 server is started.

    # Probe 1 (client machine)
    python run_probe.py --probe-id 1 --server 192.168.1.20:9000

    # Probe 2 (server/gateway machine)
    python run_probe.py --probe-id 2 --server 127.0.0.1:9000

    # Optional BPF filter (capture only specific traffic)
    python run_probe.py --probe-id 1 --server 192.168.1.20:9000 --filter "tcp or udp"

Requires:
    - Npcap installed
    - Run as Administrator
    - E3 server running on the target host:port
"""

import argparse
import socket
import struct
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from backend.e1_capture.live import LiveCapture, _pick_interface
from backend.e2_dissection.engine import ProtocolDissector
from backend.models import Packet

# Preamble constants (data_contract.md §4.2)
_PREAMBLE_MAGIC   = b'MSHK'
_PREAMBLE_VERSION = 1
_RECORD_SIZE      = 24

SEP  = "─" * 60
SEP2 = "═" * 60


def build_preamble(probe_id: int) -> bytes:
    """16-byte connection preamble sent once at connect time."""
    epoch = int(time.time())
    return struct.pack(
        '!4sBBHI4s',
        _PREAMBLE_MAGIC,      # 4 bytes: magic
        _PREAMBLE_VERSION,    # 1 byte:  preamble version
        _RECORD_SIZE,         # 1 byte:  record size (24)
        probe_id & 0xFFFF,    # 2 bytes: probe_id in reserved field
        epoch,                # 4 bytes: connect-time epoch
        b'\x00' * 4,          # 4 bytes: reserved
    )


def connect_to_e3(host: str, port: int, probe_id: int,
                  retries: int = 5) -> socket.socket:
    """Connect to E3 TCP server with retry logic."""
    for attempt in range(1, retries + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.settimeout(None)
            sock.sendall(build_preamble(probe_id))
            print(f'  [Probe {probe_id}] Connected to E3 at {host}:{port}')
            return sock
        except (ConnectionRefusedError, OSError) as exc:
            print(f'  [Probe {probe_id}] Attempt {attempt}/{retries} failed: {exc}')
            if attempt < retries:
                print(f'  [Probe {probe_id}] Retrying in 3 seconds...')
                time.sleep(3)
    print(f'  [Probe {probe_id}] Could not connect to E3 server. Is run_e3_server.py running?')
    sys.exit(1)


def run_probe(probe_id: int, host: str, port: int,
              iface: str | None, bpf_filter: str) -> None:
    """Main probe loop: capture → dissect → fingerprint → send."""

    dissector = ProtocolDissector()
    seq       = 0
    sent      = 0
    matched_interface = _pick_interface(iface)

    print(f'\n{SEP2}')
    print(f'  Mini-Shark  ·  Probe {probe_id}')
    print(SEP2)
    print(f'  Interface : {matched_interface}')
    print(f'  E3 Server : {host}:{port}')
    print(f'  BPF filter: {bpf_filter or "(none — capture all)"}')
    print(f'  Algorithm : BLAKE2b-64 (blake2b, digest_size=8)')
    print(f'{SEP}')

    sock = connect_to_e3(host, port, probe_id)

    print(f'  [Probe {probe_id}] Starting continuous live capture...')
    print(f'  [Probe {probe_id}] Press Ctrl+C to stop\n')

    try:
        from scapy.all import sniff, conf as scapy_conf

        while True:
            # Capture in 2-second bursts
            try:
                raw_packets = sniff(
                    iface=matched_interface,
                    count=100,
                    timeout=2,
                    filter=bpf_filter if bpf_filter else None,
                    store=True,
                )
            except Exception as exc:
                print(f'  [Probe {probe_id}] Capture error: {exc}')
                time.sleep(1)
                continue

            for sp in raw_packets:
                try:
                    raw = bytes(sp)
                    ts  = float(sp.time) if hasattr(sp, 'time') else time.time()
                except Exception:
                    continue

                pkt     = Packet(index=seq, timestamp=ts,
                                 length=len(raw), raw_bytes=raw)
                decoded = dissector.dissect_one(pkt)

                if decoded.fingerprint is None:
                    continue   # skip ARP / unfingerprint-able frames

                telemetry = dissector.make_telemetry(
                    decoded, pkt, probe_id=probe_id, seq=seq
                )
                if telemetry is None:
                    continue

                wire = telemetry.pack()
                try:
                    sock.sendall(wire)
                    sent += 1
                    seq  += 1

                    # Print every 10th packet
                    if sent % 10 == 1:
                        layers = ' > '.join(l.name for l in decoded.layers)
                        fp_str = f'0x{decoded.fingerprint.value:016X}'
                        dns_warn = ''
                        if decoded.dns_entropy and decoded.dns_entropy > 4.2:
                            dns_warn = f'  ⚠ DNS H={decoded.dns_entropy:.3f}'
                        print(f'  [P{probe_id}] #{seq:>6}  {layers:<35}  fp={fp_str}{dns_warn}')

                except (BrokenPipeError, OSError):
                    print(f'\n  [Probe {probe_id}] Lost connection to E3. Reconnecting...')
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = connect_to_e3(host, port, probe_id)

    except KeyboardInterrupt:
        print(f'\n{SEP}')
        print(f'  [Probe {probe_id}] Stopped.')
        print(f'  Packets sent : {sent}')
        print(f'{SEP2}')
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Mini-Shark Probe Runner (E1 + E2 + telemetry sender)'
    )
    parser.add_argument(
        '--probe-id', type=int, required=True, choices=[1, 2],
        help='Probe identity: 1 = client side, 2 = server/gateway side'
    )
    parser.add_argument(
        '--server', type=str, default='127.0.0.1:9000',
        help='E3 server address as host:port (default: 127.0.0.1:9000)'
    )
    parser.add_argument(
        '--iface', type=str, default=None,
        help='Network interface name (default: auto-detect Wi-Fi)'
    )
    parser.add_argument(
        '--filter', type=str, default='',
        help='BPF capture filter e.g. "tcp" or "port 53" (default: capture all)'
    )
    args = parser.parse_args()

    # Parse host:port
    parts = args.server.rsplit(':', 1)
    if len(parts) != 2:
        print('Error: --server must be in host:port format e.g. 192.168.1.20:9000')
        sys.exit(1)
    host, port_str = parts
    try:
        port = int(port_str)
    except ValueError:
        print(f'Error: invalid port {port_str!r}')
        sys.exit(1)

    run_probe(
        probe_id=args.probe_id,
        host=host,
        port=port,
        iface=args.iface,
        bpf_filter=args.filter,
    )


if __name__ == '__main__':
    main()
