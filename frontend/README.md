# Mini-Shark

Educational dual-probe network observatory for **KLE Technological University · Team 07 · CSE-AI · 23ECNP301**.

Unlike a single-interface sniffer, Mini-Shark correlates **ingress (VMnet2)** and **egress (VMnet3)** captures with a BLAKE2b 64-bit invariant hash, measures true wire transit delay **ΔT = T2 − T1**, and flags silent drops when the egress probe misses a packet within 500 ms.

## Run

```bash
npm install
npm run dev
```

Then open the printed local URL (typically `http://localhost:5173`).

## What to try

1. **Start Live Capture** — mock ~10 pps dual-probe stream.
2. Click a cyan particle in the 3D topology to freeze it and inspect the Wireshark-style panes.
3. **Inject 5% Drop Rate** — particles die mid-cable with a silent-drop badge.
4. **Inject 60ms Delay Spike** — slower amber packets and high-latency rows.
5. **Run DNS Tunneling Test** — burst of long-QNAME DNS queries.
6. Filter bar understands Wireshark-like atoms: `tcp`, `dns`, `ip.addr == 192.168.10.11 && tcp.port == 80`.
