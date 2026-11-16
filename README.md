# Mini-Shark — Distributed Multi-Point Network Telemetry & Latency Tracing

**Network Traffic Monitoring & Protocol Analysis Mini-Project (`23ECNP301`) · Team 07**  
Guide: Prof. Pooja Shettar · Branch: `main`

Mini-Shark is a passive, multi-point network observability system that captures live packets at the **Client**, optional **Intermediate Router**, and **Server** simultaneously, computes path-invariant **64-bit BLAKE2b fingerprints**, streams compact **24-byte telemetry batches** over TCP `:9000`, correlates packet flights inside a **500 ms window**, isolates silent packet drops to **`link_1`** (Client → Router) vs **`link_2`** (Router → Server), runs deterministic diagnostics, and visualizes traffic in a live **React + Three.js** dashboard.

---

## Topology at a Glance

```text
[Client PCs (Auto Probe ID)] ──Link 1──▶ [Linux Router (Probe 10, L3 No NAT)] ──Link 2──▶ [Server Hub (Probe 2)]
          │                                         │                                            │
          └────────────────────── TCP :9000 (24B Telemetry Batches, 50 pkts / 20ms) ─────────────┘
                                                    ▼
                     [E3 Correlation Hub (:9000)] ─▶ [E4 Diagnostics + SQLite + FastAPI (:8001)]
                                                    ▼  WebSocket /ws/live
                                      [React + Three.js Dashboard (:5173)]
```

---

## Core Architecture (4 Engines)

| Engine | Name | Owner | Responsibility | Code |
| --- | --- | --- | --- | --- |
| **E1** | Packet Capture & Buffering | M Janaki | Built-in `AF_PACKET` raw sockets on Linux; Scapy + Npcap on Windows | [`backend/e1_capture/`](backend/e1_capture/) |
| **E2** | Dissection & Fingerprinting | Chhavi Mishra | Layer decoding, strips hop-mutable fields (MAC, TTL, checksum), computes BLAKE2b-64 fingerprint & DNS Shannon entropy `H(X)` | [`backend/e2_dissection/`](backend/e2_dissection/) |
| **E3** | Multi-Point Correlation Hub | Hrishikesh Patil | O(1) dual hash tables + 500 ms binary min-heap (`heapq`), computes `ΔT = T2 - T1`, localizes `link_1` vs `link_2` drops | [`backend/e3_flows/correlator.py`](backend/e3_flows/correlator.py) |
| **E4** | Diagnostics, SQLite & UI | Vaibhav Kumar | 4 deterministic rules (`PACKET_LOSS`, `BUFFERBLOAT`, `APP_FREEZE`, `DNS_EXFIL`), `mini_shark.db` (SQLite WAL), FastAPI REST + `/ws/live` (`:8001`), React UI (`:5173`) | [`backend/e4_query/`](backend/e4_query/), [`frontend/`](frontend/) |

---

## Bandwidth & Telemetry Efficiency

Instead of full packet mirroring (like ERSPAN/GRE), Mini-Shark ships metadata only:

* **24-byte wire record (`ProbeTelemetry`, `!QQIBBH`):** `fingerprint` (8 B), `timestamp_ns` (8 B), `seq` (4 B), `probe_id` (1 B), `type_flags` (1 B), `captured_len` (2 B), after a one-time 16-byte `MSHK` preamble.
* **MTU-aligned dual-trigger batching (`run_probe.py`):** Buffers up to **50 records** (`1,200 B` payload → `1,254 B` wire frame `<= 1,500 B` Ethernet MTU) **or** flushes partial batches after **`20 ms`** (safely inside the `500 ms` correlation timeout).
* **Zero Nagle stalls:** `TCP_NODELAY = 1` prevents up to ~40 ms delayed-ACK buffering stalls on partial batches.
* **Anti-loop filter (`is_infra`):** Probes automatically skip control-plane and noisy traffic (`:9000`, `:5173`, `:22`, `/probes`, `/ws`, `:443` unless requested, mDNS/SSDP/NTP/multicast).

*(Caveat: Low overhead percentages apply to normal ~1,500 B frames; for pure 64 B TCP ACKs, a 24 B record has higher relative overhead.)*

---

## Quick Start

### 1. Central Server Hub (Backend `:8001` + Telemetry `:9000` + UI `:5173`)

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

**Start the React Dashboard (second terminal):**
```bash
cd frontend
npm install
# If viewing on http://localhost:5173 with a local backend, point VITE_API_HOST explicitly:
VITE_API_HOST=http://127.0.0.1:8001 npm run dev
```
> When opening the UI from another laptop via `http://<SERVER_IP>:5173`, `frontend/src/config.ts` automatically connects to `http://<SERVER_IP>:8001`.

**Start Egress Probe 2 on the Server:**
```bash
# Linux (uses stdlib AF_PACKET)
sudo python3 run_probe.py --server 127.0.0.1:9000 --role server

# Windows (requires Administrator shell + Npcap + pip install scapy)
python run_probe.py --server 127.0.0.1:9000 --role server
```

### 2. Deploy Across 3 Laptops First, Then Scale to 8–50 PCs

Follow the staged physical deployment guide in **[`docs/physical_lab_setup.md`](docs/physical_lab_setup.md)**:
* **Stage 1 (3-Laptop Pilot):** Server Hub Laptop (`Probe 2`) + Linux Router Laptop (`Probe 10`, pure L3 forwarding with `scripts/setup_router.sh`) + Client Laptop (`Auto Probe ID`).
* **Stage 2 (8 to 50 Physical PCs):** Attach multiple client PCs to the Router's Link 1 switch; run `./run_probe.sh --server <SERVER_IP>:9000` (Linux) or `run_probe.bat --server <SERVER_IP>:9000` (Windows) with zero manual probe ID collisions.

---

## Roadmap & Phase Status

| Phase | Scope | Milestone / Tag | Status |
| --- | --- | --- | --- |
| 1 | Architecture, contracts & offline foundation | `v0.1-phase1` | ✅ Implemented |
| 2 | E1: live probe capture, batching & portable runners | `v0.2-phase2` | ✅ Implemented |
| 3 | E2: L2–L7 dissection, BLAKE2b-64 & DNS entropy | `v0.3-phase3` | ✅ Implemented |
| 4 | E3: `:9000` telemetry hub, O(1) correlation & link drop isolation | `v0.4-phase4` | ✅ Implemented |
| 5 | E4: 4 deterministic diagnostic rules & SQLite WAL (`mini_shark.db`) | `v0.5-phase5` | ✅ Implemented |
| 6 | FastAPI REST + `/ws/live` (`:8001`) & React + Three.js UI (`:5173`) | `v0.6-phase6` | ✅ Implemented |
| 7 | Multi-PC physical lab validation & final demo | `v1.0` | 🔄 In Progress ([3-laptop → 8+ PC runbook](docs/physical_lab_setup.md)) |

---

## Documentation Index

| Document | Contents |
| --- | --- |
| [`docs/physical_lab_setup.md`](docs/physical_lab_setup.md) | **Start here for hardware labs:** Stage 1 (3-Laptop pilot) + Stage 2 (8–50 PC lab), routing, firewall, fault injection (`tc netem`), and traffic generation |
| [`docs/README.md`](docs/README.md) | Detailed technical overview, academic concepts, and performance notes |
| [`docs/data_contract.md`](docs/data_contract.md) | Engine-to-engine models, BLAKE2b v1 invariants, and 24-byte wire format |
| [`docs/api_routes.md`](docs/api_routes.md) | FastAPI REST endpoints, WebSocket `/ws/live`, and TCP `:9000` ingestion spec |
| [`docs/phase4-verification.md`](docs/phase4-verification.md) | Synthetic E3 benchmarks and verification results |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Team engine ownership, branch rules, and data-contract change checklist |
