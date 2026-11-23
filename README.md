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

**All-in-One Automated Run (Linux Server Hub):**
```bash
./start_server.sh
```
*(Runs Backend API, E3 Hub, React UI, and local Egress Probe 2 together in a single command, automatically opens firewall ports, detects LAN IP, prompts for Method A routing, and handles graceful Ctrl+C teardown. Run `./stop_server.sh` to stop if backgrounded).*

**Manual Run (Linux / macOS):**
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

### 2. Physical Lab Deployment & 4-Laptop Testbed

* **4-Laptop Physical Runbook:** See **[`docs/four_laptop_deployment_guide.md`](docs/four_laptop_deployment_guide.md)** for one-command scripts (`start_server.sh`, `start_router.bat`, `start_client_linux.sh`, `start_client_windows.bat`) with interactive terminal prompts and fault-injection control benches.
* **Staged Scale-Out (3 Laptops → 8–50 PCs):** See **[`docs/physical_lab_setup.md`](docs/physical_lab_setup.md)** for two-subnet hardware routing and lab switch scaling.

---

## Roadmap

Seven phases (details, acceptance criteria and risks per phase: [docs/implementation.md](docs/implementation.md)):

| Phase | Scope | Tag (planned) / Status |
| :---: | :--- | :--- |
| **1** | Architecture, contracts and development foundation | `v0.1-phase1` ✅ (offline foundation) |
| **2** | E1: distributed capture and buffering | `v0.2-phase2` ✅ (AF_PACKET / Scapy / Npcap) |
| **3** | E2: protocol dissection and fingerprinting | `v0.3-phase3` ✅ (BLAKE2b-64 invariant & entropy) |
| **4** | E3: telemetry ingestion and correlation | `v0.4-phase4` ✅ (:9000 hub, O(1) correlation & drops) |
| **5** | E4: diagnostic rules and persistence | `v0.5-phase5` ✅ (4 anomaly rules & SQLite WAL) |
| **6** | API, WebSocket delivery and React dashboard | `v0.6-phase6` ✅ (FastAPI :8001 & React 3D UI :5173) |
| **7** | Integration, validation and final demonstration | `v1.0` 🔄 In Progress ([4-laptop deployment guide](docs/four_laptop_deployment_guide.md)) |

---

## Documentation Index

| Document | Contents |
| --- | --- |
| [`docs/four_laptop_deployment_guide.md`](docs/four_laptop_deployment_guide.md) | **Step-by-step 4-laptop runbook:** Arch Linux Client + Windows Client + Windows Router + Linux Server Hub ("mrq") |
| [`docs/implementation.md`](docs/implementation.md) | Seven-phase engineering roadmap, acceptance criteria, engine ownership, and verification status |
| [`docs/physical_lab_setup.md`](docs/physical_lab_setup.md) | Stage 1 (3-Laptop pilot) + Stage 2 (8–50 PC lab), routing, firewall, and fault injection |
| [`docs/README.md`](docs/README.md) | Detailed technical overview, academic concepts, and performance notes |
| [`docs/data_contract.md`](docs/data_contract.md) | Engine-to-engine models, BLAKE2b v1 invariants, and 24-byte wire format |
| [`docs/api_routes.md`](docs/api_routes.md) | FastAPI REST endpoints, WebSocket `/ws/live`, and TCP `:9000` ingestion spec |
| [`docs/phase4-verification.md`](docs/phase4-verification.md) | Synthetic E3 benchmarks and verification results |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Team engine ownership, branch rules, and data-contract change checklist |
