# Mini-Shark — A Distributed Multi-Point Latency & Packet Loss Tracing System

**Network Traffic Monitoring & Protocol Analysis Mini-Project (23ECNP301)**  
**Team 07** · Guide: Prof. Pooja Shettar · Branch: `main`

Mini-Shark passively observes real application traffic (HTTP, UDP, TCP, ICMP, DNS) across **multiple physical observation points** — Client probes (auto-assigned IDs), an optional intermediate **Linux Router (Probe 10)**, and a server/egress **Probe 2** — correlates packet observations via a compact **64-bit BLAKE2b fingerprint**, computes one-way transit delay `ΔT = T2 - T1`, localizes silent drops within a **500 ms window** to **`link_1`** (Client → Router) vs **`link_2`** (Router → Server), evaluates deterministic diagnostic rules, persists records in SQLite (`mini_shark.db`), and streams live telemetry to a **React + Three.js** dashboard.

> **Deployment guide:** For step-by-step instructions to validate first on **3 laptops** and then scale to **8–50 physical lab PCs**, see **[physical_lab_setup.md](physical_lab_setup.md)**.

---

## Problem Statement and Motivation

| Approach | Why it fails to reveal transit problems |
| --- | --- |
| **Single-point capture (Wireshark on one host)** | Sees only packets reaching or leaving a single NIC; cannot prove where in transit a packet disappeared or slowed down. |
| **Synthetic ping measurements** | Routers may deprioritize or rate-limit ICMP; synthetic probes do not reflect real HTTP/TCP/UDP application queues. |
| **Coarse SNMP polling (1–5 min intervals)** | Long polling windows average away millisecond-scale microbursts and router bufferbloat. |

---

## Architecture & End-to-End Data Flow

```text
Client PCs (Link 1 Subnet)                Intermediate Router               Central Server Hub
┌───────────────────────────┐            ┌──────────────────────┐         ┌──────────────────────────────┐
│ Client Probe(s)           │  Link 1    │ Linux Router         │ Link 2  │ Egress Probe 2 (--role server│
│ E1 capture -> E2 BLAKE2b  ├───────────▶│ Pure L3 (No NAT)     ├────────▶│ Captures server arrival (T2) │
│ Auto Probe ID from IP     │            │ Probe 10 (T_router)  │         └──────────────┬───────────────┘
└─────────────┬─────────────┘            └──────────┬───────────┘                        │
              │                                     │                                    ▼
              └────────── 24B Telemetry Batches (TCP :9000, TCP_NODELAY=1) ───▶ [E3 Correlation Hub :9000]
                          (Max 50 records / 1,200B OR 20ms flush)                        │
                                                                                         ▼
                                                         [E4 Diagnostics + SQLite WAL + FastAPI (:8001)]
                                                                                         │ WebSocket /ws/live
                                                                                         ▼
                                                                           [React + Three.js UI (:5173)]
```

### The Four Engines

| Engine | Name | Owner | Implemented Scope |
| --- | --- | --- | --- |
| **E1** | Packet Capture & Buffering | M Janaki | Built-in Linux `AF_PACKET` raw socket capture (`AFPacketCapture`, zero external deps) and Windows `Scapy + Npcap` capture (`LiveCapture`), plus offline PCAP/PCAPNG loading (`backend/e1_capture/`). |
| **E2** | Protocol Dissection & Fingerprinting | Chhavi Mishra | Decodes Ethernet/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP, strips hop-mutable fields (MACs, TTL, header checksums), hashes path-invariant fields into a 64-bit BLAKE2b fingerprint, and computes DNS query Shannon entropy `H(X)` (`backend/e2_dissection/`). |
| **E3** | Multi-Point Correlation Hub | Hrishikesh Patil | Async TCP ingestion on `:9000`, 16 B `MSHK` preamble handshake, O(1) dual hash-table matching (`_table` / `_table_p2`), 500 ms `heapq` expiration min-heap, `link_1` vs `link_2` drop localization via Probe 10 (`backend/e3_flows/correlator.py`). |
| **E4** | Diagnostics, Storage & UI | Vaibhav Kumar | Four deterministic rules (`PACKET_LOSS`, `BUFFERBLOAT`, `APP_FREEZE`, `DNS_EXFIL`), SQLite WAL persistence (`mini_shark.db`), FastAPI REST + `/ws/live` WebSocket on `:8001`, and React + Vite + Three.js dashboard on `:5173`. |

---

## Bandwidth, Batching & The 20 ms Flush Design

1. **24-byte `ProbeTelemetry` record (`!QQIBBH`):** `fingerprint` (8 B), `timestamp_ns` (8 B), `seq` (4 B), `probe_id` (1 B), `type_flags` (1 B), `captured_len` (2 B).
2. **MTU-aligned batching (`_BATCH_MAX_RECORDS = 50`):** 50 records = `1,200 B` payload (`1,254 B` total wire frame with 20 B TCP + 20 B IPv4 + 14 B Ethernet), fitting cleanly under the `1,500 B` Ethernet MTU without IP fragmentation while amortizing TCP/IP header and syscall overhead by 50× (verified in [`tests/unit/test_batching.py`](../tests/unit/test_batching.py)).
3. **Dual-trigger `20 ms` timer flush (`_BATCH_FLUSH_INTERVAL_S = 0.020`):** On low-rate flows, buffered records flush after `20 ms` instead of waiting for 50 packets—keeping telemetry delivery well inside E3's `500 ms` correlation deadline without affecting `ΔT = T2 - T1` (since `timestamp_ns` is recorded at NIC capture time).
4. **`TCP_NODELAY = 1`:** Disables Nagle's algorithm in `TelemetryClient` so partial `< 1,200 B` batches transmit immediately rather than waiting on up to ~40 ms delayed-ACK stalls.
5. **Anti-loop `is_infra` filtering:** Probes exclude `:9000` (telemetry), `:5173` (Vite), `:22` (SSH), HTTP `/probes` and `/ws`, external HTTPS `:443` (unless explicitly requested via `--filter`), and LAN multicast/broadcast chatter (`5353`, `5355`, `1900`, `137/138`, `123`).

---

## Technology Stack & Ports

| Component | Technology | Default Port / Artifact |
| --- | --- | --- |
| Live capture (Probes) | Python 3.10+ (`AF_PACKET` on Linux; `scapy` + Npcap on Windows) | `run_probe.py` / `run_probe.sh` / `run_probe.bat` |
| Telemetry transport | Raw TCP, `16 B` `MSHK` preamble + `24 B` records | **TCP `9000`** |
| Backend REST + WebSocket | FastAPI + Uvicorn | **HTTP / WS `8001`** |
| Persistence | SQLite (WAL mode) | `mini_shark.db` (override via `MINI_SHARK_DB`) |
| Frontend dashboard | React 19 + Vite + Tailwind + Zustand + Three.js | **HTTP `5173`** (`frontend/`) |
| Router lab harness | Linux `ip_forward=1` + `tc netem` | `scripts/setup_router.sh` |

---

## Repository Structure

```text
Minyaa/
├── README.md                  # Top-level overview & quick start
├── run_probe.py               # Live probe CLI (client, router, server roles + batching)
├── run_probe.sh / .bat        # Zero-install probe wrappers (Linux/macOS & Windows)
├── run_e3_server.py           # Standalone E3 TCP correlation hub CLI
├── run.sh                     # Creates .venv, installs requirements, launches uvicorn
├── test_anomalies.py          # Anomaly test suite (e.g. high-entropy DNS test)
├── scripts/
│   ├── setup_router.sh        # Pure L3 forwarding + Link 1 / Link 2 tc netem drop/delay injection
│   └── traffic_generator.py   # HTTP, UDP stream, TCP burst, and mixed workload generator
├── backend/
│   ├── main.py                # FastAPI (:8001) + E3 TCP (:9000) lifespan
│   ├── models.py              # Packet, ProbeTelemetry (24B), CorrelationRecord, DiagnosticAlert
│   ├── probe/client.py        # TelemetryClient (16B MSHK preamble, TCP_NODELAY=1, heartbeat)
│   ├── e1_capture/            # AFPacketCapture (Linux), LiveCapture (Win/Scapy), PCAP loader
│   ├── e2_dissection/         # ProtocolDissector, BLAKE2b-64 fingerprint, DNS entropy
│   ├── e3_flows/correlator.py # CorrelationHub (O(1) hash tables + 500ms min-heap + link attribution)
│   ├── e4_query/              # Deterministic rules, SQLite repository, REST query engine
│   └── api/                   # REST endpoints + /ws/live WebSocket manager
├── frontend/                  # React + Vite + Three.js dashboard (:5173)
├── tests/unit/                # Unit, batching, fingerprint, correlation, and E4 tests
└── docs/                      # Architecture, contracts, API routes, physical lab guide
```

---

## Setup & Deployment Guides

1. **First-time verification on 3 laptops (`Client -> Router -> Server`):** See **[Phase 1 in physical_lab_setup.md](physical_lab_setup.md#stage-1-3-laptop-pilot-deployment-prove-end-to-end-first)**.
2. **Scaling to 8–50 lab PCs:** See **[Phase 2 in physical_lab_setup.md](physical_lab_setup.md#stage-2-scaling-to-850-physical-lab-pcs)**.
3. **Clone URL & Prerequisites:**
   ```bash
   git clone https://github.com/Janaki1711/Minyaa.git
   cd Minyaa
   ```
   * **Central Server (`backend`):** Python 3.10+ and `pip install -r requirements.txt` (launches on `--host 0.0.0.0 --port 8001`).
   * **Frontend (`frontend`):** Node.js 18+ and `npm install` inside `frontend/`.
   * **Linux Probes:** Python 3 standard library only (`sudo ./run_probe.sh ...`).
   * **Windows Probes:** Python 3 + `pip install scapy` + [Npcap](https://npcap.com) (run Administrator terminal).

---

## Configuration Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MINISHARK_TELEMETRY_HOST` | `0.0.0.0` | E3 TCP bind address |
| `MINISHARK_TELEMETRY_PORT` | `9000` | E3 TCP bind port |
| `MINISHARK_MATCH_TIMEOUT_MS` | `500` | Unmatched correlation timeout (ms) |
| `MINI_SHARK_DB` | `mini_shark.db` | SQLite database file path |
| `VITE_API_HOST` | auto from `window.location.hostname` (fallback `http://10.108.157.2:8001`) | Backend HTTP/WS origin used by the React frontend |

---

## Honest Overhead & Measurement Caveats

* **Clock synchronization is mandatory for `ΔT = T2 - T1`:** Unsynchronized clocks trigger `CLOCK_SKEW_SUSPECT` when `delay_ns < 0` or `> 5s`. Sync probes via NTP/Chrony or compare relative trends/drops cleanly on LAN.
* **Telemetry `< 1.5%` overhead caveat:** `24 B` metadata per ~`1,500 B` application packet yields ~1.6% payload overhead when amortized in 50-record batches, whereas pure `64 B` TCP ACKs incur higher relative overhead (`24 B / 64 B = 37.5%`).
* **Symmetric no-NAT path:** Router forwarding must keep `NAT/MASQUERADE` disabled; rewriting source IP/port changes the BLAKE2b invariant key and breaks cross-probe matching.
* **DNS entropy signal:** `H(X) > 4.2` flags potential DNS tunneling/exfiltration as an indicator requiring context, not standalone proof.

---

## Roadmap & Phase Status

| Phase | Scope | Milestone / Tag | Status |
| --- | --- | --- | --- |
| 1 | Architecture, contracts, and offline foundation | `v0.1-phase1` | ✅ Implemented (`models.py`, `interfaces.py`, [data_contract.md](data_contract.md)) |
| 2 | E1: distributed capture, batching & zero-install runners | `v0.2-phase2` | ✅ Implemented (`AFPacketCapture`, Scapy/Npcap, 50-pkt / 20 ms batching, `run_probe.sh` / `.bat`) |
| 3 | E2: protocol dissection, BLAKE2b-64 & DNS entropy | `v0.3-phase3` | ✅ Implemented (L2–L7 dissection, invariant hash, `is_infra` filtering, `H(X)`) |
| 4 | E3: `:9000` telemetry hub, correlation & drop localization | `v0.4-phase4` | ✅ Implemented (O(1) dual tables, 500 ms min-heap, `link_1` / `link_2` localization) |
| 5 | E4: diagnostic rules and SQLite WAL persistence | `v0.5-phase5` | ✅ Implemented (4 rules verified in `test_anomalies.py`, `mini_shark.db`) |
| 6 | FastAPI REST/WebSocket (`:8001`) & React UI (`:5173`) | `v0.6-phase6` | ✅ Implemented (`/ws/live`, React + Tailwind + Zustand + Three.js frontend) |
| 7 | Physical lab validation & final demonstration | `v1.0` | 🔄 In Progress (synthetic tests pass locally; 3-laptop pilot → 8+ PC lab demo per [physical_lab_setup.md](physical_lab_setup.md)) |

---

## Related Documents

| Document | Contents |
| --- | --- |
| [physical_lab_setup.md](physical_lab_setup.md) | 3-Laptop Pilot + 8–50 PC physical lab implementation runbook |
| [data_contract.md](data_contract.md) | Engine-to-engine structures, BLAKE2b v1 spec, and 24-byte wire record |
| [api_routes.md](api_routes.md) | FastAPI REST + WebSocket contract and TCP `:9000` framing |
| [phase4-verification.md](phase4-verification.md) | Benchmarks and verification outcomes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Engine ownership, branch rules, and contract-change policy |
