# Mini-Shark — Technical Architecture & Implementation Guide

**Course Project:** Network Traffic Monitoring & Protocol Analysis (`23ECNP301`)
**Department:** Computer Science & Engineering (Artificial Intelligence), KLE Technological University
**Team 07** · Guide: **Prof. Pooja Shettar** · Branch: `main`

---

## 1. System Mission & Core Motivation

Standard network analysis approaches present fundamental limitations when diagnosing complex network anomalies:
1. **Single-Point Sniffing (Standard Wireshark on one host):** Observes traffic arriving at or departing from only a single network interface. It cannot determine where in transit a packet was delayed, dropped, or corrupted.
2. **Synthetic Active Probing (Ping / ICMP Traceroute):** Routers frequently rate-limit or prioritize ICMP differently from application traffic. Synthetic packets do not reflect true transport queues (TCP/HTTP/DNS).
3. **Coarse SNMP Polling (1–5 minute windows):** Long polling intervals average away millisecond-scale microbursts, bufferbloat spikes, and brief network outages.

**Mini-Shark solves these challenges by combining two capabilities:**
* **Passive In-Band Inspection:** Decodes real application packets down to Layer 7 with exact byte spans and Wireshark display filter evaluation.
* **Passive Multi-Point Correlation:** Observes identical packets across multiple network vantage points (Client Ingress $\to$ Intermediate Router $\to$ Server Egress), computes path-invariant 64-bit BLAKE2b fingerprints, calculates true wire transit latency $\Delta T = T_2 - T_1$, and isolates silent drops to Link 1 versus Link 2 in real time.

---

## 2. End-to-End System Architecture

```text
Client PCs (Link 1 Subnet)                Intermediate Router               Central Server Hub
┌───────────────────────────┐            ┌──────────────────────┐         ┌──────────────────────────────┐
│ Client Probe(s)           │  Link 1    │ Linux/Windows Router │ Link 2  │ Egress Probe 2 (--role server│
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

### The Four Engines & Ownership

| Engine | Name | Owner | USN | Implemented Scope | Primary Directory |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **E1** | **Packet Capture & Buffering** | **M Janaki** | `01fe24bci067` | Built-in Linux `AF_PACKET` raw socket capture (`AFPacketCapture`, zero dependencies) and Windows `Scapy + Npcap` capture (`LiveCapture`), plus offline PCAP/PCAPNG ingestion. | [`backend/e1_capture/`](../backend/e1_capture/) |
| **E2** | **Protocol Dissection & Fingerprinting** | **Chhavi Mishra** | `01fe24bci066` | Decodes Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS. Computes field byte-spans, path-invariant BLAKE2b-64 fingerprints, and DNS Shannon entropy $H(X)$. | [`backend/e2_dissection/`](../backend/e2_dissection/) |
| **E3** | **Filtering & Multi-Point Correlation Hub** | **Hrishikesh Patil** | `01fe24bci043` | Wireshark display filter AST compiler (Mode 1), and TCP `:9000` ingestion hub with $O(1)$ dual hash tables, 500 ms `heapq` deadline timer, and Link 1 vs Link 2 drop localization (Mode 2). | [`backend/e3_flows/`](../backend/e3_flows/) |
| **E4** | **Diagnostics, Storage & User Interface** | **Vaibhav Kumar** | `01fe24bci0...` | Four deterministic incident rules (`PACKET_LOSS`, `BUFFERBLOAT`, `APP_FREEZE`, `DNS_EXFIL`), SQLite WAL persistence (`mini_shark.db`), FastAPI REST + `/ws/live` on `:8001`, and React + Three.js UI. | [`backend/e4_query/`](../backend/e4_query/), [`frontend/`](../frontend/) |

---

## 3. Bandwidth, Batching & Wire Framing

1. **24-byte `ProbeTelemetry` record (`!QQIBBH`):** `fingerprint` (8 B), `timestamp_ns` (8 B), `seq` (4 B), `probe_id` (1 B), `type_flags` (1 B), `captured_len` (2 B).
2. **MTU-aligned batching (`_BATCH_MAX_RECORDS = 50`):** 50 records = `1,200 B` payload (`1,254 B` total wire frame with 20 B TCP + 20 B IPv4 + 14 B Ethernet), fitting cleanly under the standard `1,500 B` Ethernet MTU without IP fragmentation.
3. **Dual-trigger `20 ms` timer flush (`_BATCH_FLUSH_INTERVAL_S = 0.020`):** On low-rate flows, buffered records flush after `20 ms` instead of waiting for 50 packets—keeping telemetry delivery well inside E3's `500 ms` correlation deadline without affecting transit delay $\Delta T = T_2 - T_1$ (since timestamps are recorded at NIC capture time).
4. **`TCP_NODELAY = 1`:** Disables Nagle's algorithm in `TelemetryClient` so partial batches transmit immediately rather than waiting on delayed-ACK stalls.
5. **Anti-loop `is_infra` filtering:** Probes exclude `:9000` (telemetry), `:5173` (Vite), `:8001` (FastAPI), `:22` (SSH), and local multicast/broadcast chatter.

---

## 4. Technology Stack & Port Allocations

| Component | Technology | Default Port / Target |
| :--- | :--- | :--- |
| **Edge Probes** | Python 3.10+ (`AF_PACKET` on Linux; `scapy` + Npcap on Windows) | `run_probe.py` / `run_probe.sh` / `run_probe.bat` |
| **Telemetry Transport** | Raw TCP socket, `16 B` `MSHK` preamble + `24 B` wire records | **TCP `9000`** |
| **Central Backend API** | FastAPI + Uvicorn (REST, SSE `/captures/stream`, WebSocket `/ws/live`) | **HTTP / WS `8001`** |
| **Database Store** | SQLite in Write-Ahead Logging (`PRAGMA journal_mode = WAL`) | `mini_shark.db` |
| **Observatory Frontend** | React 19 + TypeScript + Vite + Tailwind + Zustand + Three.js | **HTTP `5173`** (`frontend/`) |
| **Router Harness** | Pure L3 IP forwarding (`ip_forward=1`) + `tc netem` / PowerShell NetEm | `scripts/setup_router.sh` / `start_router.ps1` |

---

## 5. Repository Structure

```text
Mini_Shark/
├── README.md                  # Unified system overview and quick start guide
├── CODEBASE_ARCHITECTURE.md   # Exhaustive codebase architecture and file reference
├── RESEARCH_AND_ARCHITECTURE.md # Research blueprint, DPI specs, and mathematical models
├── pyproject.toml             # Python build configuration and test configurations
├── requirements.txt           # Project dependencies
├── package.json               # Development script shortcuts
├── project_spec.txt           # Academic curriculum specifications
│
├── Root Runners & Demos:
│   ├── run_minishark.py       # Universal one-laptop launcher
│   ├── live_demo.py           # Live Wi-Fi sniffer and dissection terminal demo
│   ├── run_e3_server.py       # Standalone E3 TCP correlation hub CLI
│   ├── benchmark_e3.py        # High-throughput synthetic benchmark suite
│   ├── test_anomalies.py      # Diagnostic rules validation test
│   ├── populate_demo_data.py  # SQLite telemetry seed script
│   └── query_demo.py          # Display filter CLI query demo
│
├── Distributed Testbed Scripts:
│   ├── run_probe.py           # Live edge capture probe CLI
│   ├── run_probe.sh / .bat    # Zero-install probe wrappers
│   ├── start_server.sh        # Linux central server hub runner
│   ├── stop_server.sh         # Server teardown script
│   ├── start_router.sh / .bat / .ps1 # Router runner and fault injection
│   ├── start_client_linux.sh  # Linux client runner
│   └── start_client_windows.bat / .ps1 # Windows client runner
│
├── backend/                   # Core Python engines (E1–E4) and FastAPI service
├── frontend/                  # React + Three.js dashboard
├── tests/unit/                # 153 unit and integration tests
└── docs/                      # Comprehensive specifications and deployment guides
```

---

## 6. Complete Documentation Index

* [`docs/system_architecture_diagram.md`](system_architecture_diagram.md): Mermaid system architecture and dual-plane network diagrams.
* [`docs/api_routes.md`](api_routes.md): Complete specification of all REST, SSE, WebSocket, and raw TCP `:9000` interfaces.
* [`docs/data_contract.md`](data_contract.md): Shared data structures, 24-byte wire structs, and SQLite schema.
* [`docs/four_laptop_deployment_guide.md`](four_laptop_deployment_guide.md): 4-laptop physical testbed deployment runbook.
* [`docs/physical_lab_setup.md`](physical_lab_setup.md): Two-stage lab scaling guide: 3-laptop pilot deployment to 8–50 PC networks.
* [`docs/laptop2_setup_guide.md`](laptop2_setup_guide.md): Setup guide for Laptop 2 (Client 2 / Receiver).
* [`docs/two_probe_deployment.md`](two_probe_deployment.md): Two-machine probe setup and deployment plan.
* [`docs/vm_network_setup.md`](vm_network_setup.md): Bridged VM network configuration guide.
* [`docs/implementation.md`](implementation.md): 7-phase implementation roadmap and acceptance criteria.
* [`docs/phase4-verification.md`](phase4-verification.md): Empirical benchmark results and verification evidence.
* [`docs/CONTRIBUTING.md`](CONTRIBUTING.md): Team engine ownership, branch rules, and data contract guidelines.
