# Mini-Shark — Network Traffic Monitoring, Protocol Analysis & Distributed Multi-Point Latency Tracing

[![CI](https://github.com/Janaki1711/Minyaa/actions/workflows/ci.yml/badge.svg)](https://github.com/Janaki1711/Minyaa/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/pytest-153%20passed-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](pyproject.toml)
[![Frontend](https://img.shields.io/badge/frontend-React%2019%20%2B%20Three.js-61DAFB.svg)](frontend/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Course Project:** Network Traffic Monitoring & Protocol Analysis Mini-Project (`23ECNP301`)
**Department:** Computer Science & Engineering (Artificial Intelligence), KLE Technological University
**Team 07** · Guide: **Prof. Pooja Shettar** · Academic Year: 2026–2027

---

## Academic Engine Register & Ownership

Following the verified course specification (`project_spec.txt`):

| Engine | Approved Engine Name | Student Owner | USN | Main Responsibility & Deliverables | Primary Code Directory |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **E1** | **Capture & Ingestion** | **M Janaki** | `01fe24bci067` | Live wire packet capture, interface sniffing, PCAP/PCAPNG ingestion, producer-consumer queue, and 50-pkt / 20ms batching buffers. | [`backend/e1_capture/`](backend/e1_capture/) |
| **E2** | **Protocol Analysis & Packet Dissection** | **Chhavi Mishra** | `01fe24bci066` | Layered L2–L7 protocol decoding, field byte-span mapping, 64-bit BLAKE2b invariant fingerprinting, and DNS Shannon entropy $H(X)$. | [`backend/e2_dissection/`](backend/e2_dissection/) |
| **E3** | **Filtering & Query / Correlation Hub** | **Hrishikesh Patil** | `01fe24bci043` | Wireshark AST display filter engine (Mode 1), and TCP `:9000` multi-point correlation hub with 500ms sliding min-heap & drop localization (Mode 2). | [`backend/e3_flows/`](backend/e3_flows/) |
| **E4** | **Statistics, Flow & Expert Analysis** | **Vaibhav Kumar** | `01fe24bci0...` | 5-tuple flow aggregation, SQLite WAL persistence, 4 deterministic incident rules, FastAPI REST/WebSocket (`:8001`), and React UI (`:5173`). | [`backend/e4_query/`](backend/e4_query/), [`frontend/`](frontend/) |

---

## Dual-Mode Architecture

Mini-Shark operates in two complementary modes to serve both academic laboratory evaluations and distributed multi-host deployments:

### Mode 1: Wireshark-Parity Packet Analyzer (Single-Laptop Mode)
Designed for immediate demonstration, code defense, and offline trace inspection without requiring external physical hardware:
* **Live Sniffing & PCAP Replay:** Captures live traffic using zero-dependency Linux `AF_PACKET` raw sockets or Windows `Scapy + Npcap`, or uploads `.pcap` / `.pcapng` trace files.
* **Deep Packet Inspection (DPI):** Fully decodes Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP/1.x, and TLS ClientHello.
* **Exact Byte Spans & Hex Dump:** Computes exact `(start_offset, length)` byte spans for every field and renders an interactive Hex Dump synchronized with the protocol tree.
* **Display Filter Engine:** Includes a full Lexer, recursive-descent AST parser, and SQL compiler supporting Wireshark expressions (e.g. `ip.src == 192.168.1.15 && tcp.port == 80`).
* **3-Pane Wireshark UI:** Interactive Web interface featuring Packet Table, Hierarchical Protocol Tree with invariant field highlights, and raw Hex Dump.

### Mode 2: Distributed Multi-Point Telemetry & Latency Tracing (Multi-Host Mode)
Designed for multi-hop physical testbeds (2 to 4 laptops, or multi-VM environments):
* **Path-Invariant Fingerprinting:** Computes 64-bit BLAKE2b digests from invariant headers (`ip.src`, `ip.dst`, `ip.proto`, `ip.id`, `tcp.seq`, `tcp.ack`, payload prefix) while stripping mutable fields (TTL, IP checksum, MACs).
* **Compact 24-Byte Telemetry (`!QQIBBH`):** Streams 24-byte records over TCP `:9000` after a 16-byte `MSHK` preamble.
* **MTU-Aligned Batching:** Buffers up to 50 records (`1,200 B` payload $\le 1500$ MTU) or flushes after `20 ms` with Nagle disabled (`TCP_NODELAY = 1`).
* **Drop Localization:** Classifies silent packet drops to **Link 1** (Client $\to$ Router) vs **Link 2** (Router $\to$ Server) using intermediate Router Probe 10.
* **3D WebGL Topology Observatory:** React 19 + Three.js canvas displaying real-time quadratic Bézier particle flights, shockwave drop rings, and live latency statistics.

```text
┌───────────────────────────────── Data Plane (In-Band Application Traffic) ────────────────────────┐
│                                                                                                    │
│   [Client 1 / Laptop 1] ────Link 1────▶ [Windows/Linux Router / Laptop 3] ────Link 2────▶ [Client 2 / Laptop 2]
│   (Probe 11 - Ingress)                     (Probe 10 - Transit L3)                          (Probe 2 - Egress)     │
│                                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
          │                                         │                                         │
          └───────────── Out-of-Band Telemetry (24-byte Records over TCP :9000) ──────────────┘
                                                    ▼
                                  [Central Observatory Hub / Laptop 4]
                                       FastAPI :8001 + E3 Hub :9000
                                         React + Three.js UI :5173
```

---

## Quick Start Guide

### 1. Single-Laptop Unified Launcher (Mode 1 & Local Mode 2)
The easiest way to run everything on one machine:
```bash
# Clone the repository
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa

# Create virtual environment and install dependencies
python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Linux / macOS:
source .venv/bin/activate
pip install -r requirements.txt

# Start Universal Launcher (FastAPI :8001 + E3 Hub :9000 + Dashboard)
python run_minishark.py
```
* **Frontend & Wireshark UI:** [http://localhost:8001/](http://localhost:8001/)
* **3D Distributed Observatory:** [http://localhost:8001/dashboard](http://localhost:8001/dashboard)
* **Interactive OpenAPI Docs:** [http://localhost:8001/docs](http://localhost:8001/docs)

### 2. Live Wi-Fi Sniffing Terminal Demo
Sniff live wire packets from your network interface and display extracted fields, BLAKE2b fingerprints, and Shannon entropy directly in the terminal:
```bash
# Windows (Run PowerShell as Administrator):
python live_demo.py --count 25

# Linux (Root / sudo):
sudo python3 live_demo.py --count 25
```

### 3. Distributed 4-Laptop Physical Deployment (Mode 2)
For physical laboratory testing across 4 laptops:
* **Laptop 4 (Central Server Hub — Linux):**
  ```bash
  ./start_server.sh
  ```
  *(Launches Backend `:8001`, E3 Hub `:9000`, Vite UI `:5173`, and local Egress Probe 2).*
* **Laptop 3 (Intermediate Router — Windows/Linux):**
  ```powershell
  # Windows (Admin PowerShell):
  .\start_router.bat
  ```
  *(Enables pure L3 forwarding, launches Transit Probe 10, and opens interactive NetEm fault injection).*
* **Laptop 1 (Client 1 — Arch Linux / Ubuntu):**
  ```bash
  ./start_client_linux.sh
  ```
  *(Starts Ingress Probe 11 and launches automated traffic benches).*
* **Laptop 2 (Client 2 — Windows):**
  ```powershell
  .\start_client_windows.bat
  ```
  *(Starts Egress Probe 2 and lightweight traffic receiver).*

*For the complete step-by-step physical lab runbook, see [`docs/four_laptop_deployment_guide.md`](docs/four_laptop_deployment_guide.md).*

---

## Bandwidth & Telemetry Efficiency

Mini-Shark does not mirror full packets across the network (unlike ERSPAN/GRE). Instead, it transmits lightweight metadata:
* **24-byte wire record (`ProbeTelemetry`, `!QQIBBH`):** `fingerprint` (8 B), `timestamp_ns` (8 B), `seq` (4 B), `probe_id` (1 B), `type_flags` (1 B), `captured_len` (2 B), preceded by a one-time 16-byte `MSHK` connection preamble.
* **MTU-aligned dual-trigger batching (`run_probe.py`):** Buffers up to **50 records** (`1,200 B` payload $\to 1,254$ B wire frame $\le 1,500$ B Ethernet MTU) **or** flushes partial batches after **`20 ms`** (well inside the `500 ms` correlation deadline).
* **Zero Nagle stalls:** `TCP_NODELAY = 1` prevents up to ~40 ms delayed-ACK buffering stalls on partial batches.
* **Anti-loop filter (`is_infra`):** Probes automatically exclude control traffic (`:9000`, `:5173`, `:8001`, `:22`, mDNS/SSDP/NTP/broadcasts).

---

## Repository Scripts & Utilities

| Script | Purpose | Operating System |
| :--- | :--- | :--- |
| [`run_minishark.py`](run_minishark.py) | Universal one-laptop launcher (Backend, E3 Hub, Dashboard). | Cross-platform |
| [`live_demo.py`](live_demo.py) | Terminal live Wi-Fi capture, dissection, and Shannon entropy demo. | Windows / Linux |
| [`run_probe.py`](run_probe.py) | Standalone probe CLI (supports `--role client`, `router`, `server`). | Linux (AF_PACKET) / Windows (Npcap) |
| [`run_probe.sh`](run_probe.sh) / [`.bat`](run_probe.bat) | Zero-install wrappers to launch edge probes. | Linux / Windows |
| [`start_server.sh`](start_server.sh) / [`stop_server.sh`](stop_server.sh) | All-in-one runner and teardown for the Central Server Hub. | Linux |
| [`start_router.sh`](start_router.sh) / [`.bat`](start_router.bat) / [`.ps1`](start_router.ps1) | Intermediate router runner with fault injection benches. | Linux / Windows |
| [`start_client_linux.sh`](start_client_linux.sh) | Client 1 runner with automated traffic generators. | Linux |
| [`start_client_windows.bat`](start_client_windows.bat) / [`.ps1`](start_client_windows.ps1) | Client 2 runner with traffic receiver services. | Windows |
| [`benchmark_e3.py`](benchmark_e3.py) | Synthetic correlation benchmark (10,000+ matches/sec verification). | Cross-platform |
| [`test_anomalies.py`](test_anomalies.py) | End-to-end integration test validating the 4 diagnostic rules. | Cross-platform |
| [`populate_demo_data.py`](populate_demo_data.py) | Seeds `mini_shark.db` with realistic multi-probe correlation records. | Cross-platform |
| [`query_demo.py`](query_demo.py) | CLI demo evaluating Wireshark display filters against SQLite. | Cross-platform |
| [`scripts/traffic_generator.py`](scripts/traffic_generator.py) | Workload generator (HTTP GET/POST, UDP stream, TCP burst, DNS). | Cross-platform |
| [`scripts/traffic_receiver.py`](scripts/traffic_receiver.py) | Lightweight HTTP/UDP traffic sink for destination nodes. | Cross-platform |
| [`scripts/setup_router.sh`](scripts/setup_router.sh) | Linux pure L3 forwarding and `tc netem` drop/delay setup. | Linux |

---

## Automated Incident Diagnostics (Engine E4)

Mini-Shark executes four deterministic diagnostic rules against in-flight correlation records and decoded packets:
1. **Packet Loss (`rule_packet_loss`):** Triggers when the unmatched drop rate exceeds 5%, indicating physical cable faults, interface saturation, or routing blackholes.
2. **Bufferbloat (`rule_bufferbloat`):** Triggers when transit delay $\Delta T$ exceeds 20 ms with high variance ($> 15$ ms jitter), diagnosing oversaturated router queues.
3. **Application Freeze (`rule_app_freeze`):** Detects transport connection stalls where packets flow normally but destination application processing halts.
4. **DNS Tunneling / Data Exfiltration (`rule_dns_exfil`):** Computes Shannon entropy on DNS query names:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Flags query strings where $H(X) > 4.2$ bits as suspected base64/hex-encoded data exfiltration tunnels.

---

## Comprehensive Test Suite

The test suite contains **153 unit and integration tests** covering all four engines, binary wire packing, filter AST parsing, and network protocols:
```bash
# Run the complete test suite
.\.venv\Scripts\pytest.exe -v

# Run with coverage report
.\.venv\Scripts\pytest.exe --cov=backend tests/
```

Test breakdown:
* `test_academic_cases.py`: Academic curriculum syllabus verification.
* `test_api.py`: FastAPI routes and OpenAPI schema validation.
* `test_batching.py`: 50-pkt / 20ms queue flush and timer behavior.
* `test_e1_capture.py` & `test_e1_live.py`: DPKT parser, raw socket acquisition, loopback filtering.
* `test_e2_dissection.py` & `test_e2_fingerprint.py`: Protocol decoders and BLAKE2b invariant verification.
* `test_e3_correlation.py`, `test_e3_flows.py`, `test_e3_ingestion.py`: Out-of-order matching, 500ms min-heap expiry, TCP protocol preambles.
* `test_e4_query.py`: Wireshark display filter AST parser and SQLite WAL repository.
* `test_errors.py` & `test_pipeline.py`: Exception handling and end-to-end pipeline execution.

---

## Documentation Index

| Document | Description |
| :--- | :--- |
| [`CODEBASE_ARCHITECTURE.md`](CODEBASE_ARCHITECTURE.md) | Comprehensive codebase architecture, file reference, and component map. |
| [`RESEARCH_AND_ARCHITECTURE.md`](RESEARCH_AND_ARCHITECTURE.md) | Single-laptop research blueprint, DPI specifications, and mathematical foundations. |
| [`docs/api_routes.md`](docs/api_routes.md) | Complete specification for REST, SSE, WebSocket, and raw TCP `:9000` interfaces. |
| [`docs/data_contract.md`](docs/data_contract.md) | Engine-to-engine data contracts, binary wire structs, and SQLite schema. |
| [`docs/system_architecture_diagram.md`](docs/system_architecture_diagram.md) | Detailed Mermaid system architecture and dual-plane network diagrams. |
| [`docs/four_laptop_deployment_guide.md`](docs/four_laptop_deployment_guide.md) | Exact physical deployment runbook for 4 heterogeneous laptops. |
| [`docs/physical_lab_setup.md`](docs/physical_lab_setup.md) | Two-stage lab scaling guide: 3-laptop pilot deployment to 8–50 PC networks. |
| [`docs/laptop2_setup_guide.md`](docs/laptop2_setup_guide.md) | Setup and configuration guide for Client 2 / Destination node. |
| [`docs/two_probe_deployment.md`](docs/two_probe_deployment.md) | Distributed implementation plan for 2-machine probe validation. |
| [`docs/vm_network_setup.md`](docs/vm_network_setup.md) | Bridged networking guide for VMware and VirtualBox virtual machines. |
| [`docs/implementation.md`](docs/implementation.md) | 7-phase implementation roadmap, acceptance criteria, and milestone history. |
| [`docs/phase4-verification.md`](docs/phase4-verification.md) | Empirical E3 benchmark results and performance verification. |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Team engine ownership, branch naming conventions, and contract change rules. |
| [`frontend/README.md`](frontend/README.md) | React 19 + Three.js frontend architecture, Zustand store, and 3D canvas guide. |
