# Mini-Shark — Implementation Plan & Phase Roadmap

**Network Traffic Monitoring & Protocol Analysis Mini-Project (`23ECNP301`)**  
**Team 07** · Guide: Prof. Pooja Shettar · Branch: `main`

Mini-Shark passively observes real application traffic (HTTP, video, database, DNS, ping) across distributed network vantage points (Client, Router, Server), correlates observations via compact 64-bit BLAKE2b invariant fingerprints, isolates link-level transit delay $\Delta T = T_2 - T_1$ and packet drops, evaluates 4 deterministic diagnostic rules, and streams live telemetry to a React 3D topology dashboard.

---

## Engine Ownership

| Engine | Name | Owner | Core Deliverables |
| --- | --- | --- | --- |
| **E1** | **Packet Capture & Buffering Engine** | **M Janaki** | `AFPacketCapture` (Linux raw socket), Scapy/Npcap live capture, batching queue (50-pkt / 20ms), `run_probe.py`, `run_probe.sh`, `run_probe.bat` |
| **E2** | **Protocol Dissection & Invariant Fingerprinting** | **Chhavi Mishra** | L2–L7 dissection (Ethernet, IPv4, TCP, UDP, ICMP, DNS), 64-bit BLAKE2b invariant hashing, infrastructure filtering, Shannon query entropy $H(X)$ |
| **E3** | **Multi-Point Correlation Hub** | **Hrishikesh Patil** | TCP `:9000` ingestion hub, dual hash tables (`_table`, `_table_p2`), 500 ms min-heap timeout, multi-hop link drop localization (`link_1` vs `link_2`) |
| **E4** | **Diagnostics, Storage & User Interface** | **Vaibhav Kumar** | SQLite WAL persistence (`mini_shark.db`), 4 diagnostic rules (DNS exfil, Packet loss, Bufferbloat, App freeze), FastAPI REST/WS (`:8001`), React + Three.js UI (`:5173`) |

---

## Roadmap

Seven phases (details, acceptance criteria and risks per phase below):

| Phase | Scope | Tag (planned) / Milestone | Status | Verification Evidence |
| :---: | :--- | :---: | :---: | :--- |
| **1** | **Architecture, contracts and development foundation** | `v0.1-phase1` | ✅ Complete | Data contract (`docs/data_contract.md`), Pydantic models (`models.py`), abstract interfaces (`interfaces.py`). |
| **2** | **E1: distributed capture and buffering** | `v0.2-phase2` | ✅ Complete | Zero-copy `AF_PACKET` ring capture on Linux, Scapy/Npcap cross-platform capture, batching queue, zero-install launcher scripts. |
| **3** | **E2: protocol dissection and fingerprinting** | `v0.3-phase3` | ✅ Complete | L2–L7 dissector (`engine.py`), BLAKE2b-64 invariant key (stable across IP ID, TTL, checksums, TCP flags), DNS Shannon entropy $H > 4.2$. |
| **4** | **E3: telemetry ingestion and correlation** | `v0.4-phase4` | ✅ Complete | Persistent TCP `:9000` ingestion server, $O(1)$ dual hash tables, 500 ms min-heap deadline timer, intermediate router probe attribution. |
| **5** | **E4: diagnostic rules and persistence** | `v0.5-phase5` | ✅ Complete | SQLite WAL persistence (`mini_shark.db`), 4 anomaly rules verified in `test_anomalies.py` (Packet loss, Bufferbloat, App freeze, DNS exfil). |
| **6** | **API, WebSocket delivery and React dashboard** | `v0.6-phase6` | ✅ Complete | FastAPI REST endpoints (`/captures`, `/rules`, `/probes`), `/ws/live` streaming, React 18 + Tailwind CSS + Zustand + Three.js 3D packet flight UI. |
| **7** | **Integration, validation and final demonstration** | `v1.0` | 🔄 In Progress | Heterogeneous 4-laptop physical deployment (Arch Linux Client, Windows Client, Windows Router, Linux Server Hub) per [Deployment Guide](four_laptop_deployment_guide.md). |

---

## Phase Details & Acceptance Criteria

### Phase 1: Architecture, Contracts and Development Foundation
* **Scope:** Repository layout, coding standards, CI workflow, engine-to-engine data contracts.
* **Acceptance Criteria:**
  - Common models defined in `backend/models.py`.
  - Wire layout documented in `docs/data_contract.md` (24-byte telemetry record).
  - Abstract base classes for all four engines defined in `backend/interfaces.py`.
* **Status:** ✅ Complete (`v0.1-phase1`).

### Phase 2: E1 Distributed Capture and Buffering
* **Scope:** Live wire packet capture without dropping packets under burst conditions.
* **Acceptance Criteria:**
  - Linux `AF_PACKET` raw socket support for wire-speed capture.
  - Windows / macOS portable capture via Scapy + Npcap.
  - Ingress telemetry batching (up to 50 records or 20 ms timeout) to reduce TCP overhead.
  - Automatic probe ID negotiation and zero-config client launcher scripts (`run_probe.sh`, `run_probe.bat`).
* **Status:** ✅ Complete (`v0.2-phase2`).

### Phase 3: E2 Protocol Dissection and Fingerprinting
* **Scope:** Protocol parsing and invariant hash derivation for cross-probe packet matching.
* **Acceptance Criteria:**
  - Full dissection for Ethernet, IPv4, TCP, UDP, ICMP, and DNS.
  - 64-bit BLAKE2b invariant fingerprint insensitive to NAT-safe fields, TTL decrements, IP checksum updates, and hop-by-hop transforms.
  - Shannon entropy calculation $H(X) = -\sum p(x) \log_2 p(x)$ on DNS query names.
  - Infrastructure packet filtering (ignoring probe telemetry traffic on port 9000, 8001, 5173).
* **Status:** ✅ Complete (`v0.3-phase3`).

### Phase 4: E3 Telemetry Ingestion and Correlation
* **Scope:** High-throughput central ingestion of telemetry streams and $O(1)$ packet matching.
* **Acceptance Criteria:**
  - Asynchronous TCP server listening on port 9000 accepting multiple simultaneous probe streams.
  - Dual hash tables for matching packets arriving at either Client or Server first.
  - Min-heap deadline queue expiring unmatched packets after 500 ms.
  - Support for intermediate router probe (Probe 10) to accurately distinguish Link 1 (`Client ──✖──> Router`) from Link 2 (`Router ──✖──> Server`) drops.
* **Status:** ✅ Complete (`v0.4-phase4`).

### Phase 5: E4 Diagnostic Rules and Persistence
* **Scope:** Deterministic anomaly classification and database storage.
* **Acceptance Criteria:**
  - SQLite WAL database schema storing `correlation_records`, `diagnostic_alerts`, and `probes`.
  - Rule 1: `DNS_EXFIL_SUSPECTED` (Entropy $H > 4.2$ bits).
  - Rule 2: `PACKET_LOSS` (Loss rate $> 5\%$, localizing to Link 1 vs Link 2).
  - Rule 3: `BUFFERBLOAT` (Linear regression delay slope $> 0.5$ ms/packet).
  - Rule 4: `APP_FREEZE` (Average transit delay $> 150$ ms).
* **Status:** ✅ Complete (`v0.5-phase5`). Verified in `test_anomalies.py`.

### Phase 6: API, WebSocket Delivery and React Dashboard
* **Scope:** Full-stack visualization, real-time telemetry streaming, and interactive operator controls.
* **Acceptance Criteria:**
  - FastAPI backend serving REST endpoints and `/ws/live` WebSocket connection.
  - React + Tailwind CSS dashboard with dark/light themes and Wireshark-style display filter syntax (`tcp`, `http`, `drop`, `dns`).
  - Three.js 3D network topology canvas with animated packet flights, drop explosions, and dynamic node badge updates.
* **Status:** ✅ Complete (`v0.6-phase6`).

### Phase 7: Integration, Validation and Final Demonstration
* **Scope:** Bare-metal multi-computer deployment and live evaluation under real traffic and fault injection.
* **Acceptance Criteria:**
  - Demonstration across 4 physical laptops (Arch Linux Client, Windows Client, Windows Router, Linux Server Hub).
  - Live fault injection showing Link 1 drop vs Link 2 drop localization.
  - Comprehensive documentation: [4-Laptop Deployment Guide](four_laptop_deployment_guide.md) and [Physical Lab Setup Runbook](physical_lab_setup.md).
* **Status:** 🔄 In Progress (`v1.0`).

---

## Related Documentation

* [`docs/four_laptop_deployment_guide.md`](four_laptop_deployment_guide.md) — 4-Laptop physical hardware deployment guide.
* [`docs/physical_lab_setup.md`](physical_lab_setup.md) — 3-Laptop pilot and 8–50 PC institutional lab deployment runbook.
* [`docs/data_contract.md`](data_contract.md) — Engine-to-engine models and 24-byte wire specification.
* [`docs/api_routes.md`](api_routes.md) — REST endpoints and WebSocket protocol contract.
