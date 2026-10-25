# Mini-Shark — Distributed Network Traffic Monitoring & Protocol Analysis System

**KLE Technological University** · 5th Semester Computer Networks Mini-Project (23ECNP301)  
**Guide:** Prof. Pooja Shettar · **Team 07:** M Janaki, Chhavi Mishra, Hrishikesh Patil, Vaibhav Kumar  
**Default Branch:** `master` · **Engine Feature Branches:** `E1`, `E2`, `E3`, `E4`

---

## 1. Problem Statement and Motivation

Traditional network analysis tools suffer from severe visibility limitations in multi-hop networks:

| Conventional Approach | Inherent Limitation in Multi-Hop Diagnosis |
| :--- | :--- |
| **Single-Host Sniffing (Wireshark)** | Observes traffic only at a single network interface card (NIC). Cannot observe the packet at both ends of a transit path, making it impossible to localize packet drops or quantify intermediate link delays. |
| **Active Synthetic Probing (`ping` / `traceroute`)** | Routers deprioritize or rate-limit ICMP/UDP echo packets. Synthetic probe latency does not represent real application data (HTTP/TCP/DB). |
| **Coarse Polling (SNMP / NetFlow)** | 1- to 5-minute polling intervals average out microbursts, masking bufferbloat and transient queue starvation until severe packet loss has already occurred. |

**Mini-Shark** solves this by passively observing identical in-flight application packets across two distributed observation points (**Probe 1: Client** and **Probe 2: Gateway/Server**), computing microsecond-accurate one-way transit delays ($\Delta T = T_2 - T_1$), detecting packet drops via timeout eviction, and diagnosing root causes using strictly deterministic (non-ML) rules.

---

## 2. Distributed System Architecture

```
  CLIENT HOST (Probe 1)                                            SERVER / GATEWAY (Probe 2)
┌───────────────────────────────────────┐                        ┌───────────────────────────────────────┐
│ [E1: Capture Engine]                  │                        │ [E1: Capture Engine]                  │
│  • Promiscuous Raw Socket / Npcap     │                        │  • Promiscuous Raw Socket / Npcap     │
│  • 10,000-slot Ring Buffer (Lock-free)│                        │  • 10,000-slot Ring Buffer (Lock-free)│
│                                       │                        │                                       │
│ [E2: Dissection & Math Engine]        │                        │ [E2: Dissection & Math Engine]        │
│  • L2-L7 Protocol Header Decoder      │   Physical Network     │  • L2-L7 Protocol Header Decoder      │
│  • 64-bit Invariant Hasher (BLAKE2b)  │ ══════════════════════ │  • 64-bit Invariant Hasher (BLAKE2b)  │
│  • Shannon Entropy Anomaly Evaluator  │     (Transit Path)     │  • Shannon Entropy Anomaly Evaluator  │
│                                       │                        │                                       │
│  • TCP Telemetry Client (:9000)       │                        │  • TCP Telemetry Client (:9000)       │
└──────────────────┬────────────────────┘                        └──────────────────┬────────────────────┘
                   │                                                                │
                   │  24-byte Telemetry Stream: {probe_id, hash, timestamp, len}    │
                   │               (Out-of-Band TCP Stream on Port 9000)            │
                   └───────────────────────────────┬────────────────────────────────┘
                                                   │
                                                   ▼
+════════════════════════════════════════════════════════════════════════════════════════════════════════+
║                                   CENTRAL DIAGNOSTIC SERVER                                            ║
║                                                                                                        ║
║   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   ║
║   │ INGESTION GATEWAY (E3): Asynchronous Multi-Client TCP Socket Server (:9000)                    │   ║
║   └──────────────────────────────────────────────┬─────────────────────────────────────────────────┘   ║
║                                                  │                                                     ║
║                                                  ▼                                                     ║
║   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   ║
║   │ CORRELATION & FLOW TRACKING HUB (E3):                                                          │   ║
║   │ • Sliding-Window Hash Table: O(1) average lookup across distributed probe streams              │   ║
║   │ • Binary Min-Heap Priority Queue: O(log K) deadline-driven 500 ms drop timeout scheduler       │   ║
║   │ • One-Way Wire Delay Engine: ΔT = T2 - T1 (microsecond resolution)                            │   ║
║   │ • Bidirectional 5-Tuple Flow Aggregator (jitter, throughput, volume)                           │   ║
║   └──────────────────────────────────────────────┬─────────────────────────────────────────────────┘   ║
║                                                  │                                                     ║
║                                                  ▼                                                     ║
║   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   ║
║   │ DETERMINISTIC DIAGNOSTIC RULE ENGINE (E4):                                                     │   ║
║   │ • Rule 1: Confirms packet drop on intermediate link if Probe 2 fails to report within 500 ms   │   ║
║   │ • Rule 2: Flags Bufferbloat when transit delay spikes under high load without packet drop      │   ║
║   │ • Rule 3: Detects host application freeze when TCP Window Size = 0                             │   ║
║   │ • Rule 4: Flags covert data theft when DNS query Shannon Entropy H(X) > 4.2                    │   ║
║   └──────────────────────────────┬───────────────────────────────────────────────┬─────────────────┘   ║
║                                  │                                               │                     ║
║                                  ▼                                               ▼                     ║
║   ┌──────────────────────────────────────────────┐               ┌─────────────────────────────────┐   ║
║   │ SQLite Persistence Repository (minishark.db) │               │ FastAPI WebSocket Dispatcher    │   ║
║   │ (probes, telemetry, correlations, alerts)    │               │ (Port 8000, batched live push)  │   ║
║   └──────────────────────────────────────────────┘               └────────────────┬────────────────┘   ║
+═══════════════════════════════════════════════════════════════════════════════════╪════════════════════+
                                                                                    │
                                                                                    ▼
                                                                   ┌─────────────────────────────────┐
                                                                   │ REACT WEB DASHBOARD (:8000)     │
                                                                   │ • Real-Time Hop Delay Timeline  │
                                                                   │ • Link Drop Counter & Alarms    │
                                                                   │ • Diagnostic Alert Incident Cards│
                                                                   └─────────────────────────────────┘
```

---

## 3. What Needs to Be Done in Each Branch

To enable conflict-free parallel engineering across the team, the codebase is modularized into 4 specialized engine branches and the integration branch (`master`).

```
master  ────────────────────────────────────────── (Stable baseline, integration, CI)
   │
   ├── E1  (Owner: M Janaki)       ── Live Capture, Ring Buffer, Probe Telemetry Client
   ├── E2  (Owner: Chhavi Mishra)   ── Protocol Dissection, Invariant Hashing, Shannon Entropy
   ├── E3  (Owner: Hrishikesh Patil)── TCP Ingestion Hub, Sliding Window, Min-Heap Correlator
   └── E4  (Owner: Vaibhav Kumar)   ── Diagnostic Rules, SQLite Storage, WebSocket API & UI
```

---

### Branch `E1` — Packet Capture & Edge Buffering Engine
* **Branch Name:** `E1` (or `feat/e1-*`)
* **Assigned Engineer:** **M Janaki**
* **Target Directory:** `backend/e1_capture/`, `backend/probe/`, `tests/unit/test_e1_*.py`
* **Data Contracts:** Produces raw byte frames and microsecond capture timestamps $T$.

#### Key Deliverables & Tasks
1. **Live Raw Socket Interceptor (`backend/e1_capture/live.py`):**
   * Implement promiscuous mode socket capture:
     * Linux: Raw sockets with `AF_PACKET` and `ETH_P_ALL`.
     * Windows: Npcap / WinPcap API binding or raw socket fallback.
   * Intercept raw Ethernet frames directly from the designated network adapter.
   * Retain offline PCAP/PCAPNG replay mode in `backend/e1_capture/engine.py` for testing and regression verification.
2. **Bounded Circular Ring Buffer (`backend/e1_capture/ring_buffer.py`):**
   * Multi-threaded Producer-Consumer pattern with 10,000 pre-allocated frame slots.
   * Thread-safe synchronization using `threading.Lock` and `threading.Condition`.
   * Capture producer thread pushes raw frames without waiting for dissection; downstream consumer pulls frames for E2 processing.
   * Monotonic buffer saturation counter tracking dropped frames during microbursts.
3. **Out-of-Band Telemetry Client (`backend/probe/client.py`):**
   * Lightweight client maintaining a persistent TCP socket to the Central Server on **Port 9000**.
   * Sends probe registration handshake on connect (`probe_id`, interface name, local clock details).
   * Streams 24-byte binary telemetry records generated by E2.
   * Automatic reconnect logic with exponential backoff on network disconnect.
4. **Unit Tests & Acceptance Criteria:**
   * `tests/unit/test_e1_capture.py`: Validate header bounds (`captured_len <= wire_len`), corrupt capture handling (`CorruptCaptureError`).
   * `tests/unit/test_e1_ringbuffer.py`: High-concurrency producer-consumer stress testing, buffer wrap-around, and saturation drop counters.
   * **Target:** Bounded memory footprint (< 50 MB) and zero kernel drops during standard traffic bursts.

---

### Branch `E2` — Protocol Dissection & Invariant Fingerprinting Engine
* **Branch Name:** `E2` (or `feat/e2-*`)
* **Assigned Engineer:** **Chhavi Mishra**
* **Target Directory:** `backend/e2_dissection/`, `tests/unit/test_e2_*.py`
* **Data Contracts:** Consumes raw frames from E1; outputs `DecodedPacket` and 24-byte telemetry records defined in `docs/data_contract.md`.

#### Key Deliverables & Tasks
1. **Layer 2–Layer 7 Protocol Dissectors (`backend/e2_dissection/`):**
   * Parse Ethernet II, IEEE 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, and HTTP.
   * Populate dataclasses: `Packet`, `Layer`, `DecodedPacket` (defined in `backend/models.py`).
   * Implement robust containment for malformed/truncated packets without throwing unhandled exceptions.
2. **64-bit Invariant Packet Hasher (`backend/e2_dissection/fingerprint.py`):**
   * Implement deterministic 64-bit hash using Python standard library `hashlib.blake2b(digest_size=8)`.
   * **Invariant Header Field Selection:** Hash only fields that remain unchanged across transit hops:
     * IPv4: `Identification` (16 bits) + `Protocol` (8 bits) + `Source IP` (32 bits) + `Destination IP` (32 bits) + `TCP Sequence Number` (32 bits, if TCP) or UDP Payload Checksum / ICMP ID+Seq.
     * **Explicitly ignore mutable fields:** Exclude IP TTL / Hop Limit (decremented at every router), MAC addresses (rewritten at every L2 hop), and IP Header Checksum (recomputed on TTL decrement).
3. **Shannon Information Entropy Engine (`backend/e2_dissection/entropy.py`):**
   * Compute Shannon entropy over DNS query subdomains:
     $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   * Evaluate string randomness: If $H(X) > 4.2$, flag query as potential **Covert DNS Tunneling / Data Exfiltration**.
4. **24-Byte Binary Record Serializer (`backend/e2_dissection/serializer.py`):**
   * Pack telemetry records into strict 24-byte network byte order (`>B7sQQIH`):
     * `probe_id` (1 byte), `reserved` (7 bytes), `fingerprint` (8 bytes / 64 bits), `timestamp_us` (8 bytes / 64 bits), `wire_len` (4 bytes / 32 bits), `flags` (2 bytes).
5. **Unit Tests & Acceptance Criteria:**
   * `tests/unit/test_e2_dissection.py`: Protocol coverage for all supported protocols against byte fixtures.
   * `tests/unit/test_e2_fingerprint.py`: Verify that two packets with different TTLs and MAC addresses yield the **exact same 64-bit fingerprint**.
   * `tests/unit/test_e2_entropy.py`: Validate entropy calculation on English domain names vs. high-entropy base64/hex encoded DNS queries.

---

### Branch `E3` — Multi-Point Correlation Hub & Telemetry Gateway
* **Branch Name:** `E3` (or `feat/e3-*`)
* **Assigned Engineer:** **Hrishikesh Patil**
* **Target Directory:** `backend/e3_flows/`, `tests/unit/test_e3_*.py`
* **Data Contracts:** Ingests 24-byte records over TCP :9000; outputs correlated transit events and 5-tuple flow records.

#### Key Deliverables & Tasks
1. **Asynchronous TCP Ingestion Server (`backend/e3_flows/server.py`):**
   * High-throughput asynchronous TCP server listening on **Port 9000** using `asyncio`.
   * Accepts simultaneous incoming telemetry connections from Probe 1 and Probe 2.
   * Handles stream framing, partial chunks, heartbeats, and client reconnection.
2. **Sliding-Window $O(1)$ Hash Table Matcher (`backend/e3_flows/correlator.py`):**
   * Maintains in-memory hash map of active in-flight packet fingerprints.
   * Correlates Probe 1 and Probe 2 sightings of the same packet in average $O(1)$ time.
   * Computes wire transit delay: $\Delta T = T_2 - T_1$.
   * Filters out duplicate observations and validates timestamp sanity.
3. **$O(\log K)$ Min-Heap Priority Queue Eviction (`backend/e3_flows/timer.py`):**
   * Implements timeout scheduling using binary min-heap (`heapq`).
   * Entries are keyed by `(deadline = T1 + 500ms, fingerprint)`.
   * Packets not matched by Probe 2 within 500 ms are popped from the heap in $O(\log K)$ time and emitted as `PACKET_DROP` events.
4. **Bidirectional 5-Tuple Flow Aggregator (`backend/e3_flows/engine.py`):**
   * Groups matched packets into 5-tuple flows (`src_ip, dst_ip, src_port, dst_port, protocol`).
   * Tracks total packets, payload bytes, active duration, and network jitter (RFC 3550 standard).
5. **Unit Tests & Acceptance Criteria:**
   * `tests/unit/test_e3_correlation.py`: In-order matching, out-of-order arrival, duplicate fingerprint filtering, and negative delay mitigation.
   * `tests/unit/test_e3_timer.py`: Verify precise expiration of unmatched records at the 500 ms boundary.
   * `tests/unit/test_e3_server.py`: Concurrency test with synthetic probe clients streaming concurrent packets over TCP.

---

### Branch `E4` — Deterministic Diagnostics, Storage & User Interface
* **Branch Name:** `E4` (or `feat/e4-*`)
* **Assigned Engineer:** **Vaibhav Kumar**
* **Target Directory:** `backend/e4_query/`, `backend/api/`, `frontend/`, `tests/unit/test_e4_*.py`
* **Data Contracts:** Consumes correlated events from E3; persists to SQLite; serves REST/WebSocket on Port 8000.

#### Key Deliverables & Tasks
1. **Deterministic Diagnostic Rule Engine (`backend/e4_query/rules.py`):**
   * **Rule 1 (Packet Loss Localization):** Fires `ALERT_PACKET_LOSS` if Probe 1 reports a packet but Probe 2 times out after 500 ms.
   * **Rule 2 (Bufferbloat Detection):** Fires `ALERT_BUFFERBLOAT` when transit delay $\Delta T > 3 \times \overline{\Delta T_{\text{baseline}}}$ during high byte throughput without packet loss.
   * **Rule 3 (TCP Zero-Window Application Freeze):** Fires `ALERT_ZERO_WINDOW` when TCP `Window Size == 0`, diagnosing application-side socket buffer starvation.
   * **Rule 4 (DNS Data Exfiltration Alert):** Fires `ALERT_DNS_EXFILTRATION` when Shannon Entropy $H(X) > 4.2$ on DNS query names.
2. **SQLite Persistence Repository (`backend/e4_query/storage.py`):**
   * Database file: `minishark.db` (with WAL mode enabled for high-performance concurrent writes).
   * Tables: `probes`, `telemetry_records`, `correlations`, `flows`, `diagnostic_alerts`.
   * Safe migration support and query filtering language.
3. **FastAPI REST API & WebSocket Server (`backend/api/`, `backend/main.py`):**
   * REST endpoints on **Port 8000** for querying flows, packet timelines, and active alerts.
   * WebSocket channel (`/ws/live`) delivering batched real-time metrics and diagnostic alert cards at 60 FPS refresh rate.
4. **React Web Dashboard (`frontend/`):**
   * Real-time Transit Delay Timeline graph (displaying link latency spikes).
   * Visual multi-probe topology map (Client $\to$ Gateway $\to$ Server).
   * Interactive Diagnostic Incident Cards with symptom, root cause, evidence metrics, and recommended remediation.
5. **Unit Tests & Acceptance Criteria:**
   * `tests/unit/test_e4_rules.py`: Test all 4 diagnostic rules against synthetic edge cases (positive and negative assertions).
   * `tests/unit/test_e4_storage.py`: Schema initialization, persistence round-trips, and filter queries.
   * `tests/unit/test_e4_api.py`: FastAPI route response schema validation and WebSocket broadcast lifecycle.

---

### Branch `master` — Integration, Baseline & Releases
* **Branch Name:** `master` (Default Branch)
* **Team Ownership:** All Team Members
* **Responsibilities:**
  1. Maintain the working baseline where all 50+ unit tests pass.
  2. Merge feature PRs from `E1`, `E2`, `E3`, `E4` after review.
  3. Orchestrate end-to-end integration tests (`tests/integration/`) linking the complete probe-to-server pipeline.
  4. Tag development phases: `v0.1-phase1`, `v0.2-phase2`, `v0.3-phase3`, `v0.4-phase4`, `v0.5-phase5`, `v1.0`.

---

## 4. Academic Concepts Demonstrated

| Engine | Primary Academic Concepts |
| :--- | :--- |
| **E1** | **Operating Systems:** Producer-Consumer concurrency, thread synchronization, mutex locks, condition variables, ring buffers, bounded memory management, kernel-to-user raw packet capture. |
| **E2** | **Computer Networks & Information Theory:** Protocol layering and decapsulation (RFC 791, RFC 793, RFC 1035), packet header mutability (TTL decrement, MAC rewriting, checksum calculation), Claude Shannon's Information Entropy. |
| **E3** | **Data Structures & Algorithms:** $O(1)$ average hash table matching, binary min-heap priority queues ($O(\log K)$), sliding-window deadline eviction, RFC 3550 network jitter computation. |
| **E4** | **Software Engineering & Systems:** Deterministic expert systems, event-driven WebSocket communication, Write-Ahead Logging (WAL) database persistence, state-machine analysis. |

---

## 5. Technology Stack & Port Allocation

| Component | Technology | Default Port | Role |
| :--- | :--- | :--- | :--- |
| **Probe Telemetry Transport** | Raw TCP (Big-Endian binary) | **Port 9000** | Lightweight out-of-band streaming (< 1.5% overhead) |
| **Central Diagnostic Web Server** | Python + FastAPI + Uvicorn | **Port 8000** | REST API & WebSocket event delivery |
| **Persistence Layer** | SQLite (`minishark.db`) | Local Disk | WAL-mode structured diagnostic storage |
| **Frontend Dashboard** | React + TailwindCSS + Recharts | **Port 5173 / 8000** | Live telemetry visualization & alert cards |
| **Test Suite** | pytest | CLI | Unit and integration test verification |

---

## 6. Getting Started & Verification

### Prerequisites
- Python 3.10 or newer
- Windows: [Npcap](https://npcap.com/) (with "WinPcap API-compatible mode" enabled)
- Linux: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`

### Setup Environment
```powershell
# Clone the repository
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Run Existing Unit Tests
```powershell
.\.venv\Scripts\pytest.exe tests/ -v
```

### Launch Central Server (Development Mode)
```powershell
python -m backend.main
```
Health Check: `curl http://127.0.0.1:8000/health` $\to$ `{"status":"ok"}`

---

## 7. Roadmap & Milestone Tags

| Phase | Milestone Scope | Git Tag | Status |
| :---: | :--- | :---: | :---: |
| **Phase 1** | Foundation, Data Contracts, Test Fixtures, Offline Starter Pipeline | `v0.1-phase1` | **Completed** (50 tests passing) |
| **Phase 2** | E1: Distributed Live Capture, Ring Buffer, Probe Telemetry Client | `v0.2-phase2` | *In Progress (E1 Branch)* |
| **Phase 3** | E2: Protocol Dissection, Invariant Hasher, Shannon DNS Entropy | `v0.3-phase3` | *Planned (E2 Branch)* |
| **Phase 4** | E3: Async TCP Ingestion Server (:9000), Min-Heap Correlation Hub | `v0.4-phase4` | *Planned (E3 Branch)* |
| **Phase 5** | E4: Deterministic Diagnostic Rule Engine & SQLite Persistence | `v0.5-phase5` | *Planned (E4 Branch)* |
| **Phase 6** | E4: REST API, WebSocket Broadcaster, React Web Dashboard | `v0.6-phase6` | *Planned (E4 Branch)* |
| **Phase 7** | End-to-End Multi-Probe Integration, Physical Link Testing & Final Demo | `v1.0` | *Planned (Master Branch)* |

---

## 8. Git Workflow & Collaboration Guidelines

1. Always branch off the latest `master`.
2. Commit message format follows **Conventional Commits**:
   * `feat(e1): implement 10,000-slot bounded circular ring buffer`
   * `test(e2): add invariant hash cross-hop stability test`
   * `fix(e3): correct min-heap deadline eviction boundary`
   * `feat(e4): add rule 3 tcp zero window freeze detector`
3. Before pushing to your branch, ensure all checks pass:
   ```powershell
   pytest tests/ -v
   ruff check .
   black --check .
   ```
