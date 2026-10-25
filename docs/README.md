# Mini-Shark — A Distributed Multi-Point Latency & Packet Loss Tracing System

**Network Traffic Monitoring & Protocol Analysis Mini-Project (23ECNP301)**
**Team 07** · Guide: Prof. Pooja Shettar · Default branch: `master` · Latest tag: `v0.1-phase1`

Mini-Shark passively observes real application traffic (HTTP, video, database)
at **two probe locations** — a client-side *Probe 1* and a server/gateway-side
*Probe 2* — correlates the observations of each packet using a compact 64-bit
fingerprint, estimates one-way transit delay, detects packets that never
appear at the destination probe within a 500 ms timeout, classifies the
resulting diagnostic conditions, persists everything in SQLite, and presents
live and historical results through a React dashboard.

> **Status note.** The repository currently contains a **working offline
> PCAP/PCAPNG analysis pipeline** (the Phase-1 foundation and starter engines
> described below) with 47 passing unit tests. The distributed live-capture
> architecture described in this document is the **agreed target design**
> (per the final project presentation); most of its components are **planned,
> not yet implemented**. See [Current implementation status](#current-implementation-status)
> for exactly what works today.

## Problem statement and motivation

Network problems are usually diagnosed from a single vantage point, which is
not enough to answer the question *"where on the path did this packet slow
down or disappear?"* The final presentation identifies three failure modes of
the common alternatives:

| Approach | Why it fails to reveal transit problems |
| --- | --- |
| **Single-point capture (Wireshark on one host)** | Sees only packets that reach (or leave) the local network card. It cannot observe the same packet on both ends of the path, so it cannot isolate drops or delays on intermediate links. |
| **Synthetic ping measurements** | Routers may deprioritise or throttle ICMP probe packets, so ping latency does not reflect real user traffic (HTTP, video, database). The measurement itself can be misleading. |
| **Coarse SNMP-style polling (1–5 min intervals)** | Polling averages smear away millisecond-scale microbursts. Router bufferbloat stays invisible until packets are already being lost. |

A packet that leaves the client but never reaches the server is, from the
user's perspective, a failure — yet no single-host tool can prove *when* it
vanished or *how long* the surviving packets took to cross the network.

## Proposed solution and intended users

Mini-Shark takes **in-band passive observations at two points of the same
real traffic flow** and compares them:

1. **Probe 1** (client side) and **Probe 2** (server/gateway side) each run a
   capture engine (E1) and a dissection/fingerprinting engine (E2).
2. Each probe sends a **compact telemetry record per packet** (target: 24
   bytes, see [data_contract.md](data_contract.md)) to a **central diagnostic
   server** over a persistent TCP connection on **port 9000**.
3. The central server's **correlation hub (E3)** matches the observations of
   the same packet via its fingerprint, computes the estimated one-way transit
   delay `ΔT = T₂ − T₁`, and flags packets whose Probe-2 observation does not
   arrive within **500 ms**.
4. The **diagnostics, storage and UI engine (E4)** applies deterministic
   diagnostic rules, persists results in SQLite (`minishark.db`), and streams
   live metrics and incident cards to a **React dashboard** through FastAPI
   **WebSockets on port 8000**.

**Intended users:** network administrators (link drops, bufferbloat),
application/server teams (application freezes, server delay), and security
staff (possible DNS tunnelling / data exfiltration). The dashboard replaces
retrospective hex-dump guessing with evidence-backed diagnostic cards and
suggested next steps.

## Distributed architecture and end-to-end data flow

```
 Client host                         Network                        Server / gateway host
┌─────────────────────┐                                     ┌──────────────────────────┐
│ Probe 1             │                                     │ Probe 2                  │
│  E1 capture+buffer ─┼──► E2 dissect+64-bit fingerprint    │  E1 capture+buffer ──► E2 │
└─────────────────────┘                                     └──────────────────────────┘
        │ telemetry (TCP :9000, 24-byte records)                     │ telemetry (TCP :9000)
        ▼                                                            ▼
              ┌───────────────────────────────────────────┐
              │        Central diagnostic server          │
              │  E3 Multi-Point Correlation Hub           │
              │   · hash table (O(1) avg) matching        │
              │   · min-heap drop timer (O(log K))        │
              │   · ΔT = T₂ − T₁, 500 ms timeout         │
              │  E4 Diagnostics, Storage & UI             │
              │   · deterministic diagnostic rules        │
              │   · SQLite (minishark.db)                 │
              │   · FastAPI REST + WebSocket (HTTP :8000) │
              └───────────────────┬───────────────────────┘
                                  │ WebSocket push
                                  ▼
                     React dashboard (live latency graph,
                     packet-loss %, status, incident cards)
```

1. Real application traffic (HTTP, video, database) travels between a client
   and a server.
2. Probe 1 observes the traffic on the client/source side.
3. Probe 2 observes the corresponding traffic on the server side or an
   appropriate gateway.
4. Each probe's **E1** captures raw packets and enqueues them into a bounded
   ring buffer (10,000 slots) using a producer thread.
5. Each probe's **E2** decodes the protocol layers, extracts stable header
   fields, and generates an 8-byte (64-bit) fingerprint per packet.
6. Each probe transmits compact telemetry (fingerprint, probe ID, timestamp,
   minimal metadata) to the central server over **TCP port 9000**.
7. **E3** correlates the two observations of each packet, computes ΔT, and
   raises unmatched-packet events after their deadlines (T₁ + 500 ms) expire.
8. **E4** applies deterministic diagnostic rules and stores correlation
   records and alerts in SQLite.
9. FastAPI and WebSockets expose live and historical data on **port 8000**.
10. The React dashboard renders latency timelines, loss indications, network
    status, diagnostic findings, and recommended actions.

PCAP/PCAPNG analysis of the existing pipeline is **retained as an optional
offline testing, replay and debugging mode** — it is not equivalent to live
distributed observation and is documented as such.

## The four engines

| Engine | Name | Owner | Core responsibility |
| --- | --- | --- | --- |
| **E1** | Packet Capture & Buffering Engine | M Janaki | Live passive capture at each probe (raw-packet mechanism, producer thread, 10,000-slot bounded ring buffer); hands raw packets + metadata to E2 without letting downstream work block capture. |
| **E2** | Protocol Dissection & Invariant Fingerprinting Engine | Chhavi Mishra | Decodes Ethernet/IPv4/IPv6/TCP/UDP/ICMP/DNS, extracts fields that are stable across the path (skipping TTL, hop-rewritten MACs, recomputed checksums), produces the 64-bit BLAKE2b fingerprint, and computes DNS-query Shannon entropy as a diagnostic signal. |
| **E3** | Multi-Point Correlation Hub | Hrishikesh Patil | Ingests telemetry from both probes over TCP :9000, matches observations in expected O(1) average time via an in-memory hash table, computes ΔT = T₂ − T₁, schedules expirations on a min-heap (O(log K)), and emits matched/late/unmatched events to E4. |
| **E4** | Diagnostics, Storage & User Interface | Vaibhav Kumar | Evaluates deterministic diagnostic rules (packet loss, bufferbloat, application freeze, possible DNS exfiltration), persists probes/records/alerts in SQLite `minishark.db`, serves the REST API, pushes live updates over WebSockets (:8000), and backs the React dashboard. |

Engines interact only through the shared data contract
([data_contract.md](data_contract.md)), so each engine can be developed and
unit-tested in isolation, with cross-engine integration tests covering the
contract seams.

## Technology stack

| Component | Technology | State |
| --- | --- | --- |
| Packet capture & processing | Python 3.11+ (raw-packet capture mechanism per E1 plan; `dpkt` retained for offline PCAP/PCAPNG parsing) | Offline parsing implemented; live capture planned |
| Central backend | Python + FastAPI + uvicorn | HTTP API implemented (offline routes); live routes planned |
| Correlation structures | In-memory hash table + binary min-heap (`heapq`) | Planned |
| Telemetry transport | Raw TCP, **port 9000**, fixed-size records, big-endian | Planned |
| Persistence | SQLite (`minishark.db`) | SQLite implemented for offline analysis; distributed schema planned |
| Live updates | FastAPI WebSockets | Planned |
| Frontend | React | Planned (not started) |
| Dashboard-facing service | **Port 8000** | Dev server runs here today |
| Testing | pytest (`tests/unit/`), hand-built byte-level fixtures | 47 unit tests passing |
| Workflow | Git + GitHub, `ruff` + `black` via pre-commit, GitHub Actions CI | Configured (see CI note in [CONTRIBUTING.md](CONTRIBUTING.md)) |

No new dependencies are required for the fingerprint (Python's `hashlib`
provides BLAKE2b with an 8-byte digest). The live-capture mechanism for E1
(raw `AF_PACKET` sockets on Linux vs. a libpcap binding) is an open decision
recorded in [implementation.md](implementation.md).

## Academic concepts demonstrated

| Engine | Concepts |
| --- | --- |
| E1 | Operating systems: producer–consumer problem, thread synchronisation, mutex locks and condition variables, race-condition avoidance, bounded buffers and memory management, kernel-to-user-space packet capture |
| E2 | Computer networks: protocol layering and decapsulation (RFC 791 IPv4, RFC 793 TCP, RFC 1035 DNS), packet-header mutability (TTL decrement, checksum recalculation, MAC rewriting), hashing and fingerprinting, Claude Shannon's information theory, entropy calculation |
| E3 | Hash tables and collision handling, average-time O(1) lookup complexity, binary min-heaps and priority queues (O(log K)), sliding-window / time-based eviction, deadline-driven timeout processing |
| E4 | Deterministic rule-based (expert-system style) diagnosis, relational database design, primary/foreign keys, ACID transactions and data integrity, event-driven architecture, asynchronous I/O, WebSockets, real-time frontend updates |

## Repository structure

```
Mini_Shark/
├── backend/
│   ├── main.py           # FastAPI entrypoint (offline routes + GET /health)
│   ├── models.py         # shared dataclasses: Packet, Layer, DecodedPacket, Flow
│   ├── interfaces.py     # abstract EngineE1–EngineE4
│   ├── errors.py         # typed engine errors
│   ├── pipeline.py       # offline pipeline: E1 → E2 → E3 → E4 in one call
│   ├── e1_capture/       # implemented: PCAP/PCAPNG loading (offline mode)
│   ├── e2_dissection/    # implemented: dissector registry + protocol dissectors
│   ├── e3_flows/         # implemented: five-tuple flow grouping (legacy analytics)
│   ├── e4_query/         # implemented: SQLite storage + filter compiler
│   └── api/              # HTTP routes (thin: validate, call an engine, serialise)
├── tests/
│   ├── unit/             # 47 unit tests (+ helpers.py byte-level frame builders)
│   ├── data/             # controlled PCAP/PCAPNG fixtures (currently empty)
│   └── expected/         # expected-output placeholders (currently unused)
├── docs/                 # this README, implementation plan, data contract,
│                         # API design, contributing guide, final presentation
├── .github/workflows/    # CI: pre-commit (ruff, black) + pytest
├── pyproject.toml        # project metadata, ruff/black/pytest config
├── requirements.txt      # dpkt, fastapi, uvicorn, sqlalchemy, python-multipart
└── run.sh                # create venv, install deps, start the dev server
```

Planned additions (not yet present): probe runtime (E1/E2 on each probe), the
TCP telemetry ingestion service (E3), the correlation/diagnostic services and
extended SQLite schema (E4), and `frontend/` (React dashboard).

## Prerequisites and setup

**Prerequisites:** Python 3.11 or newer, Git. Live distributed operation will
additionally require two probe hosts with permission to capture packets
(administrator/root on the probe machine), and time-synchronised clocks
(NTP) — see [limitations](#current-implementation-status-and-limitations).

```bash
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
./run.sh          # creates .venv, installs requirements.txt, runs uvicorn --reload
```

`run.sh` targets Git Bash / WSL / Linux. On Windows PowerShell do the same
steps manually:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Verify the service:

```bash
curl http://127.0.0.1:8000/health     # → {"status":"ok"}
```

## Configuration

Deployment-sensitive values must be configuration, not scattered hard-coded
constants. The names below are **proposed** (only the database variable is
read by code today):

| Setting | Proposed variable | Default | Used by | State |
| --- | --- | --- | --- | --- |
| API / dashboard port | `MINISHARK_API_PORT` | `8000` | uvicorn, E4, dashboard | Proposed (uvicorn CLI today) |
| Telemetry ingestion host | `MINISHARK_TELEMETRY_HOST` | `0.0.0.0` | E3 TCP service | Proposed |
| Telemetry ingestion port | `MINISHARK_TELEMETRY_PORT` | `9000` | E3 TCP service, probes | Proposed |
| Telemetry record timeout | `MINISHARK_MATCH_TIMEOUT_MS` | `500` | E3 expiration | Proposed |
| Ring-buffer capacity | `MINISHARK_RING_SLOTS` | `10000` | E1 | Proposed |
| Probe identity | `MINISHARK_PROBE_ID` | `1` / `2` | E1/E2 | Proposed |
| Database path | `MINI_SHARK_DB` | `mini_shark.db` | E4 (SQLite) | **Implemented** (offline storage) |

> **Naming discrepancy (open):** the presentation specifies the database file
> `minishark.db`, while the current code default is `mini_shark.db` (overridable
> via `MINI_SHARK_DB`). Renaming requires a coordinated code + docs change; the
> decision is tracked in [implementation.md](implementation.md).

## Running the components

### Implemented today (offline analysis mode)

```bash
uvicorn backend.main:app --reload        # API on http://127.0.0.1:8000
curl -F "file=@capture.pcap" http://127.0.0.1:8000/captures   # analyze a capture
```

### Planned (live distributed mode) — design only, not yet implemented

```bash
# On the central server (once implemented):
uvicorn backend.main:app --port 8000     # REST + WebSocket for the dashboard
python -m backend.e3_correlation         # TCP telemetry ingestion on :9000

# On each probe host (once implemented):
python -m backend.probe --probe-id 1 --server <central-host>:9000
python -m backend.probe --probe-id 2 --server <central-host>:9000

# Dashboard (once implemented):
cd frontend && npm install && npm run dev
```

The exact launch commands are part of the Phase 2–6 plans in
[implementation.md](implementation.md) and will be finalised with the code.

## Running tests and quality checks

```bash
pytest                    # unit tests in tests/unit (47 currently)
ruff check .              # lint
black .                   # format
pre-commit run --all-files
```

CI (`.github/workflows/ci.yml`) runs pre-commit (ruff + black) and pytest.
Note: CI currently triggers on the branch name `main` while the repository's
default branch is `master`; this pre-existing mismatch is documented in
[CONTRIBUTING.md](CONTRIBUTING.md).

## API, ports and documentation

| Interface | Port | Protocol | State |
| --- | --- | --- | --- |
| Dashboard-facing REST API | 8000 | HTTP (FastAPI) | Offline-analysis routes implemented; live-metrics/diagnostics routes proposed |
| Live dashboard stream | 8000 | WebSocket (FastAPI) | Proposed |
| Probe telemetry ingestion | 9000 | Raw TCP, fixed 24-byte records | Proposed |

Full endpoint designs, payloads, error handling and WebSocket message types:
[api_routes.md](api_routes.md). Shared structures and the telemetry wire
format: [data_contract.md](data_contract.md).

| Document | Contents |
| --- | --- |
| [implementation.md](implementation.md) | Seven-phase plan for the distributed system: tasks, owners, tests, acceptance criteria, risks |
| [data_contract.md](data_contract.md) | Engine-to-engine structures and the 24-byte telemetry record layout |
| [api_routes.md](api_routes.md) | REST + WebSocket design; TCP telemetry ingestion; offline routes reference |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branch naming, Conventional Commits, contract-change and review rules |

## Current implementation status

| Area | State |
| --- | --- |
| Data contract — `backend/models.py` | **Implemented (offline models):** frozen dataclasses `Packet`, `Layer`, `DecodedPacket`, `Flow`. Distributed structures (`PacketFingerprint`, `ProbeTelemetry`, `CorrelationRecord`, `DiagnosticAlert`) are **proposed** in the data contract. |
| Engine interfaces — `backend/interfaces.py` | **Implemented** for the offline pipeline (`load_capture` → `dissect` → `group` → `store`/`query`). Live-mode interfaces (capture loop, telemetry stream, correlation callbacks) are **planned**. |
| E1 capture | **Partial:** offline PCAP/PCAPNG loading with strict validation. **Not implemented:** live capture, producer thread, ring buffer, capture-error/shutdown handling. |
| E2 dissection | **Partial:** Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP dissectors. **Not implemented:** invariant-field selection, 64-bit fingerprint, DNS entropy. |
| E3 correlation | **Not implemented.** Current `backend/e3_flows/` contains the legacy five-tuple flow grouper (supplementary analytics), not the correlation hub. No TCP ingestion, hash-table matching, or min-heap timer exists. |
| E4 diagnostics/storage/UI | **Partial:** SQLite persistence + parameterised filter language for offline analysis; REST routes work. **Not implemented:** diagnostic rule engine, distributed schema (`probes`, `diagnostic_alerts`), WebSocket streaming, React dashboard. |
| Telemetry (TCP :9000) | **Not implemented.** Record layout designed in the data contract. |
| Tests | **Implemented:** 47 unit tests passing (verified locally). Cross-engine integration tests for the distributed pipeline: **planned**. |
| Frontend | **Not started.** |
| Performance targets | **Not measured.** All figures below are design targets from the presentation. |

### Performance targets (design targets — not yet measured)

| Target | Source | Notes |
| --- | --- | --- |
| 10,000-slot pre-allocated ring buffer (≈ tens of MB bounded memory) | Presentation (E1) | Absorbs burst capture without unbounded growth; measure actual bytes/slot in Phase 2. |
| 24-byte telemetry record per packet | Presentation (E1/E2/E3) | Mandatory fields fit exactly 24 bytes with the proposed layout — see the trade-offs in [data_contract.md](data_contract.md). |
| < 1.5 % network overhead from telemetry | Presentation | Only holds for traffic with large average frames; for small packets (e.g. 64-byte ACKs) per-packet telemetry is a large relative overhead. Must be validated by measurement (Phase 7). |
| O(1) average-time hash-table matching; O(log K) heap updates | Presentation (E3) | Standard complexity of the chosen structures; in-application throughput still needs benchmarking. |
| 500 ms unmatched-packet timeout | Presentation (E3) | Configurable design default; appropriate value depends on path RTT and clock quality. |
| Dashboard "60 FPS" | Presentation (E4) | A UI rendering target (≈60 Hz refresh). It does **not** imply the backend produces 60 updates per second; the WebSocket layer should batch/throttle accordingly. |

## Current implementation status and limitations

Known limitations of the current system and of the proposed design:

- **Offline ≠ distributed.** The working pipeline analyses a captured file;
  it cannot observe a packet at two points in time, so it cannot measure
  one-way delay or prove loss on a link.
- **One-way delay needs synchronised clocks.** ΔT = T₂ − T₁ is only as
  accurate as the clock offset between the probes. NTP synchronisation,
  timestamp precision, negative/implausible delays, out-of-order telemetry,
  duplicates, and late-arriving records are engineering considerations
  addressed in [data_contract.md](data_contract.md).
- **Fingerprints are heuristic, not magic.** The 64-bit fingerprint is
  derived from selected header fields; stability across NAT, IP fragments,
  TCP retransmissions, stacks that zero the IPv4 ID, and non-TCP protocols
  must be validated before trusting matches (see the data contract).
- **A timeout is not proof of a specific drop point.** A 500 ms expiry proves
  that no matching observation was received in the window; with two probes it
  localises the problem to the path segment between them, not to an exact
  link or device.
- **DNS entropy is a signal, not a verdict.** H(X) > 4.2 flags *possible*
  tunnelling/exfiltration; it requires contextual evidence and can produce
  false positives (e.g. high-entropy legitimate subdomains).
- **Database file name** differs between the presentation (`minishark.db`) and
  the current code (`mini_shark.db`) — pending a team decision.
- **CI branch mismatch:** CI triggers on `main`; the default branch is
  `master`.

## Roadmap

Seven phases (details, acceptance criteria and risks per phase:
[implementation.md](implementation.md)):

| Phase | Scope | Tag (planned) |
| --- | --- | --- |
| 1 | Architecture, contracts and development foundation | `v0.1-phase1` ✅ (offline foundation) |
| 2 | E1: distributed capture and buffering | `v0.2-phase2` |
| 3 | E2: protocol dissection and fingerprinting | `v0.3-phase3` |
| 4 | E3: telemetry ingestion and correlation | `v0.4-phase4` |
| 5 | E4: diagnostic rules and persistence | `v0.5-phase5` |
| 6 | API, WebSocket delivery and React dashboard | `v0.6-phase6` |
| 7 | Integration, validation and final demonstration | `v1.0` |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for engine ownership, the shared-data
contract rules (including telemetry and fingerprint compatibility), branch
naming, Conventional Commits, and the pull-request checklist. In short:
branch off `master`, keep the contract changes explicit, keep CI green, get
one review.
