# Implementation Plan — Network Traffic Analyzer and Protocol Analysis System

**Team 07** · Guide: Pooja Shettar · Based on the S1 Functional Requirements Engineering handbook (06 Oct 2026)

| Engine | Name | Owner |
| --- | --- | --- |
| E1 | Packet & Frame Processing Engine | Janki |
| E2 | Protocol Dissection Engine | Chhavi Mishra |
| E3 | Flow & Traffic Analysis Engine | Hrishikesh |
| E4 | Traffic Query & Reporting Engine | Vaibhav Kumar |

---

## 0. Assumptions and Suggested Stack

The handbook does not fix a technology stack, so this plan assumes the following. Change it if your guide has already approved something different.

| Concern | Choice | Reason |
| --- | --- | --- |
| Language (backend) | Python 3.11+ | Strong packet libraries, quick to prototype |
| Capture parsing | `dpkt` or `scapy` (PCAP + PCAPNG); `pytest` for tests | Avoids writing the file-format parser from scratch |
| Web backend | FastAPI | Typed request validation, auto API docs |
| Storage | SQLite (via SQLAlchemy or plain `sqlite3`) | Zero setup, satisfies the DBMS course requirement |
| Frontend | React + Vite, or plain HTML + JS | Packet table, protocol tree, flow view, stats charts |
| Tooling | Git, GitHub Actions (lint + tests), `ruff`, `black` | Keeps `main` always green |

### Proposed repository layout

```
traffic-analyzer/
├── backend/
│   ├── e1_capture/        # E1: PCAP/PCAPNG loading, packet records
│   ├── e2_dissection/     # E2: protocol identification, header parsing, tree
│   ├── e3_flows/          # E3: five-tuple flows, statistics
│   ├── e4_query/          # E4: storage, filter/query engine
│   ├── api/               # FastAPI routers (thin, call the engines)
│   ├── models.py          # Shared dataclasses: Packet, DecodedPacket, Flow
│   └── main.py
├── frontend/
├── tests/
│   ├── data/              # Controlled PCAPs + expected-output JSON
│   ├── e1/ e2/ e3/ e4/ integration/
├── docs/
├── .github/workflows/ci.yml
└── README.md
```

### Git workflow (applies to every phase)

- `main` is protected: it only receives merges through pull requests with passing CI and one teammate review.
- Branch naming: `feat/e3-flow-grouping`, `fix/e1-empty-capture`, `test/e2-dns-validation`.
- Commit messages follow Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`.
- Each commit should leave the test suite green. If a commit adds a feature, the tests for it go in the same commit or the one right after.
- Tag a release at the end of every phase: `v0.1-phase1`, `v0.2-phase2`, and so on. A tag is your rollback point.

### Shared data contract (agree on this in Phase 1)

Because four people write four engines, the interfaces between them are the biggest risk. Fix these early:

- `Packet` (output of E1): `index`, `timestamp`, `length`, `raw_bytes`
- `DecodedPacket` (output of E2): `packet_index`, `layers: list[Layer]`, each `Layer` having `name`, `fields`, `undecoded_bytes`
- `Flow` (output of E3): `flow_id`, `five_tuple`, `packet_indices`, `packet_count`, `byte_count`, `start_ts`, `end_ts`, `duration`
- Ungrouped packets (no valid five-tuple, e.g. ARP) go into an explicit "ungrouped" bucket, never dropped.

---

## Phase 1 — Foundation, Contracts and Test Data

**Goal:** a working repo, CI, shared data models and a library of controlled test captures, so all four engines can be built in parallel without blocking each other.

**Duration:** about 1 week

| Task | Owner |
| --- | --- |
| Repo, branch protection, CI pipeline (lint + pytest) | Hrishikesh |
| Shared models (`Packet`, `DecodedPacket`, `Flow`) and interface stubs | Hrishikesh + all review |
| Collect/generate controlled PCAPs: TCP, UDP, DNS, HTTP, ICMP, ARP, one PCAPNG, one corrupt, one empty, one 100 MB file | Janki |
| Expected-value files for the test captures (compared against Wireshark/tshark) | Chhavi |
| Draft SQLite schema and API route list | Vaibhav |

**Planned commits (8–10)**

1. `chore: initialize repository with README, .gitignore and folder structure`
2. `chore: add pyproject, ruff/black config and pre-commit hooks`
3. `ci: add GitHub Actions workflow running lint and pytest`
4. `feat(models): add Packet, DecodedPacket, Layer and Flow dataclasses`
5. `feat(interfaces): add engine interface stubs for E1–E4`
6. `test(data): add controlled PCAP/PCAPNG fixtures (valid, corrupt, empty, large)`
7. `test(data): add expected-output JSON generated from tshark for each fixture`
8. `docs: add data-contract and API route draft`
9. `docs: add CONTRIBUTING with branch and commit conventions`

**Exit criteria**
- CI runs green on an empty test suite and fails on a deliberate lint error.
- Every engine owner has read and agreed to the data contract.
- Fixtures include every case named in the handbook (valid, corrupt, empty, unsupported).

**Tag:** `v0.1-phase1`

---

## Phase 2 — Capture Ingestion and Protocol Dissection (E1 + E2)

**Goal:** load a capture and turn each packet into a decoded protocol tree.
**Requirements covered:** FR-01, FR-02, FR-03, NFR-03, NFR-06

**Duration:** about 2 weeks (E1 and E2 run in parallel; E2 consumes E1 output through the contract)

### E1 — Packet & Frame Processing (Janki)

**Planned commits (6–8)**

1. `feat(e1): load PCAP file and iterate packet records`
2. `feat(e1): add PCAPNG support`
3. `feat(e1): extract timestamp, length and raw bytes per packet`
4. `feat(e1): detect and reject corrupt or unsupported files with typed errors`
5. `feat(e1): handle empty capture and report zero packets`
6. `test(e1): compare packet count and fields against tshark expected output`
7. `perf(e1): stream packets instead of loading the whole file (large-file path)`

### E2 — Protocol Dissection (Chhavi)

**Planned commits (8–10)**

1. `feat(e2): dissector registry and Layer data structure`
2. `feat(e2): Ethernet header dissection`
3. `feat(e2): IPv4 and IPv6 dissection`
4. `feat(e2): TCP and UDP dissection`
5. `feat(e2): ICMP and ARP dissection`
6. `feat(e2): application protocols (DNS, HTTP) as supported set`
7. `feat(e2): build hierarchical protocol tree per packet`
8. `fix(e2): mark malformed or unsupported headers as undecoded and continue`
9. `test(e2): validate decoded fields against reference values for each protocol`

**Exit criteria**
- ≥99% extraction success on valid captures (E1 KPI).
- ≥95% correct decoding on supported validation packets (E2 KPI).
- Corrupt file produces a clear error and the process keeps running (NFR-03).
- A malformed packet never stops processing of the rest of the capture.

**Tag:** `v0.2-phase2`

---

## Phase 3 — Flow Correlation and Traffic Statistics (E3)

**Goal:** group packets into flows and compute statistics, deterministically.
**Requirements covered:** FR-04, FR-05, FR-06, NFR-07

**Duration:** about 2 weeks (can start in week 1 of Phase 2 using fixtures and stubbed E2 output)

> Note: FR-04 and FR-05 are worded identically in the handbook. Both are satisfied by the same five-tuple grouping, but consider rewording FR-04 (e.g. "identify protocol relationships") before Gate 1 so the traceability matrix stays honest.

**Planned commits (10–12)**

1. `feat(e3): define FlowKey (src IP, dst IP, src port, dst port, protocol)`
2. `feat(e3): group TCP packets into flows by five-tuple`
3. `feat(e3): group UDP packets into flows by five-tuple`
4. `feat(e3): treat both directions of a conversation as one flow (normalized key)`
5. `feat(e3): handle ICMP and non-port protocols with an applicable grouping rule`
6. `feat(e3): classify packets without a valid tuple (e.g. ARP) as ungrouped`
7. `feat(e3): compute per-flow packet count, byte count, start/end time and duration`
8. `feat(e3): compute per-protocol statistics (packets, bytes, share of traffic)`
9. `fix(e3): return partial statistics when timestamps are missing or a flow has one packet`
10. `test(e3): compare flow membership against controlled capture with known flows`
11. `test(e3): verify aggregates against independently calculated values (pandas/tshark)`
12. `test(e3): determinism test, same input run N times gives identical flows and counts`

**Reliability notes**
- Use an ordered dictionary or sort flows by first-packet index so output order is stable (NFR-07).
- Keep flow aggregation as a pure function of the packet list; this makes it easy to test.
- Avoid floating-point drift in duration: store timestamps as integer nanoseconds or `Decimal` if the capture supports it.

**Exit criteria**
- ≥99% grouping consistency on controlled captures.
- Ten repeated runs on the same capture give byte-identical JSON output.
- Statistics match independent calculations on every fixture.

**Tag:** `v0.3-phase3`

---

## Phase 4 — Storage and Query Engine (E4, backend half)

**Goal:** persist selected analysis results and let users filter them safely.
**Requirements covered:** FR-07, FR-08, NFR-04, NFR-05

**Duration:** about 2 weeks

**Planned commits (9–11)**

1. `feat(e4): create SQLite schema for captures, packets, protocol layers and flows`
2. `feat(e4): repository layer with insert for packets and flows (parameterized SQL only)`
3. `feat(e4): batch insert in a single transaction for large captures`
4. `feat(e4): retrieve stored packets and flows by capture ID`
5. `feat(e4): filter grammar (e.g. `ip.src == 10.0.0.1 && tcp.port == 443`) and parser`
6. `feat(e4): translate validated filters into safe SQL`
7. `fix(e4): reject malformed filters with a clear error, never crash the service (NFR-05)`
8. `fix(e4): roll back and report failure if storage fails, never claim persistence (UC-07)`
9. `test(e4): store-then-reload test comparing key fields and record counts`
10. `test(e4): positive and negative filter test cases`
11. `test(e4): fuzz the filter parser with random and malformed input`

**Reliability notes**
- Never build SQL by string concatenation; use parameters. This is also your SQL-injection defence.
- Index on capture ID, flow ID, protocol and the five-tuple columns.
- Store a hash of the source file so the same capture is not inserted twice by accident.

**Exit criteria**
- ≥99% of records inserted from a controlled capture come back with matching key fields (NFR-04).
- A fuzzed filter run of at least a few thousand inputs causes zero crashes.
- Empty results return an empty list, not an error (UC-08).

**Tag:** `v0.4-phase4`

---

## Phase 5 — API Layer and Web Interface (E4, presentation half + integration)

**Goal:** connect all four engines behind an API and show results in the browser.
**Requirements covered:** FR-09, FR-01 (upload path), NFR-01, NFR-02

**Duration:** about 2 weeks

**Planned commits (12–14)**

**Backend API**
1. `feat(api): POST /captures to upload and analyze a file`
2. `feat(api): run analysis as a background job with status endpoint (keeps UI responsive, NFR-01)`
3. `feat(api): GET packets (paginated), packet detail with raw bytes`
4. `feat(api): GET protocol tree for a packet`
5. `feat(api): GET flows and flow detail`
6. `feat(api): GET statistics (per flow and per protocol)`
7. `feat(api): query endpoint using the filter engine`
8. `feat(api): consistent error responses (400/404/422/500) with readable messages`

**Frontend**
9. `feat(ui): upload page with progress and error display`
10. `feat(ui): paginated packet list with hex/raw bytes panel`
11. `feat(ui): collapsible protocol tree view`
12. `feat(ui): flow table with drill-down to member packets`
13. `feat(ui): statistics view with charts`
14. `feat(ui): filter bar with inline validation errors and empty-state messages`

**Reliability notes**
- Paginate everything. Rendering 100k packets in the DOM is the fastest way to freeze the interface.
- Limit upload size and validate the file magic bytes server-side, not only the extension.
- Preserve UI state when the backend is unavailable and show a service-error banner (UC-09).

**Exit criteria**
- A user can go from upload to packet details, protocol tree, flows, statistics and filtering with no CLI use (NFR-02).
- A 100 MB capture returns a usable result within 30 s on the test machine (NFR-01).
- Uploading a corrupt file shows an error and the app stays usable.

**Tag:** `v0.5-phase5`

---

## Phase 6 — Integration Testing, Hardening, Documentation and Demo

**Goal:** prove every requirement with evidence, close gaps and prepare the final submission.
**Requirements covered:** all FR and NFR; fills the "Test Ref" column of the RTM

**Duration:** about 1–2 weeks

**Planned commits (8–10)**

1. `test(integration): end-to-end test from upload to query for each fixture capture`
2. `test(integration): automated acceptance tests mapped to FR-01 … FR-09 acceptance criteria`
3. `test(perf): 100 MB benchmark script, record timings in docs`
4. `test(robustness): corrupt, truncated, empty and unsupported file suite`
5. `fix: resolve defects found during integration testing` (one commit per defect, referencing the issue)
6. `perf: optimize hot paths found by profiling (only if NFR-01 is not met)`
7. `docs: update RTM with design and test references for every requirement`
8. `docs: README with install, run, test instructions and screenshots`
9. `docs: user guide and architecture overview`
10. `chore: release v1.0 with demo script and sample captures`

**Exit criteria**
- Every Mandatory requirement has a passing automated test, with the test name written in the RTM.
- All engine KPIs from the handbook are measured and recorded: ≥99% extraction, ≥95% decoding, ≥99% grouping consistency, ≥99% retrieval integrity.
- A fresh clone can be set up and run by following only the README.
- A rehearsed demo covers all nine use cases (UC-01 to UC-09), including at least two exception flows.

**Tag:** `v1.0`

---

## Summary Timeline

| Phase | Focus | Engines | Approx. commits | Tag |
| --- | --- | --- | --- | --- |
| 1 | Foundation, contracts, test data | All | 8–10 | `v0.1-phase1` |
| 2 | Ingestion and protocol dissection | E1, E2 | 15–18 | `v0.2-phase2` |
| 3 | Flows and statistics | E3 | 10–12 | `v0.3-phase3` |
| 4 | Storage and query | E4 | 9–11 | `v0.4-phase4` |
| 5 | API and web interface | E4 + integration | 12–14 | `v0.5-phase5` |
| 6 | Testing, hardening, documentation | All | 8–10 | `v1.0` |

**Total:** roughly 60–75 commits across the team, about 9–11 weeks if phases 2–4 overlap as suggested.

## Requirement Coverage Check

| Requirement | Phase | Requirement | Phase |
| --- | --- | --- | --- |
| FR-01 | 2, 5 | NFR-01 | 5, 6 |
| FR-02 | 2 | NFR-02 | 5 |
| FR-03 | 2 | NFR-03 | 2, 6 |
| FR-04 | 3 | NFR-04 | 4 |
| FR-05 | 3 | NFR-05 | 4 |
| FR-06 | 3 | NFR-06 | 2 |
| FR-07 | 4 | NFR-07 | 3 |
| FR-08 | 4 | | |
| FR-09 | 5 | | |

## Top Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Engine interfaces drift between owners | Integration breaks in Phase 5 | Freeze data contract in Phase 1; contract tests in CI |
| Large captures freeze the UI or API | Fails NFR-01 | Streaming reads, background jobs, pagination, early 100 MB benchmark |
| Malformed packets crash a dissector | Fails NFR-03 / NFR-06 | Per-packet try/except boundary; fuzz tests; mark undecoded and continue |
| Non-deterministic flow ordering | Fails NFR-07 | Stable sort keys; repeated-run test in CI |
| SQL injection or parser crash via filters | Fails NFR-05 | Parameterized queries; fuzz test; strict grammar |
| One teammate blocked waiting on another | Schedule slip | Fixtures and stubs from Phase 1 so each engine is testable alone |

## Housekeeping Items in the Handbook

These small inconsistencies are worth fixing before Gate 1:

1. FR-04 and FR-05 have identical wording.
2. In the Engine 03 sheet, the owner SRN is listed as 01FE24BCI074, which is Vaibhav's; Hrishikesh's SRN elsewhere is 01FE24BCI043.
3. The student table headers read "SRN | Student Name" but the columns contain name then SRN.
4. The Engine 03 and 04 "What This Engine Does NOT Own" cells are placeholder text; the Engine Decomposition Rule asks for explicit out-of-scope lists.
5. The summary table lists the owner as "Hrishikesh" for E3 but the use-case diagram section is still empty.