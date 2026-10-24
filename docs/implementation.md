# Implementation Plan — Distributed Multi-Point Latency & Packet Loss Tracing System

**Team 07** · Guide: Prof. Pooja Shettar · Mini-Project 23ECNP301

This plan replaces the earlier single-host PCAP-analysis roadmap. It tracks the
architecture in the final project presentation: two in-band probes, compact
telemetry over TCP, central correlation, deterministic diagnostics, and a live
dashboard. The offline PCAP/PCAPNG pipeline that already exists in the
repository is **retained as a testing/replay mode** and is not redesigned
here.

> **Evidence convention.** Sections labelled *planned* describe work that has
> **not** been performed. "Completion evidence" entries are empty until real
> artifacts (commits, test runs, benchmarks) exist; nothing in this document
> asserts completed work beyond Phase 1's offline foundation, which is
> verifiable in the repository (47 passing unit tests, tag `v0.1-phase1`).

## Engine ownership

| Engine | Name | Owner |
| --- | --- | --- |
| E1 | Packet Capture & Buffering Engine | M Janaki |
| E2 | Protocol Dissection & Invariant Fingerprinting Engine | Chhavi Mishra |
| E3 | Multi-Point Correlation Hub | Hrishikesh Patil |
| E4 | Diagnostics, Storage & User Interface | Vaibhav Kumar |

## Assumptions and stack

The presentation implies the following stack. Change it only with team
agreement and a note in this file.

| Concern | Choice | Reason / notes |
| --- | --- | --- |
| Language | Python 3.11+ | Existing codebase; strong stdlib (`hashlib` BLAKE2b, `heapq`, `socket`, `sqlite3`) |
| Live capture (E1) | **Open decision:** raw `AF_PACKET` sockets (Linux, root) vs. a libpcap binding | The presentation proposes raw sockets with `ioctl`/`recvfrom`. `AF_PACKET` is Linux-only and needs privileges; a libpcap binding is more portable. Decide in Phase 2 after a portability check. `dpkt` stays for offline PCAP/PCAPNG replay. |
| Fingerprint (E2) | `hashlib.blake2b(digest_size=8)` | Stdlib, matches the presentation's 8-byte BLAKE2b design; no new dependency |
| Telemetry transport | Raw TCP, port 9000, fixed-size records, big-endian | Persistent connection per probe; framing defined in `data_contract.md` |
| Correlation (E3) | `dict` hash table + `heapq` min-heap | O(1) average matching; O(log K) deadline scheduling |
| Web backend | FastAPI + uvicorn | Existing; WebSocket support built in |
| Storage | SQLite (`sqlite3`), DB file per team decision (see open questions) | Existing E4 storage; schema extended for probes/correlation/alerts |
| Frontend | React | Per presentation; no frontend exists yet |
| Tooling | Git, GitHub Actions, `ruff`, `black`, `pre-commit`, `pytest` | Existing configuration retained |

### Shared conventions (apply to every phase)

- Default branch: `master`. Branch naming: `feat/e3-tcp-ingestion`,
  `fix/e1-buffer-overflow`, `test/e2-fingerprint-stability`.
- Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `perf:`, `refactor:`,
  `chore:`; engine scope in parentheses, e.g. `feat(e3): ...`.
- Every commit leaves the test suite green; feature tests ship with the
  feature.
- Tag a release at the end of each phase: `v0.2-phase2`, …, `v1.0`.
- Any change to the telemetry record, fingerprint inputs, correlation logic,
  database schema, REST contract or WebSocket message types must update the
  matching section of `data_contract.md` / `api_routes.md` in the **same PR**
  (see `CONTRIBUTING.md`).

### Shared data contract (frozen in Phase 1)

The engine-to-engine structures are specified in
[`data_contract.md`](data_contract.md):

- `CapturedPacket` (E1 → E2): probe ID, sequence, timestamp, lengths, raw bytes.
- `PacketFingerprint` (E2, internal): algorithm/version, 64-bit value, fields used.
- `ProbeTelemetry` (E2 → E3): 24-byte serialized record — fingerprint, probe ID,
  timestamp, flags, sequence, captured length; big-endian; TCP-framed.
- `CorrelationRecord` (E3 → E4): matched/late/unmatched state, T₁, T₂, ΔT,
  deadline, flags.
- `DiagnosticAlert` (E4 internal/persisted): category, severity, evidence,
  recommended action.
- Offline models (`Packet`, `Layer`, `DecodedPacket`, `Flow`) are **preserved**
  for the replay/testing mode; `Flow` is *not* the correlation record.

---

## Phase 1 — Architecture, contracts and development foundation

**Goal:** one agreed architecture, one frozen data contract, and the existing
development foundation (CI, linting, tests) ready for four parallel engine
streams.

**Engine:** all (contract only).
**Dependencies:** none.

**Scope and ordered tasks** — *status as found in the repository:*

| # | Task | Owner | Status |
| --- | --- | --- | --- |
| 1 | Freeze engine responsibilities (this document + README) | All | Done (this revision) |
| 2 | Define shared data contract incl. telemetry framing | All | Done (docs revision; code structures pending) |
| 3 | Define probe identity and configuration variables | Hrishikesh | Documented; code wiring pending |
| 4 | Design telemetry framing and validation rules | Hrishikesh | Documented in `data_contract.md`; implementation is Phase 4 |
| 5 | Test strategy, CI, repository conventions | Hrishikesh | Exists (pytest, pre-commit, GitHub Actions); extended per this plan |

**Proposed Conventional Commits:**

1. `docs: realign README and plan with distributed tracing architecture`
2. `docs(data-contract): define telemetry record, fingerprint and correlation structures`
3. `docs(api): replace static-capture draft with live-tracing API design`
4. `docs(contributing): add contract-change and integration-test rules`
5. `feat(config): add probe/telemetry configuration skeleton` *(if done in code)*

**Unit / integration tests:** none new (documentation phase); the existing
47-test suite must remain green.

**Acceptance criteria:**

- All five docs describe the same four engines, ports (9000/8000) and flow.
- Every team member has reviewed the contract; open questions are listed
  (see below) and assigned.
- `pytest`, `ruff check .`, `black --check .` pass unchanged.

**Completion evidence:** this documentation revision; existing tag
`v0.1-phase1` covers the offline foundation (models, interfaces, engines
starter, routes, 47 unit tests).

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| Contract drifts as engines are built in parallel | Contract changes require a docs PR + team review (CONTRIBUTING rules) |
| 24-byte record turns out insufficient | Record layout already reserves a version field; extension strategy documented in the data contract |

---

## Phase 2 — E1: Distributed capture and buffering

**Goal:** each probe host can passively capture real application traffic into
a bounded buffer without blocking or unbounded memory growth.

**Engine:** E1 (M Janaki).
**Dependencies:** Phase 1 (contract: `CapturedPacket`), two probe hosts or VMs
with capture privileges.

**Ordered tasks (planned):**

1. Spike: compare raw `AF_PACKET` socket vs. libpcap binding on the target OS;
   record the decision here. *(Open decision — see risks.)*
2. `feat(e1): live capture thread reading raw packets from an interface`
3. `feat(e1): pre-allocated ring buffer with configurable slot count (default 10,000)`
4. `feat(e1): producer-consumer handoff with mutex + condition variables`
5. `feat(e1): emit CapturedPacket (probe ID, seq, timestamp, lengths, bytes)`
6. `feat(e1): handle capture errors, interface loss and graceful shutdown`
7. `feat(e1): buffer-saturation policy (drop-oldest vs drop-newest) with drop counters`
8. `test(e1): ring-buffer unit tests (wrap, saturation, concurrent producer/consumer)`
9. `test(e1): replay-mode test feeding controlled PCAP frames through the same buffer`
10. `docs(e1): record capture-mechanism decision and privilege requirements`

**Unit tests:** ring-buffer semantics (bounded capacity, no lost-slot
accounting, thread-safe enqueue/dequeue under stress), timestamp capture,
drop-counter accuracy, shutdown joins all threads.
**Integration tests:** PCAP-replay harness drives the buffer at a configured
rate and asserts ordered `CapturedPacket` output and zero silent drops below
capacity.

**Acceptance criteria:**

- Sustained synthetic input at 10,000 packets/s is absorbed with the buffer
  bounded at its configured slot count (measure, don't assume).
- Saturation is observable (counters) and never crashes the probe.
- Shutdown within a bounded time with no thread leaks.

**Completion evidence:** _(to be filled: commits, benchmark numbers, test run
links — none exist yet)_

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| Raw-socket approach is Linux-only / needs root | Decide via the Phase-2 spike; keep a libpcap fallback behind the E1 interface |
| Python GC/GIL limits capture throughput | Keep capture thread minimal (copy bytes, enqueue); benchmark early; document measured ceiling |
| Timestamp quality insufficient for ΔT | Use kernel-assisted timestamps where available; document precision achieved |

---

## Phase 3 — E2: Protocol dissection and fingerprinting

**Goal:** decode supported protocols and produce a stable 64-bit fingerprint
that matches the same packet at both probes.

**Engine:** E2 (Chhavi Mishra).
**Dependencies:** Phase 1 (contract), Phase 2 output (`CapturedPacket`), or
the PCAP-replay harness for offline development.

**Ordered tasks (planned):**

1. `feat(e2): reuse/extend existing dissectors for Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS`
2. `feat(e2): select invariant field set per protocol (skip TTL, MACs, checksums)`
3. `feat(e2): 64-bit BLAKE2b fingerprint with explicit algorithm version`
4. `test(e2): fingerprint stability across two captures of the same flow (replay at both "probe" positions)`
5. `test(e2): document and test known instability cases (IPv4 ID zeroing, fragments, retransmissions, NAT)`
6. `feat(e2): DNS-query Shannon entropy calculation (H(X) = −Σ p·log₂ p)`
7. `test(e2): entropy unit tests (uniform, skewed, empty, non-ASCII names)`
8. `feat(e2): compact telemetry metadata emission toward the 24-byte record`
9. `docs(e2): fingerprint field matrix and limitation notes in the data contract`

**Unit tests:** per-protocol decapsulation against the existing byte-level
fixtures; fingerprint determinism; entropy values against hand-computed
examples; malformed-packet containment (never crash, mark undecoded).
**Integration tests:** same synthetic flow captured "twice" (simulated probes,
including a hop that decrements TTL and rewrites MACs) must yield identical
fingerprints for the supported field set.

**Acceptance criteria:**

- Fingerprints identical across simulated hops for TCP/UDP/IPv4 flows built
  from supported fields.
- Fingerprint computed in well under the per-packet telemetry budget on the
  target hardware (measure; the presentation's "< 0.1 µs" is a target).
- DNS entropy produces correct values on known inputs; the *classification*
  (possible exfiltration) stays in E4.

**Completion evidence:** _(none yet)_

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| IPv4 ID is zero/random on modern stacks → weaker fingerprints | Validate; consider falling back to a payload-length + ports + seq combination; document per-stack results |
| NAT or middleboxes rewrite IPs/IDs between probes | Documented limitation; recommend probes inside the same administrative domain; add NAT-simulated integration test |
| IP fragments lack transport headers | Define fragment handling (match on IP ID + fragment fields, or exclude with a flag) in the contract |
| 64-bit collisions between concurrent packets | Birthday-bound analysis in the data contract; collisions within the 500 ms window are rare but must degrade gracefully |

---

## Phase 4 — E3: Telemetry ingestion and correlation

**Goal:** central server ingests telemetry from both probes and turns it into
delay estimates and unmatched-packet events.

**Engine:** E3 (Hrishikesh Patil).
**Dependencies:** Phase 1 (telemetry record), Phase 3 (fingerprints arriving
in records).

**Ordered tasks (planned):**

1. `feat(e3): TCP ingestion service on port 9000 (asyncio), one persistent connection per probe`
2. `feat(e3): record framing, version check and malformed-message handling`
3. `feat(e3): correlation hash table keyed by fingerprint (+ disambiguating metadata)`
4. `feat(e3): min-heap of expiration deadlines (T₁ + timeout, default 500 ms)`
5. `feat(e3): match handling — compute ΔT = T₂ − T₁, emit CorrelationRecord`
6. `feat(e3): late-match handling for records arriving after timeout expiry`
7. `feat(e3): duplicate and out-of-order telemetry handling`
8. `feat(e3): clock-quality checks (negative/implausible ΔT flagged, not silently accepted)`
9. `feat(e3): event stream toward E4 (matched, late, unmatched/timeout)`
10. `test(e3): unit tests for matching, expiry boundaries, late arrivals, duplicates, collisions`
11. `test(e3): integration test — two synthetic probes → ingestion → expected records`
12. `docs(e3): correlation semantics and timeout interpretation`

**Unit tests:** O(1) insert/lookup path; heap ordering; timeout boundary
(exactly at 500 ms — define and test inclusivity); late match after expiry
produces a `late` record and updates stats; duplicate T₂ ignored; ΔT negative
→ flagged; key collision within window handled deterministically.
**Integration tests:** scripted two-probe streams (in order, reversed,
interleaved, with drops and delays) assert the exact set of correlation
records and timeout events.

**Acceptance criteria:**

- With synthetic load, correlation throughput ≥ the expected probe packet
  rate with headroom (measure and record).
- No unbounded memory: expired entries always leave both the table and heap.
- Every timeout is explained by an absent T₂ within the window, and late
  arrivals are visible as `late`, never double-counted as loss.

**Completion evidence:** _(none yet)_

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| Clock skew between probes corrupts ΔT | Require NTP on probes; flag implausible values; expose clock-offset estimate in stats |
| Fingerprint collisions cause false matches | Disambiguate with metadata (length, ports); document residual risk |
| Heap grows under loss floods | Hard cap + drop-counter telemetry; alert on cap hits |
| Telemetry protocol bug breaks both probes at once | Version byte + strict validation + canary integration test in CI |

---

## Phase 5 — E4: Diagnostic rules and persistence

**Goal:** convert correlation events into evidence-backed diagnostic alerts
and persist everything for history.

**Engine:** E4 (Vaibhav Kumar).
**Dependencies:** Phase 4 (event stream), existing E4 storage code.

**Ordered tasks (planned):**

1. `feat(e4): SQLite schema v2 — probes, correlation/packet records, diagnostic_alerts (minishark.db per team decision)`
2. `feat(e4): schema-version management (user_version pragma) and migrations`
3. `feat(e4): transactional repository for correlation events and alerts`
4. `feat(e4): deterministic rule engine — packet loss / link-drop rule`
5. `feat(e4): bufferbloat rule (sustained rising ΔT pattern)`
6. `feat(e4): application-freeze / server-delay rule`
7. `feat(e4): possible DNS exfiltration rule (entropy signal + context, never as sole proof)`
8. `feat(e4): alert evidence, severity and recommended-action templates`
9. `test(e4): rule tests per category with synthetic metric windows (positive + negative)`
10. `test(e4): persistence round-trip, migration and crash-safety (rollback) tests`
11. `docs(e4): rule definitions, thresholds and confidence qualifications`

**Unit tests:** each rule fires and *does not* fire on crafted inputs;
threshold boundaries; evidence completeness; DB round-trip equality;
migration from the offline schema; rollback on injected storage failure.
**Integration tests:** E3 synthetic event stream → expected alerts persisted
with correct evidence links.

**Acceptance criteria:**

- Every alert references the correlation records/packet fingerprints that
  justify it; recommendations are labelled guidance, not guarantees.
- DNS entropy alone never produces a "confirmed theft" alert.
- Database survives kill-during-write without corruption (WAL/rollback
  verified by test).

**Completion evidence:** _(none yet)_

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| Rules produce false positives that erode trust | Conservative defaults, tunable thresholds, evidence always shown, confidence field |
| Schema churn between phases | Versioned migrations from day one |
| Alert volume floods storage/UI | Rate limiting, deduplication window, aggregation of recurring alerts |

---

## Phase 6 — API, WebSocket delivery and React dashboard

**Goal:** live and historical data visible to a user with no page reloads.

**Engine:** E4 (Vaibhav Kumar), with E3 as data source.
**Dependencies:** Phases 4–5, `api_routes.md` design.

**Ordered tasks (planned):**

1. `feat(api): health/readiness + probe status endpoints`
2. `feat(api): correlation/live-metrics endpoints (recent ΔT, loss events, stats)`
3. `feat(api): diagnostics endpoints (current, detail with evidence, history + filters)`
4. `feat(api): historical queries (time ranges, aggregates, bounded pagination)`
5. `feat(api): WebSocket /ws/live — typed messages (latency, loss, probe status, alerts, errors)`
6. `feat(ui): React scaffold + WebSocket client with reconnect/backoff`
7. `feat(ui): live latency graph and packet-loss metric`
8. `feat(ui): network status and probe health indicators`
9. `feat(ui): diagnostic incident cards with evidence and recommended action`
10. `feat(ui): historical views with bounded rendering/pagination`
11. `test(api): endpoint contract tests + WebSocket message-schema tests`
12. `test(ui): component tests for graph, cards, reconnect behaviour`

**Unit tests:** response shapes and status codes per `api_routes.md`; WS
message validation both directions; reconnect emits no duplicate state.
**Integration tests:** synthetic event injection → REST reflects it → WS
client receives a typed message within a bounded time.

**Acceptance criteria:**

- Dashboard stays responsive under sustained synthetic event flow (measure
  update rate actually delivered; the 60 FPS figure is a rendering target —
  document measured backend push cadence separately).
- WS reconnect after a server restart restores live state without manual
  reload.
- All historical views bounded (pagination/windowing), no unbounded DOM growth.

**Completion evidence:** _(none yet)_

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| WS message churn breaks the dashboard | Message-type registry + schema tests in CI; version field |
| Rendering 60 FPS overloads browsers | Throttle/batch pushes (e.g. 10 Hz data, interpolated rendering); document honestly |
| REST/WS duplication drifts | Single serialization layer shared by both |

---

## Phase 7 — Integration, validation and final demonstration

**Goal:** prove the whole two-probe-to-dashboard pipeline end to end and
publish honest, reproducible results.

**Engine:** all.
**Dependencies:** Phases 2–6.

**Ordered tasks (planned):**

1. `test(integration): full pipeline — two synthetic probes → correlation → alerts → API/WS`
2. `test(integration): failure/recovery — probe disconnect, server restart, DB locked, malformed telemetry flood`
3. `perf: telemetry size and overhead measurement script (24-byte claim, <1.5% claim)`
4. `perf: capture-throughput, buffer-saturation and drop-counter benchmarks`
5. `perf: correlation throughput and timeout-accuracy benchmarks`
6. `perf: CPU/memory footprint per component; dashboard delivered-update-rate measurement`
7. `docs: record reproducible results (methods + raw numbers) in a results document`
8. `docs: known limitations and open questions for the final report`
9. `chore: demo runbook and tagged release`

**Tests:** the integration and failure suites above; regression run of all
unit tests on the release commit.

**Acceptance criteria:**

- A fresh clone can reproduce the demo by following the README only.
- Every performance claim in the README is either backed by a recorded
  measurement or explicitly labelled a target.
- Limitations (clock sync, fingerprint stability, timeout semantics, DNS
  heuristic) are stated in the final documentation.

**Completion evidence:** _(none yet)_

**Risks and mitigations:**

| Risk | Mitigation |
| --- | --- |
| Demo-day network is unreliable | Pre-recorded fallback capture + replay mode |
| Benchmarks flaky on laptops | Document methodology, repeat runs, report medians |

---

## Summary

| Phase | Focus | Engine | State |
| --- | --- | --- | --- |
| 1 | Architecture, contracts, foundation | All | Docs revision done; code wiring pending |
| 2 | Live capture and buffering | E1 | Planned |
| 3 | Dissection and fingerprinting | E2 | Planned (dissector base exists) |
| 4 | Telemetry ingestion and correlation | E3 | Planned |
| 5 | Diagnostic rules and persistence | E4 | Planned (offline storage exists) |
| 6 | API, WebSocket, React dashboard | E4 | Planned (offline routes exist) |
| 7 | Integration, validation, demo | All | Planned |

## Open questions requiring team confirmation

1. **Capture mechanism for E1** — raw `AF_PACKET` sockets (Linux/root) vs.
   libpcap binding; affects portability claims.
2. **Database file name** — presentation says `minishark.db`; current code
   default is `mini_shark.db` (`MINI_SHARK_DB` override exists). Rename or
   accept the code name?
3. **Clock synchronisation policy** — required NTP accuracy, and whether E3
   should ingest a probe-reported clock offset.
4. **Fingerprint field set per protocol** — presentation lists IPv4 ID,
   protocol, IPs, TCP seq; confirm handling for UDP/ICMP and stacks that
   zero the IPv4 ID.
5. **Telemetry record extension** — the 24-byte record has spare flag bits
   but no room for ports/metrics; confirm the extension path (flag-driven
   side records) if E3 needs disambiguating metadata.
6. **CI branch mismatch** — CI triggers on `main`, default branch is
   `master`; align (config change, team decision).
7. **Retention policy** — how long correlation records and raw telemetry
   summaries live in `minishark.db` before pruning.
