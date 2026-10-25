# Contributing to Mini-Shark

Mini-Shark is a four-engine distributed system (see [README](README.md)).
Because the engines are built in parallel by different owners, most of the
rules below exist to keep the shared contracts from drifting.

## Engine ownership

| Engine | Scope | Owner |
| --- | --- | --- |
| E1 | Packet Capture & Buffering (probe-side capture, ring buffer, concurrency) | M Janaki |
| E2 | Protocol Dissection & Invariant Fingerprinting (parsers, 64-bit hash, DNS entropy) | Chhavi Mishra |
| E3 | Multi-Point Correlation Hub (TCP ingestion :9000, hash-table matching, min-heap timer) | Hrishikesh Patil |
| E4 | Diagnostics, Storage & User Interface (rules, SQLite, REST/WebSocket :8000, dashboard) | Vaibhav Kumar |

Cross-cutting changes (contracts, CI, config) are proposed to the whole team
and merged with one approval from a non-author.

## Shared data contracts — the hard rules

The engine-to-engine interfaces live in [data_contract.md](data_contract.md).
They are versioned and must not change silently:

1. **Telemetry compatibility.** Any change to the 24-byte telemetry record,
   the TCP preamble, record framing, or validation behavior requires:
   a contract-change PR updating `data_contract.md` **and**
   `api_routes.md` where relevant, a version nibble bump if the wire format
   changes, and coordinated deployment notes for both probes and the central
   server (mixed versions must fail fast, never misparse).
2. **Fingerprint changes.** Any change to the hashed field set, hash
   algorithm, or canonical field encoding requires a `PacketFingerprint`
   **version bump**, an update to the field-stability notes in the data
   contract, and re-validation tests showing cross-probe equality on the
   supported protocol set.
3. **Correlation semantics.** Changes to match states, timeout/late-match
   behavior, or flag meanings must update the data contract and the E3 test
   matrix (duplicates, out-of-order, late arrivals, expiry boundaries).
4. **Database schema.** Schema changes ship with a forward migration and a
   `PRAGMA user_version` bump; alert and correlation-table changes also
   update the persistence section of the data contract.
5. **API and WebSocket contracts.** REST changes update
   [api_routes.md](api_routes.md); WebSocket message types live in a single
   registry shared by server and dashboard, with schema tests on both sides.

Rule of thumb: **if another engine's code could break, the contract document
changes in the same PR.**

## Branch naming

- Features: `feat/<engine>-<short-description>` — e.g.
  `feat/e3-tcp-ingestion`
- Bug fixes: `fix/<engine>-<short-description>` — e.g.
  `fix/e1-buffer-shutdown`
- Tests only: `test/<engine>-<short-description>`
- Docs only: `docs/<short-description>`

## Commit messages

Follow **Conventional Commits**:

```
<type>(<engine scope>): <description>

[optional body]
[optional footer(s)]
```

Types: `feat`, `fix`, `test`, `docs`, `perf`, `refactor`, `chore`, `ci`.
Scopes: `e1`, `e2`, `e3`, `e4`, `api`, `ui`, `contract`, `ci`.
Every commit must leave the test suite green; a feature ships with its tests
in the same commit or the one immediately after.

## Testing expectations

| Area | Expectation |
| --- | --- |
| E1 | Ring-buffer semantics (wrap, saturation, counters), thread-safety under stress, capture-error and shutdown paths, replay-mode equivalence |
| E2 | Per-protocol decapsulation against byte-level fixtures, fingerprint determinism and cross-"hop" stability (TTL/MAC changes), entropy math, malformed-packet containment |
| E3 | Matching, expiry boundary (inclusive/exclusive — define and test), late matches, duplicates, out-of-order arrival, collision handling, clock-quality flags |
| E4 | Rule positive/negative cases with synthetic windows, evidence completeness, persistence round-trips, migrations, rollback on failure |
| API/WS | Contract tests for every endpoint and message type (shapes, status codes) |
| Cross-engine | **Integration tests required** for any change touching a contract seam: telemetry producer→consumer, E3→E4 event stream, E4→dashboard message flow |

- Unit tests in `tests/unit/`; integration tests in `tests/integration/`
  (create when the first cross-engine test lands); fixtures in `tests/data/`.
- Never commit real capture files containing third-party traffic; build
  byte-level fixtures (see `tests/unit/helpers.py`) or synthetic captures.
- Run locally before pushing: `pytest`, `ruff check .`, `black .`,
  `pre-commit run --all-files`.

## Pull requests and CI

1. Branch off `master` (the default branch) and open a PR against `master`.
2. CI must pass: pre-commit (ruff + black) and pytest.
3. At least one teammate reviews and approves; contract changes need the
   affected engine owners named in the PR description.
4. Release tags (`v0.x-phaseY`) are created by maintainers after merge.

> **Known issue:** the CI workflow currently triggers on the branch name
> `main` while the default branch is `master`. Until the team decides to
> align them (tracked in [implementation.md](implementation.md) open
> questions), do not assume CI ran on your PR — run the checks locally.

## Reporting reproducible defects

Packet-processing and correlation bugs are hard to reproduce from a
screenshot. A report must include:

- **Engine and version** (fingerprint version, telemetry record version if
  relevant).
- **Minimal input:** a byte-level fixture, a generated PCAP, or a telemetry
  script that reproduces the stream (two-probe tests can replay both sides).
- **Observed vs. expected** behavior, including any correlation flags,
  timestamps, and clock-skew assumptions.
- For flaky timing issues: measured rates, machine/OS, and how many runs
  before reproduction.

## Documenting performance measurements

Performance numbers do not belong in commit messages or chat — they belong in
a committed results note (method, hardware/OS, workload shape, raw numbers,
median of N runs). Rules:

- Never copy a figure from the presentation into the README as if it were
  measured. **Targets are labelled targets** until a measurement backs them
  (see the README's performance-targets table).
- If a benchmark contradicts a target (e.g. telemetry overhead above 1.5 % on
  small-packet traffic), record the result and open a team discussion — do
  not quietly drop the target or massage the workload.

## Documenting diagnostic limitations

E4 emits *inferred* diagnoses. Contributors changing rules must keep the
contractual distinctions intact:

- Observed symptom vs. inferred root cause stay separate fields.
- DNS entropy never yields a "confirmed theft" verdict; confidence stays
  `low`/`medium` with contextual evidence.
- A timeout localizes loss only to the segment between probes; wording in
  alerts, docs and the dashboard must not overclaim.
- Recommended actions are guidance, never guaranteed fixes.

## Code formatting and linting

- `black` for formatting (line length 88), `ruff` for linting — config in
  `pyproject.toml`.
- `pre-commit run --all-files` before every push (hooks: black, ruff,
  trailing whitespace, end-of-file, YAML check).
