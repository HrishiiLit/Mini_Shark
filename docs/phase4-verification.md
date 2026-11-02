# Phase 1–4 verification and execution plan

## Initial audit (2 November 2026)

- `git status --short`: five modified tracked files and five new files,
  including an existing, uncommitted E3 implementation and tests.
- Baseline: `python -m pytest -q` passed **114 tests**.
- Quality baseline: `ruff check .` reported **123 errors**;
  `black --check .` reported **15 files** needing formatting.
- Phase 1: offline capture, dissection, flow grouping, SQLite queries and API
  are covered by the existing suite. Distributed documentation is stale.
- Phase 2: Scapy/Npcap batch capture exists. The proposed `CapturedPacket`,
  preallocated ring buffer, producer/consumer handoff, saturation counters,
  shutdown tests and 10,000 packets/s evidence do **not** exist. Hardware live
  capture has not been verified in this audit. Phase 2 is **partial**.
- Phase 3: BLAKE2b, hop-invariance tests, DNS entropy and 24-byte serialization
  exist and pass. Fragment/ICMPv6 coverage and performance evidence are
  incomplete; NAT/retransmission limitations still apply.
- Initial E3 defects: fingerprint-only keys discard repeated observations;
  stale heap nodes and early Probe-2 observations can grow without a bound;
  expiry classification depends on timer scheduling; protocol validation,
  connection identity and shutdown cleanup are incomplete.

## Phase 4 execution plan

1. Complete bounded correlation: FIFO observations keyed by fingerprint and
   captured length, per-observation duplicate suppression, inclusive deadlines,
   late correction, clock flags, observable capacity eviction and bounded caches.
2. Complete TCP ingestion: strict preamble/version/identity validation,
   fragmented records, heartbeat recovery, idle timeout, bounded connections,
   task/writer cleanup and a usable command-line service.
3. Exercise both probes through real TCP and the E2 telemetry builder; cover
   deadline boundaries, repeats, collisions, late arrivals and malformed input.
4. Run the demo and a reproducible synthetic throughput/memory benchmark.
5. Update contracts and status using actual evidence; verify tests and quality
   checks. Commit focused changes after reviewing the final diff.

## Final evidence

- `python -m pytest -q`: **144 passed** in 3.25 seconds after placeholder
  cleanup (Windows, Python 3.14.3).
- `ruff check .`: passed; `black --check .`: all 42 Python files unchanged.
- `git diff --check`: passed.
- `pre-commit run --all-files`: passed (Black, Ruff, trailing whitespace,
  end-of-file and YAML hooks), after installing the missing pre-commit tool.
- Editable package build/install: `pip install --no-deps -e .` passed using
  normal build isolation. A preliminary `--no-build-isolation` attempt failed
  because this venv had no setuptools; the declared isolated build succeeds.
- `python -m backend.e3_flows --help`: passed; standalone command and CLI
  configuration documented in the README.
- `python demo_e3.py`: real TCP run on port 9000 produced 5 matched events,
  2 timeout events, 1 late recovery (1 remaining unmatched), 1 suppressed
  duplicate and 1 clock-skew flag. Suspect delays stay out of percentiles.
- `python benchmark_e3.py --packets 20000 --runs 3`: all 20,000 pairs matched
  in every run. Median **25,460 pairs/s** direct, **13,839 pairs/s** over real
  localhost TCP, with the default **500 ms** timeout and at most 100 in-flight
  pairs per batch. Raw run rates and configuration: `phase4-benchmark.json`.
- A 20,000-observation Probe-2-only flood with capacity 1,024 retained exactly
  1,024 active observations/heap nodes and 1,024 dedup entries; 18,976 capacity
  evictions were counted. Python-traced peak allocation was **1,071,448 bytes**
  (not process RSS). Unit tests separately exercise Probe-1 floods, late-cache
  bounds and successful-match heap reclamation.
- Removed ten unreferenced `{}` placeholder files from `tests/expected/` after
  confirming no test reads them. Functional regression tests are retained.
- CI now covers `master`/`main` and installs declared test dependencies rather
  than ignoring installation failures. Remote GitHub Actions was not run here.

The initial saturation benchmark caught the draft's fixed 100 ms early-T2
grace expiring valid observations under uneven TCP draining. E3 now defaults
to the full configured match window and uses `asyncio.timeout` without spawning
a task for every read. The final benchmark uses bounded batches and the normal
500 ms timeout; it does not claim unlimited burst buffering.

## Remaining qualification

- Phase 2 is still partial as detailed above. The audit verifies the Scapy
  adapter using synthetic capture objects; it does not establish NIC/driver
  operation, timestamp accuracy or sustained physical capture throughput.
- Phase 3 passes its existing supported-field tests, but fragment/ICMPv6,
  zero-ID/retransmission ambiguity and NAT limitations prevent claiming full
  production coverage. The sub-microsecond fingerprint target is unmeasured.
- E3 results are synthetic on one Windows machine, not a two-host/NTP test or
  a hardware guarantee. Snapshot lengths must agree at both probes.
- Late recovery and deduplication are bounded by cache retention. FIFO cannot
  uniquely distinguish identical packet fingerprints; capacity-evicted events
  are flagged as incomplete evidence rather than proof of loss.
- No phase release tag or remote push was performed. E4 diagnostics, distributed
  persistence, REST/WebSocket integration and React remain phases 5–6.
