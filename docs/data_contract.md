# Data Contract — Mini-Shark Distributed Tracing

This document defines every structure shared between the four engines. It is
the single source of truth for engine boundaries; any change to it must follow
the contract-change rules in [CONTRIBUTING.md](CONTRIBUTING.md).

**Status convention:** structures marked *implemented* exist in
`backend/models.py` for offline or distributed operation. Structures marked
*proposed* define the distributed architecture and are not yet in the codebase.

Two rules apply throughout:

1. **A network flow and a cross-probe correlation are different concepts.**
   The five-tuple `Flow` model remains valid for offline traffic analytics,
   but it is *not* the packet-correlation record of E3.
2. **Fingerprints are derived, not constant.** The value `0x8F3A2B194E5C0D1A`
   in the presentation is an *example* of a computed 64-bit fingerprint, not a
   universal identifier. Every fingerprint is computed from packet fields by
   the algorithm below.

---

## 1. CapturedPacket — *proposed* (E1 → E2)

A raw packet as observed by one probe.

| Field | Type | Req/Opt | Meaning & validation |
| --- | --- | --- | --- |
| `probe_id` | `uint8` (1–255) | Required | Identity of the observing probe (1 = client side, 2 = server/gateway side by convention). Assigned via configuration (`MINISHARK_PROBE_ID`). |
| `seq` | `uint32` | Required | Per-probe monotonic packet counter (wraps at 2³²). Used for gap detection at E3 and ordering evidence; not part of the cross-probe fingerprint. |
| `timestamp_ns` | `uint64` | Required | Capture timestamp, **nanoseconds since the Unix epoch**, taken as close to the NIC as the capture mechanism allows. Precision depends on the capture mechanism (see §8). |
| `captured_len` | `uint16` | Required | Number of bytes captured (may be < wire length if snaplen truncation applies). |
| `original_len` | `uint16` | Optional | Wire length when known. Not representable in the 24-byte telemetry record (see §4); retained locally by E1/E2 for evidence. |
| `data` | `bytes` | Required | Raw frame bytes (link layer up). E1 owns the buffer; **E2 must not retain `data` past dissection** — the ring buffer recycles slots, so holding a reference corrupts memory semantics. E2 copies any bytes it needs (e.g. fingerprint inputs). |
| `interface` | `str` | Optional | Capture interface name; diagnostics-only metadata. |

**Producer:** E1. **Consumer:** E2. **Serialization:** in-process only; never
sent over the network as raw bytes (only derived telemetry is sent).

*Relation to the implemented offline model:* the existing `Packet`
(`index`, `timestamp`, `length`, `raw_bytes`) is the offline-mode equivalent
without probe identity or sequence; `CapturedPacket` extends that shape rather
than replacing it.

## 2. DecodedPacket — *implemented for offline mode; reused by E2*

Existing model in `backend/models.py`, unchanged:

| Field | Type | Meaning |
| --- | --- | --- |
| `packet_index` | `int` | Reference to the originating packet's index |
| `layers` | `list[Layer]` | Ordered protocol layers, link → application |

`Layer`: `name: str`, `fields: dict[str, Any]`, `undecoded_bytes: bytes`.

E2's live path additionally produces a `PacketFingerprint` (§3) per decoded
packet and may compute a DNS entropy value (§7) for DNS queries. Malformed or
unsupported headers are marked (`malformed` flag / `Undecoded` layer) and
**never abort processing of other packets**.

## 3. PacketFingerprint — *implemented* (E2, internal and inside telemetry)

| Field | Type | Req/Opt | Meaning & validation |
| --- | --- | --- | --- |
| `algorithm` | `str` enum | Required | `"blake2b-64"` (Python `hashlib.blake2b(digest_size=8)`). |
| `version` | `uint8` | Required | Fingerprint algorithm version (`1` = initial field set). **Changing the field set or algorithm requires a version bump** and coordinated E2/E3/E4 deployment. |
| `value` | `uint64` | Required | The 64-bit fingerprint, serialized big-endian. |
| `fields_used` | `list[str]` | Optional | Debug/telemetry metadata: which fields fed the hash for this packet (e.g. `["ip.id","ip.proto","ip.src","ip.dst","tcp.seq"]`). Not transmitted in the 24-byte record. |

### Field set (version 1, per the presentation)

Hashed (treated as path-invariant for a given packet):

| Field | Why it is (mostly) stable |
| --- | --- |
| IPv4/IPv6 source address | Unchanged by routing (NAT is a documented exception, §9) |
| IPv4/IPv6 destination address | Unchanged by routing (NAT exception) |
| IP protocol / next header | Constant end-to-end |
| IPv4 identification | Copied to all fragments; routers do not rewrite it for unfragmented packets (some stacks zero it — §9) |
| TCP source port, destination port, sequence number | Stable without NAT; retransmissions reuse these fields |
| UDP: source port, destination port, length | UDP has no sequence number; ports + length substitute |
| ICMP: type, code | Current v1 implementation; echo identifier/sequence are not included |

Version-1 coverage qualification: ICMPv6 currently contributes IP-layer fields
only; IPv6 extension headers and reliable IP-fragment correlation are not
implemented. Malformed transport headers may leave only IP fields. Treat these
as weak fingerprints rather than unique packet identities. The field matrix
above reflects the actual v1 encoder; stronger fields require a version bump.

Explicitly **excluded**: TTL/Hop Limit (decremented per router), source and
destination MAC addresses (rewritten at every hop), header checksums
(recalculated per hop), TCP/UDP checksums (pseudo-header changes with TTL).

### Matching limitations (must be validated in Phase 3, not assumed)

- **IPv4 ID reuse/zeroing:** some stacks set IPv4 ID to 0 for large/DF
  packets; two concurrent packets could then collide on the remaining fields
  within the same flow only if TCP seq also matches — retransmissions reuse
  seq numbers and *will* produce identical fingerprints. E3 must treat a
  fingerprint match as "the next unclaimed observation," which is correct for
  ordering but can mis-pair retransmitted segments; document measured impact.
- **IP fragmentation:** non-first fragments carry no transport header; the
  fingerprint for them can only use IP-layer fields. Decide in Phase 3
  whether fragments are correlated at all; either way, document the choice.
- **NAT/middleboxes:** a NAT between the probes rewrites addresses and
  possibly ports/IDs, so fingerprints legitimately differ at the two probes.
  The supported deployment is probes inside the same administrative domain
  with no address-rewriting middlebox between them.
- **Collisions:** a 64-bit hash over a 500 ms in-flight window at 10,000
  packets/s sees ≤ ~5,000 distinct concurrent keys; the birthday-bound
  collision probability is negligible (≈ 2.7×10⁻¹³) but not zero — E3
  disambiguates with probe metadata where available and never treats a
  collision as impossible.
- **Protocol coverage:** the invariant field set is fully specified only for
  the supported set (IPv4/IPv6 + TCP/UDP/ICMP/DNS). Other protocols are
  excluded from correlation until their field sets are defined.

**Producer:** E2. **Consumers:** E2 (embeds into telemetry), E3 (matching
key). **Persistence:** stored with correlation records (§6, §7).

## 4. ProbeTelemetry — *implemented* (E2 → E3, over TCP port 9000)

The compact per-packet record. **Target size: 24 bytes** (presentation
figure). The layout below was checked field-by-field and fits exactly 24
bytes with no spare bytes.

### Wire layout (version 1), big-endian, fixed 24 bytes

| Offset | Size | Field | Type | Notes |
| --- | --- | --- | --- | --- |
| 0 | 8 | `fingerprint` | `uint64` | §3 value |
| 8 | 8 | `timestamp_ns` | `uint64` | Probe-local capture time, ns since epoch |
| 16 | 4 | `seq` | `uint32` | Per-probe counter (gap detection, duplicates) |
| 20 | 1 | `probe_id` | `uint8` | 1–255 |
| 21 | 1 | `type_flags` | `uint8` | bits 0–3: record type (1 = packet data); bits 4–7: telemetry format version (`0001` = v1) |
| 22 | 2 | `captured_len` | `uint16` | Captured bytes, evidence only |
| | **24** | | | |

**What did *not* fit, and why that is acceptable:** original wire length,
ports, protocol number, DNS entropy, TCP flags, and clock-offset metadata
cannot fit without exceeding 24 bytes. The chosen smallest adjustment: those
values require separately supplied context or future **extension records** —
new `type_flags` record types (e.g. type 2 = DNS entropy report, type 3 =
probe summary) whose payloads are defined alongside the type. Extension
records do not change the 24-byte packet-data record. If a future need
requires fields in the packet-data record itself, the format version nibble
permits a v2 record with a different size, declared in the connection
preamble (§4.2). This is the documented decision point; changing it requires
a contract change PR.

E3 cannot recover headers or entropy from a one-way hash. Only types 1 (packet)
and 3 (heartbeat, same layout, fingerprint/length zero) are implemented; type 2
and other extensions are reserved and rejected. `TelemetryClient.send_heartbeat`
is explicit; a probe runtime must schedule it every 5 seconds while idle.

### 4.2 TCP framing and connection lifecycle

TCP is a byte stream; record boundaries must be explicit:

1. **Preamble (once per connection):** the probe sends a fixed 16-byte
   preamble — 4-byte magic `MSHK`, 1-byte preamble version, 1-byte record
   size (24 for v1), 2 reserved bytes, 4-byte epoch-seconds of the probe's
   clock at connect time, 4 reserved. This declares the record size and gives
   E3 a coarse clock-offset hint. E3 validates magic, version, record size and
   zero reserved fields, then logs and closes on mismatch (no error reply).
2. **Record stream:** after the preamble, the probe sends a stream of
   **fixed-size records** as laid out above. The receiver accumulates bytes
   and emits a record whenever 24 bytes are available; partial records are
   buffered across `recv` calls.
3. **Keepalive/heartbeat:** an idle probe sends a type-3 summary record at a
   configured interval (default 5 s) so E3 can track probe liveness.
4. **Shutdown:** a clean close marks the probe offline. Outstanding observations
   retain their original deadlines so disconnects cannot manufacture early
   loss events. Server stop closes writers and awaits all handler tasks.

### 4.3 Validation and malformed-message handling

- Unknown `type_flags` version nibble → reject connection (fail fast; prevents
  silent misinterpretation).
- Known type with wrong size (impossible for v1 fixed records; guards future
  versions) → reject connection, log peer address.
- `timestamp_ns` implausible for the preamble clock hint (offset beyond a
  configured bound) → accept record but set a **clock-quality flag** on the
  correlation; E3 surfaces the flag to E4 rather than dropping data.
- Unknown record types, unconfigured probe IDs, identity changes within a
  connection, and a second simultaneous connection for the same probe are
  rejected. Identity is established by the first valid record.
- At most 8 connections by default; stream-reader limit 4,096 bytes (asyncio
  applies transport backpressure). Each complete preamble/record must arrive
  within 30 seconds. Trailing partial records increment rejection counters.
- Valid traffic restores degraded probes to online; 15 seconds without valid
  traffic marks them degraded; EOF or the 30-second read timeout marks offline.
- Clock differences beyond 60 seconds (record/server or preamble/server) set
  `CLOCK_SKEW_SUSPECT`. The coarse clock hint is not a synchronisation estimate.
- **Authentication:** v1 has no token field or authentication and no encryption;
  it is deployment-internal. Auth/TLS require a future versioned contract.

**Producer:** E2's emitter (per probe). **Consumer:** E3 ingestion service
(port 9000). **Not** duplicated as an HTTP route — ingestion is TCP-only by
design (see [api_routes.md](api_routes.md) §2).

## 5. CorrelationRecord — *implemented* (E3 → E4)

One record per distinct in-flight packet key observed by the probes.

| Field | Type | Req/Opt | Meaning & validation |
| --- | --- | --- | --- |
| `fingerprint` | `uint64` | Required | Correlation key (§3) |
| `probe1_observed` | `bool` | Required | Seen at Probe 1 |
| `probe2_observed` | `bool` | Required | Seen at Probe 2 |
| `t1_ns` / `t2_ns` | `uint64` | Optional | Capture timestamps per probe (present iff observed there) |
| `delay_ns` | `int64` | Optional | ΔT = T₂ − T₁, present only when both observed. **Signed:** negative values are *valid data* (clock skew) and are flagged, not discarded. |
| `match_state` | enum | Required | `matched` · `late` (T₂ after timeout) · `unmatched` (timed out) · `probe2_only` (reverse-direction or missing T₁ case) |
| `deadline_ns` | `uint64` | Required | T₁ + timeout (default 500 ms, configurable) |
| `flags` | `uint32` | Optional | `CLOCK_SKEW_SUSPECT`=1, `COLLISION_DISAMBIGUATED`=2, reserved `FRAGMENT`=4, `DUPLICATE_T2_IGNORED`=8, `FINGERPRINT_VERSION_MISMATCH`=16; `CAPACITY_EVICTED`=32 |
| `probe1_seq` / `probe2_seq` | `uint32` | Optional | Telemetry sequence numbers, for gap/duplicate evidence |
| `created_at_ns` | `uint64` | Required | Server-side record creation time |

**Semantics that E3 guarantees and E4 relies on:**

- Matching uses `(fingerprint, captured_len)` buckets and FIFO observations
  within each bucket. Both probes need equal snaplen/link-layer lengths.
  Probe-local sequences never identify the cross-probe packet. Repeated
  fingerprints remain separate observations; FIFO ambiguity is flagged when
  multiple candidates exist. Indistinguishable retransmissions can still pair
  incorrectly. Ports are unavailable on the wire and cannot disambiguate E3.
- Exactly identical telemetry (all six fields) is suppressed for either probe
  while retained in the bounded 50,000-observation FIFO dedup cache. After cache
  eviction, duplicates can be processed again; no unbounded guarantee is made.
- Deadline expiry is inclusive: server `now >= T1 + timeout`. Expiration runs
  before each record as well as on a 50 ms timer, preventing timer races. A
  late match is based on server receipt/processing time, not only T2 capture
  time. Early T2 is buffered for the configured match window from server receipt
  (500 ms by default), then emits `probe2_only` with that grace deadline.
- `unmatched` means *"no Probe-2 observation arrived within the timeout
  window."* It does **not** prove where on the path the packet was lost — with
  two probes the strongest honest claim is "lost (or delayed beyond the
  window) between the two observation points." If a T₂ arrives afterwards the
  record transitions to `late` and E4 must be able to retract or downgrade the
  original alert.
- Pending observations across both probes are capped at 200,000. Capacity
  pressure evicts the earliest deadline with `CAPACITY_EVICTED`; this means
  incomplete correlation evidence, not confirmed packet loss. Heap nodes are
  lazily removed and compacted to at most twice the active count; an empty
  table has an empty heap. Expired T1 observations occupy a separate bounded
  50,000-entry FIFO cache for late matching, oldest expired candidate first.
- `unmatched_total` counts cumulative emitted timeout/eviction events;
  `late_recoveries` counts corrections to them. Use
  `uncorrected_unmatched_total = unmatched_total - late_recoveries` rather than
  counting late recovery as loss again. Recovery is limited by cache retention.
- Negative or >10-second delays are flagged; suspect delays are excluded from
  latency percentiles. Listener callbacks run synchronously on the event loop;
  failures are logged and counted, and do not prevent other listeners receiving
  an event. E4 must keep callbacks short or implement its own bounded handoff.

**Producer:** E3. **Consumer:** E4. **Persistence:** §7 `packets`/correlation
table.

## 6. DiagnosticAlert — *proposed* (E4, persisted and served)

| Field | Type | Req/Opt | Meaning & validation |
| --- | --- | --- | --- |
| `alert_id` | `int64` (PK) | Required | Surrogate key, assigned at insert |
| `category` | enum | Required | `PACKET_LOSS` · `BUFFERBLOAT` · `APP_FREEZE` · `DNS_EXFIL_SUSPECTED` |
| `severity` | enum | Required | `info` · `warning` · `critical` |
| `detected_at_ns` | `uint64` | Required | Rule-fire time |
| `evidence_refs` | list | Required | Correlation record IDs / fingerprint values / time windows that justified the alert. **An alert without evidence refs is invalid by contract.** |
| `metrics` | `dict[str, float]` | Required | Observed metrics at detection (e.g. `loss_rate`, `delay_trend_ms_per_s`, `zero_window_events`, `dns_entropy`) |
| `recommended_action` | `str` | Required | Prescribed next step (e.g. "Enable FQ-CoDel AQM", "Check link/cable", "Restart process", "Block domain / inspect"). **Guidance, not a guaranteed fix.** |
| `confidence` | enum | Required | `high` (direct evidence, e.g. confirmed loss) · `medium` · `low` (heuristic, e.g. DNS entropy) |
| `resolved_at_ns` | `uint64` | Optional | Set when a late match or recovery retracts/downgrades the alert |

**Diagnostic correctness rules:**

- `DNS_EXFIL_SUSPECTED` is produced from a *heuristic* (Shannon entropy of a
  DNS query name above a threshold, presentation value H(X) > 4.2) and
  **always** carries `confidence: low/medium` with contextual evidence; it is
  never presented as proof of data theft.
- `BUFFERBLOAT` and `APP_FREEZE` are *inferred root causes* from observed
  patterns (sustained rising ΔT; zero-window/paired-probe evidence
  distinguishing server-side delay from path delay). The alert separates
  **symptom** (observed) from **root cause** (inferred) in its evidence.
- `PACKET_LOSS` states the scope honestly: loss *between the observation
  points*, pending additional probes for finer localization.

**Producer/owner:** E4 rule engine. **Consumers:** REST API, WebSocket,
dashboard (see [api_routes.md](api_routes.md)).

## 7. Persistence models — *proposed schema v2* (E4, SQLite)

The presentation's entities are preserved with the relationships the tracing
system needs. Implementation detail: `packets` below is the correlation
record store — it is **not** the offline-mode `packets` table (raw frames of
an uploaded capture); the two coexist behind a schema version.

| Entity | Key columns (beyond PK) | Relationships |
| --- | --- | --- |
| `probes` | `probe_id` (PK, uint8), `name`, `ip`, `location`, `role` (`source`/`destination`), `first_seen_ns`, `last_seen_ns`, `status` | Referenced by `packets` |
| `packets` (correlation records) | `fingerprint` (uint64), `t1_ns`, `t2_ns`, `delay_ns`, `match_state`, `flags`, `probe1_id`/`probe2_id` (FK → probes, nullable), `created_at_ns` | FK to `probes`; referenced by `diagnostic_alerts` |
| `flows` (supplementary analytics, optional) | normalized five-tuple, packet/byte counts, time window | Independent of correlation; supports dashboard flow summaries only |
| `diagnostic_alerts` | `category`, `severity`, `detected_at_ns`, `metrics_json`, `evidence_json`, `recommended_action`, `confidence`, `resolved_at_ns` | FK → correlation records via `evidence_json` refs (normalized join table if needed) |

Requirements: parameterized SQL only; primary/foreign keys enforced; writes
of an alert and its evidence in one transaction; schema version via
`PRAGMA user_version` with forward migrations. Offline-mode tables
(`captures`, `packets`-raw, `layers`, `flows`) are unchanged and keep their
current behavior.

*Naming decision pending:* the presentation specifies database file
`minishark.db`; current code defaults to `mini_shark.db` (env `MINI_SHARK_DB`).
Tracked as an open question in [implementation.md](implementation.md).

## 8. Time, clocks and timestamp precision

- All cross-engine times are **integer nanoseconds since the Unix epoch**
  (`uint64`); no floats on the wire or in the schema.
- One-way delay ΔT = T₂ − T₁ is only meaningful if probe clocks are
  synchronised better than the delays being measured. Requirements to verify
  in Phase 4/7: NTP (or equivalent) running on both probes; measured clock
  offset recorded in probe summaries; E3 flags negative or implausible ΔT
  (`CLOCK_SKEW_SUSPECT`) rather than silently accepting it.
- Capture timestamps should be taken in (or near) the kernel — userspace
  receive time adds jitter that biases ΔT upward. The achieved precision per
  capture mechanism must be measured and documented in Phase 7.

## 9. Known limitations and open contract questions

| # | Issue | Status |
| --- | --- | --- |
| 1 | NAT between probes breaks fingerprint equality | Deployment constraint (same admin domain); documented |
| 2 | TCP retransmissions share fingerprints → possible mis-pairing | Accepted for v1; measure impact; disambiguation via seq/timing possible later |
| 3 | IP fragments: non-first fragments lack transport fields | Phase 3 decision required (correlate on IP fields vs. exclude) |
| 4 | Stacks that zero the IPv4 ID weaken fingerprints | Phase 3 validation required; fallback field set to be evaluated |
| 5 | 24-byte record has no room for ports/metrics | Extension-record mechanism defined (§4); no change to packet-data record |
| 6 | Clock skew corrupts one-way ΔT | Mitigations in §8; residual risk documented, not eliminated |
| 7 | UDP/ICMP fingerprint field sets are proposed, not presentation-specified | Phase 3 confirmation required |
| 8 | DB file name mismatch (`minishark.db` vs `mini_shark.db`) | Team decision pending |

## 10. Offline-mode models (retained)

For the PCAP/PCAPNG replay-and-analysis mode that exists in the codebase
today, unchanged:

- **Packet** *(implemented)* — `index: int`, `timestamp: float`,
  `length: int`, `raw_bytes: bytes`
- **Layer** *(implemented)* — `name`, `fields`, `undecoded_bytes`
- **DecodedPacket** *(implemented)* — `packet_index`, `layers`
- **Flow** *(implemented)* — `flow_id`, `five_tuple`,
  `packet_indices`, `packet_count`, `byte_count`, `start_ts`, `end_ts`,
  `duration`; packets without a valid five-tuple go to the explicit
  "ungrouped" bucket and are never dropped.

These support offline testing, replay and debugging of E2/E3 logic against
captured data; they are **not** the live distributed contract and must not be
described as such.
