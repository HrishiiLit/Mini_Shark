# API Design — Mini-Shark Distributed Tracing

This document specifies every external interface of the central diagnostic
server: HTTP REST (port 8000), the WebSocket dashboard stream (port 8000),
and the probe telemetry ingestion service (raw TCP, port 9000). Payload
shapes follow the shared [data contract](data_contract.md).

**Status convention:** each endpoint is marked **Implemented** (exists in
`backend/api/routes.py` today, serving the offline PCAP-replay mode) or
**Proposed** (designed here, not yet in the code). Nothing marked *Proposed*
should be documented or demoed as working.

> **Port discipline:** telemetry from probes flows over **TCP 9000** and is
> never ingested via HTTP. The REST/WebSocket surface on **port 8000** serves
> the dashboard and operators only. Do not add an HTTP ingestion route that
> duplicates the TCP service.

---

## 1. Health and configuration

### `GET /health` — **Implemented**

Liveness probe for the API process.

- **Params:** none. **Auth:** none.
- **Response 200:**

```json
{ "status": "ok" }
```

- **Errors:** none (a running server always answers 200).

### `GET /ready` — **Proposed**

Readiness for the distributed mode: reports whether telemetry ingestion is
listening and database access works.

- **Params:** none. **Auth:** none (deploy-internal).
- **Response 200** when ready:

```json
{
  "status": "ready",
  "telemetry_ingestion": { "listening": true, "port": 9000, "connected_probes": [1, 2] },
  "database": { "ok": true, "path": "minishark.db", "schema_version": 2 }
}
```

- **Errors:** `503` with `"status": "starting"` / `"degraded"` and the failing
  subsystem named.

### `GET /config` — **Proposed**

Effective runtime configuration (ports, timeout, ring size, fingerprint
version). Read-only; validation of operator edits happens via environment
variables at startup, not at runtime.

- **Response 200:**

```json
{
  "telemetry_port": 9000,
  "match_timeout_ms": 500,
  "ring_slots": 10000,
  "fingerprint_algorithm": "blake2b-64",
  "fingerprint_version": 1,
  "telemetry_record_bytes": 24
}
```

## 2. Probe and telemetry ingestion

### Telemetry ingestion — raw TCP, port 9000 — **Proposed (by design; not HTTP)**

Probes open one persistent TCP connection to the central server and stream
fixed-size 24-byte telemetry records after a 16-byte connection preamble.
Framing, validation, versioning, heartbeat and error handling are specified
in [data contract §4](data_contract.md). Summary:

| Concern | Behavior |
| --- | --- |
| Framing | Preamble (magic `MSHK`, version, record size, probe clock hint) then fixed 24-byte records; partial records buffered across reads |
| Authentication | Optional shared token in the preamble (config-driven); no TLS (documented limitation) |
| Validation | Version/size checked at preamble; per-record field bounds; implausible timestamps flagged, not dropped |
| Malformed input | Unknown version or size → connection closed with error preamble + server log; bounded buffers guard floods |
| Heartbeat | Type-3 summary record every 5 s (default) drives probe liveness; missed heartbeats flip probe status to offline |

There is deliberately **no** `POST /telemetry`-style HTTP endpoint: TCP
ingestion is the contract, and adding a second ingestion path would create
two sources of truth for the same records.

### `GET /probes` — **Proposed**

Probe registry and liveness (data sourced from E3 connection state + the
`probes` table).

- **Auth:** none (deploy-internal) or dashboard session, deployment choice.
- **Response 200:**

```json
{
  "probes": [
    {
      "probe_id": 1, "name": "client-side", "ip": "192.168.1.10",
      "role": "source", "status": "online",
      "last_heartbeat_ns": 1761260000123456789,
      "clock_offset_ms_estimate": 1.2,
      "packets_sent": 184213, "records_rejected": 0
    },
    {
      "probe_id": 2, "name": "server-side", "ip": "192.168.1.20",
      "role": "destination", "status": "online",
      "last_heartbeat_ns": 1761260000120456789,
      "clock_offset_ms_estimate": 0.8,
      "packets_sent": 183990, "records_rejected": 2
    }
  ]
}
```

- **Errors:** `503` if ingestion is not running.

## 3. Correlation and live metrics

### `GET /metrics/latency` — **Proposed**

Recent one-way delay observations (sliding window, bounded).

- **Query:** `window_s` (default 60, max 3600), `probe_pair` (default
  `1,2`).
- **Response 200:**

```json
{
  "window_s": 60,
  "samples": [
    { "t_ns": 1761260000127000000, "delay_ms": 4.0, "fingerprint": "0x8F3A2B194E5C0D1A" }
  ],
  "stats": { "count": 1842, "p50_ms": 3.8, "p95_ms": 6.2, "p99_ms": 11.9, "max_ms": 42.0 }
}
```

- **Errors:** `422` invalid `window_s`; `503` ingestion down.
- **Notes:** samples may be downsampled server-side above a configured rate;
  `stats` is always computed over the full window.

### `GET /metrics/loss` — **Proposed**

Recent unmatched/timeout events (E3 `unmatched` / `late` records).

- **Query:** `since_ns`, `limit` (max 500), `state` (`unmatched`|`late`).
- **Response 200:**

```json
{
  "events": [
    {
      "fingerprint": "0x1A2B3C4D5E6F7081",
      "t1_ns": 1761260000123000000,
      "match_state": "unmatched",
      "deadline_ns": 1761260000623000000,
      "scope": "between probe 1 and probe 2"
    }
  ],
  "stats": { "window_packets": 1842, "unmatched": 4, "late": 1, "loss_rate": 0.00217 }
}
```

- **Notes:** the `scope` field states the honest interpretation — a timeout
  localizes loss only to the segment between observation points.

### `GET /metrics/correlation` — **Proposed**

Correlation engine statistics: throughput, in-flight count, heap/table sizes,
duplicate and collision counters, clock-quality flags.

- **Response 200 (representative):**

```json
{
  "ingestion": { "uptime_s": 3612, "records_per_s": 9850, "connected_probes": 2 },
  "correlation": {
    "in_flight": 4821, "matched_total": 1792003, "unmatched_total": 941,
    "late_total": 88, "duplicates_ignored": 12, "collisions_disambiguated": 0,
    "clock_suspect_flags": 3
  },
  "structures": { "hash_entries": 4821, "heap_entries": 4821, "heap_cap": 200000 }
}
```

## 4. Diagnostics

### `GET /alerts` — **Proposed**

Current (unresolved) diagnostic alerts.

- **Query:** `severity`, `category`, `limit` (default 100), `offset`.
- **Response 200:**

```json
{
  "alerts": [
    {
      "alert_id": 9001,
      "category": "BUFFERBLOAT",
      "severity": "warning",
      "detected_at_ns": 1761260015000000000,
      "metrics": { "delay_trend_ms_per_s": 33.0, "p95_delay_ms": 450.0 },
      "symptom": "Increasing one-way delay (120 → 450 ms over 90 s)",
      "inferred_root_cause": "Sustained queue buildup on an intermediate router",
      "recommended_action": "Enable FQ-CoDel AQM on the bottleneck router",
      "confidence": "medium",
      "evidence_refs": [55231, 55232, 55233]
    }
  ]
}
```

- **Errors:** `422` unknown severity/category filter.

### `GET /alerts/{alert_id}` — **Proposed**

Full alert detail including the correlation records referenced by
`evidence_refs`.

- **Response 200:** the alert object plus `"evidence": [ <correlation record>, ... ]`
  (fields per [data contract §5](data_contract.md)).
- **Errors:** `404` unknown alert ID.

### `GET /alerts/history` — **Proposed**

Resolved and superseded alerts with time-range filtering.

- **Query:** `from_ns`, `to_ns`, `category`, `severity`, `limit`, `offset`.
- **Response 200:** same envelope as `/alerts`, each item additionally
  carrying `resolved_at_ns` and, where applicable, `retracted_by` (e.g. a
  late match).
- **Errors:** `422` invalid time range (`to_ns < from_ns`).

**Diagnostic correctness (server-enforced):** DNS-related alerts are always
`DNS_EXFIL_SUSPECTED` with `confidence` `low` or `medium` and entropy
evidence; no endpoint ever reports "confirmed data theft." Symptom and
inferred root cause are separate fields on every alert.

## 5. Historical storage and analysis

### `GET /history/correlations` — **Proposed**

Paginated correlation records from SQLite, time-range queryable.

- **Query:** `from_ns`, `to_ns`, `match_state`, `min_delay_ms`, `limit`
  (max 500), `offset`.
- **Response 200:**

```json
{
  "total_estimate": 18402,
  "records": [
    {
      "id": 55231, "fingerprint": "0x8F3A2B194E5C0D1A",
      "t1_ns": 1761260000123000000, "t2_ns": 1761260000127000000,
      "delay_ms": 4.0, "match_state": "matched", "flags": 0
    }
  ]
}
```

### `GET /history/flows` — **Proposed** (supplementary analytics)

Flow summaries where flow tracking is enabled. Flows are *analytics*, not
correlation records ([data contract §7](data_contract.md)).

- **Query:** `from_ns`, `to_ns`, `protocol`, `limit`, `offset`.
- **Response 200:** `[{ "flow_id": 12, "five_tuple": "...", "packets": 412, "bytes": 189344, "start_ns": ..., "end_ns": ... }]`

### `GET /history/metrics` — **Proposed**

Aggregated latency/loss buckets for historical charts.

- **Query:** `from_ns`, `to_ns`, `bucket_s` (default 10).
- **Response 200:**

```json
{
  "bucket_s": 10,
  "buckets": [
    { "t_ns": 1761260000000000000, "p50_ms": 3.9, "p95_ms": 6.0, "loss_rate": 0.001, "packets": 98210 }
  ]
}
```

- **Errors:** `422` invalid range/bucket; `413` if the requested range would
  exceed the maximum bucket count (client must widen the bucket).

## 6. Live dashboard — WebSocket, port 8000

### `WS /ws/live` — **Proposed**

Server-push stream of live state to the React dashboard.

**Connection lifecycle:**

- Client connects; server immediately sends a `snapshot` message (current
  stats, probe status, unresolved alerts) then incremental `event` messages.
- Heartbeat: server sends ping every 5 s; client reconnects with exponential
  backoff (1 s → 30 s cap) after any close. On reconnect the client accepts a
  fresh `snapshot` as authoritative (no replay of missed events in v1).
- Payloads are JSON, each with `"type"` and `"schema_version": 1`; client
  rejects unknown types rather than guessing.

**Message types (server → client):**

| `type` | Payload (representative) |
| --- | --- |
| `snapshot` | `{ stats, probes, alerts }` — full current state on connect |
| `latency` | `{ t_ns, delay_ms, fingerprint, p50_ms, p95_ms }` |
| `loss` | `{ t_ns, fingerprint, match_state, deadline_ms, scope }` |
| `probe_status` | `{ probe_id, status, last_heartbeat_ns, clock_offset_ms_estimate }` |
| `alert` | full alert object (§4) |
| `alert_resolved` | `{ alert_id, resolved_at_ns, reason: "late_match" \| "operator" \| "recovered" }` |
| `error` | `{ code, message }` — non-fatal stream notice |

Example:

```json
{ "type": "latency", "schema_version": 1, "t_ns": 1761260000127000000,
  "delay_ms": 4.0, "fingerprint": "0x8F3A2B194E5C0D1A", "p50_ms": 3.8, "p95_ms": 6.2 }
```

**Client → server (v1):** subscribe/unsubscribe to message classes with
optional server-side throttling, e.g.
`{ "type": "subscribe", "schema_version": 1, "classes": ["latency","loss","alert"], "min_interval_ms": 100 }`.
No other client messages are interpreted.

**Rate honesty:** the presentation's "60 FPS" is a **UI rendering target**
(smooth client-side animation). It is not a guarantee of 60 server pushes per
second. The server batches/throttles per the client's `min_interval_ms`
(default 100 ms ⇒ ≤10 pushes/s per class); the dashboard interpolates
client-side for smooth rendering. Measured delivery rates are a Phase 7
benchmark.

## 7. Offline analysis routes (existing, unchanged)

These **Implemented** routes serve the PCAP/PCAPNG replay mode that exists in
the codebase today (single-file analysis, not distributed tracing). They are
kept for offline testing and debugging and are documented here so the two
surface areas are not confused:

| Method & path | Purpose | Errors |
| --- | --- | --- |
| `GET /captures` | List previously analyzed captures | — |
| `POST /captures` | Upload a PCAP/PCAPNG file; runs E1→E4 offline pipeline; returns `{capture_id, packets, flows, statistics}` | `400` empty/invalid file, `500` storage failure |
| `GET /captures/{capture_id}/packets` | Paginated packets (`offset`, `limit` ≤ 500) | `404` unknown capture |
| `GET /captures/{capture_id}/packets/{packet_index}/tree` | Protocol tree (`DecodedPacket`) | `404` |
| `GET /captures/{capture_id}/flows` | Flow list (`limit` ≤ 1000) | `404` |
| `GET /captures/{capture_id}/flows/{flow_id}` | Flow detail with member packet indices | `404` |
| `GET /captures/{capture_id}/statistics` | Per-protocol/flow aggregates | `404` |
| `POST /query` | Filter query, e.g. `ip.src == "10.0.0.1" && tcp.port == 443` | `400` filter syntax, `500` storage |
| `GET /query/fields` | List filterable fields | — |

A future refactor may move these under a `/offline/` prefix; any such change
is a breaking API change requiring docs + client updates in the same PR.

## 8. Conventions (all endpoints)

- **Status codes:** `200` success · `400` malformed request · `404` unknown
  resource · `413` result too large · `422` semantic validation failure ·
  `503` subsystem unavailable · `500` internal (with typed error body).
- **Error body shape:** `{ "detail": "<human-readable>", "code": "<machine>" }`.
- **Times:** all `*_ns` fields are integer nanoseconds since the Unix epoch
  (big-endian on the wire only for TCP records; JSON uses numbers — clients
  needing exact 64-bit values should treat them as strings where their
  runtime cannot represent them; **open question for dashboard parsing**).
- **Pagination:** `limit` + `offset` with server-side caps; `total_estimate`
  may be approximate under live ingestion.
- **Authentication:** none in v1 (deploy-internal service). Any addition of
  auth is a contract change.
- **Versioning:** breaking REST changes bump a `/v2/` prefix; WebSocket uses
  `schema_version`; telemetry uses the preamble/record version nibble
  ([data contract §4](data_contract.md)).
