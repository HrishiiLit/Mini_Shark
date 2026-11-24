# Data Contract — Mini-Shark Distributed Tracing & Protocol Analysis

This document defines every data structure and interface shared between the four engines (E1 – E4). It is the single source of truth for engine boundaries.

Two foundational rules apply throughout:
1. **A network flow and a cross-probe correlation are distinct concepts.** The 5-tuple `Flow` model represents bidirectional conversations for traffic analytics, whereas `CorrelationRecord` models the cross-probe flight of an individual packet across distributed vantage points.
2. **Fingerprints are derived, path-invariant digests.** The 64-bit fingerprint is computed from immutable packet headers by E2 using BLAKE2b-64, enabling accurate matching even across routers where TTL, checksums, and MAC addresses are rewritten.

---

## 1. Packet & CapturedPacket (E1 → E2)

A raw wire frame observed by an edge probe or read from an offline capture.
* **Implemented in:** [`backend/models.py`](../backend/models.py) as `Packet`.

| Field | Type | Required | Meaning & Validation |
| :--- | :--- | :---: | :--- |
| `index` | `int` | Yes | Monotonically increasing sequential index (0, 1, 2, ...). |
| `timestamp` | `float` | Yes | Capture timestamp in epoch seconds (microsecond or nanosecond resolution). |
| `length` | `int` | Yes | Total wire length of the frame in bytes. |
| `raw_bytes` | `bytes` | Yes | Raw frame bytes from the link layer up (Ethernet II frame). |

* **Live Probe Context:** In the distributed probe runtime (`run_probe.py`), each packet also carries an associated `probe_id` (uint8: 11 = Client, 10 = Router, 2 = Server) and a monotonic sequence counter `seq` (uint32).

---

## 2. DecodedPacket & Layer (E2 Internal & E2 → E3/E4)

Hierarchical representation of a decoded packet.
* **Implemented in:** [`backend/models.py`](../backend/models.py) as `Layer` and `DecodedPacket`.

### `Layer`
| Field | Type | Meaning |
| :--- | :--- | :--- |
| `name` | `str` | Protocol name (`Ethernet`, `VLAN`, `ARP`, `IPv4`, `IPv6`, `TCP`, `UDP`, `ICMP`, `DNS`, `HTTP`, `TLS`, `DHCP`). |
| `fields` | `dict[str, Any]` | Parsed protocol header fields (e.g. `src`, `dst`, `seq`, `ack`, `flags`). |
| `undecoded_bytes` | `bytes` | Trailing payload passed to downstream dissectors. |

### `DecodedPacket`
| Field | Type | Required | Meaning |
| :--- | :--- | :---: | :--- |
| `packet_index` | `int` | Yes | Reference to originating `Packet.index`. |
| `layers` | `list[Layer]` | Yes | Ordered protocol layers from link layer up to application layer. |
| `fingerprint` | `PacketFingerprint` | Optional | Path-invariant 64-bit digest (None if packet has no IP layer). |
| `dns_entropy` | `float` | Optional | Shannon entropy $H(X)$ of the first DNS query name (None if not DNS). |

---

## 3. PacketFingerprint (E2 → E3)

A stable 64-bit digest derived from path-invariant header fields.
* **Implemented in:** [`backend/models.py`](../backend/models.py).

| Field | Type | Required | Meaning |
| :--- | :--- | :---: | :--- |
| `algorithm` | `str` | Yes | Constant `"blake2b-64"` (`hashlib.blake2b(digest_size=8)`). |
| `version` | `int` | Yes | Field-set version (1 = initial field set). |
| `value` | `int` | Yes | Unsigned 64-bit integer (`uint64`). |
| `fields_used` | `list[str]` | Yes | List of fields hashed (e.g. `["ip.src", "ip.dst", "ip.proto", "ip.id", "tcp.seq"]`). |

### Path-Invariant Hashing Rules (Version 1)
* **Fields Hashed:**
  * IPv4: `src`, `dst`, `proto`, `id`
  * IPv6: `src`, `dst`, `next_header`
  * TCP: `src_port`, `dst_port`, `seq`, `ack`, payload prefix
  * UDP: `src_port`, `dst_port`, `length`, payload prefix
  * ICMP: `type`, `code`
* **Fields Explicitly Excluded (Hop-Mutable):**
  * Time-to-Live / Hop Limit (decremented at every L3 hop).
  * MAC addresses (rewritten by every router).
  * IP Header Checksum & TCP/UDP Checksums (recalculated when TTL decrements).
  * DSCP / ECN flags (may be remarketed by QoS queues).

---

## 4. ProbeTelemetry & Handshake Wire Formats (E2 → E3 over TCP :9000)

* **Implemented in:** [`backend/models.py`](../backend/models.py) as `ProbeTelemetry` and `TelemetryPreamble`.

### 4.1. 16-Byte Connection Preamble (`TelemetryPreamble`)
Sent once immediately when a probe connects to TCP port `9000`:

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Magic ("MSHK" = 0x4D53484B)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  | Rec Size (24) |            Reserved (0x0000)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Probe Clock Epoch (seconds, uint32)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Reserved (0x00000000)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2. Fixed 24-Byte Wire Record (`ProbeTelemetry`, Struct: `!QQIBBH`)
Streamed continuously for each captured packet:

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     64-bit Fingerprint (uint64)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  64-bit Timestamp ns (uint64)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     32-bit Sequence No (uint32)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Probe ID (u8) | Type/Ver (u8) |    Captured Length (uint16)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* **Batching:** Probes queue up to **50 records** (`1,200` bytes payload $\le 1,500$ MTU) or flush after **`20 ms`**.
* **Transport:** Nagle disabled (`TCP_NODELAY = 1`) to eliminate delayed-ACK buffering.
* **Keepalive:** Heartbeat packet (`type_flags = 0x13`, all other fields 0) transmitted if idle for $> 5$ seconds.

---

## 5. CorrelationRecord (E3 → E4)

Output of the real-time cross-probe correlation engine.
* **Implemented in:** [`backend/models.py`](../backend/models.py).

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `fingerprint` | `int` (uint64) | 64-bit BLAKE2b correlation key. |
| `probe1_observed`| `bool` | True if observed at Ingress Probe 1 / Client. |
| `probe2_observed`| `bool` | True if observed at Egress Probe 2 / Server. |
| `router_observed`| `bool` | True if observed at Transit Probe 10 / Router. |
| `t1_ns` | `int | None` | Ingress capture timestamp (ns since epoch). |
| `t2_ns` | `int | None` | Egress capture timestamp (ns since epoch). |
| `router_ts` | `int | None` | Transit capture timestamp at Router (ns since epoch). |
| `delay_ns` | `int | None` | One-way transit latency $\Delta T = T_2 - T_1$. |
| `match_state` | `str` | `"matched"`, `"unmatched"`, `"late"`, or `"probe2_only"`. |
| `drop_link` | `str | None` | Drop localization: `"link_1"` (Client $\to$ Router), `"link_2"` (Router $\to$ Server), or `None`. |
| `flags` | `int` (uint32) | Bitmask of `CorrelationFlags`: `CLOCK_SKEW_SUSPECT` (1), `COLLISION_DISAMBIGUATED` (2), `DUPLICATE_T2_IGNORED` (8), `CAPACITY_EVICTED` (32). |
| `probe1_seq` | `int | None` | Sequence number from Probe 1. |
| `probe2_seq` | `int | None` | Sequence number from Probe 2. |
| `deadline_ns` | `int` | Expiration deadline in hub time ($T_{\text{receipt}} + 500\text{ ms}$). |
| `created_at_ns`| `int` | Server-side record creation timestamp. |

---

## 6. DiagnosticAlert (E4)

Automated incident alerts generated by deterministic diagnostic rules.
* **Implemented in:** [`backend/models.py`](../backend/models.py).

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `alert_id` | `int | None` | Surrogate primary key in SQLite. |
| `category` | `str` | `"PACKET_LOSS"`, `"BUFFERBLOAT"`, `"APP_FREEZE"`, `"DNS_EXFIL"`. |
| `severity` | `str` | `"INFO"`, `"WARNING"`, `"CRITICAL"`. |
| `confidence` | `str` | `"LOW"`, `"MEDIUM"`, `"HIGH"`. |
| `detected_at_ns`| `int` | Timestamp when rule fired (ns since epoch). |
| `recommended_action`| `str` | Prescribed remediation step. |
| `evidence_refs`| `list[int]` | Associated correlation record / packet indices providing proof. |
| `metrics` | `dict[str, float]`| Numerical metrics observed (e.g. `loss_rate: 0.08`, `delay_ms: 68.2`). |

---

## 7. Flow Model (E3 / E4 Analytics)

Bidirectional conversation grouping.
* **Implemented in:** [`backend/models.py`](../backend/models.py).

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `flow_id` | `int` | Unique flow identifier. |
| `five_tuple` | `tuple` | Normalized `(src_ip, dst_ip, src_port, dst_port, protocol)`. |
| `packet_indices`| `list[int]` | List of packet indices belonging to this flow. |
| `packet_count` | `int` | Total number of packets in the flow. |
| `byte_count` | `int` | Total volume in bytes. |
| `start_ts` | `float` | Timestamp of first packet. |
| `end_ts` | `float` | Timestamp of last packet. |
| `duration` | `float` | Flow lifespan $T_{\text{end}} - T_{\text{start}}$ (seconds). |

---

## 8. Persistence Schema (SQLite WAL Mode: `mini_shark.db`)

* **Implemented in:** [`backend/e4_query/storage.py`](../backend/e4_query/storage.py).

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    timestamp REAL NOT NULL,
    packet_count INTEGER DEFAULT 0,
    flow_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id),
    packet_index INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    length INTEGER NOT NULL,
    raw_bytes BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS layers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id),
    packet_index INTEGER NOT NULL,
    layer_name TEXT NOT NULL,
    fields_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id),
    flow_id INTEGER NOT NULL,
    five_tuple TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    start_ts REAL,
    end_ts REAL,
    duration REAL
);

CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint INTEGER NOT NULL,
    match_state TEXT NOT NULL,
    t1_ns INTEGER,
    t2_ns INTEGER,
    delay_ns INTEGER,
    flags INTEGER DEFAULT 0,
    probe1_seq INTEGER,
    probe2_seq INTEGER,
    created_at_ns INTEGER NOT NULL,
    drop_link TEXT
);

CREATE TABLE IF NOT EXISTS diagnostic_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    detected_at_ns INTEGER NOT NULL,
    recommended_action TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL
);
```
