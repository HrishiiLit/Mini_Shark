# Mini-Shark API Specification & Network Interface Guide

This document is the authoritative specification for all external network interfaces of the Mini-Shark diagnostic system:
* **HTTP REST API (Default Port: `8001`):** Wireshark-parity packet inspection, display filter queries, capture session management, edge probe status, correlation telemetry queries, and diagnostic alerts.
* **WebSocket Live Stream (Default Port: `8001` at `/ws/live`):** Persistent full-duplex stream pushing 1-second metric snapshots, live correlation events, and real-time diagnostic alerts.
* **Server-Sent Events (SSE) Stream (Default Port: `8001` at `/captures/stream`):** Real-time chunked stream of live wire packets.
* **Raw TCP Telemetry Ingestion (Default Port: `9000`):** Binary streaming protocol for distributed edge probes exchanging 16-byte preambles and fixed 24-byte telemetry records.

---

## 1. System Health & Runtime Status

### `GET /health`
Liveness probe for the Mini-Shark API server process.
* **Method:** `GET`
* **Path:** `/health`
* **Authentication:** None
* **Response 200 OK:**
```json
{
  "status": "ok",
  "version": "0.4.0",
  "e3_server": "0.0.0.0:9000",
  "probes_connected": 2,
  "correlation_stats": {
    "matched": 1284,
    "unmatched": 14,
    "late": 2,
    "loss_rate": 0.0108
  }
}
```

### `GET /status`
Full operational status of the central server, active correlation hub, and SQLite database.
* **Method:** `GET`
* **Path:** `/status`
* **Response 200 OK:**
```json
{
  "api_port": 8001,
  "e3_port": 9000,
  "hub_stats": {
    "matched": 1284,
    "unmatched": 14,
    "late": 2,
    "in_flight": 3
  },
  "database": {
    "total_correlations": 1300,
    "matched": 1284,
    "unmatched": 14,
    "late": 2,
    "loss_rate": 0.0108,
    "avg_delay_ms": 3.42,
    "p95_delay_ms": 8.15
  },
  "recent_alerts": [
    {
      "category": "BUFFERBLOAT",
      "severity": "WARNING",
      "confidence": "HIGH"
    }
  ]
}
```

---

## 2. Distributed Probe Management & Telemetry Ingestion

### `GET /probes`
Returns real-time connection status and IP addressing for all connected edge capture probes.
* **Method:** `GET`
* **Path:** `/probes`
* **Response 200 OK:**
```json
{
  "probe1_connected": true,
  "probe1_ip": "192.168.1.15",
  "probe2_connected": true,
  "probe2_ip": "192.168.1.16",
  "router_connected": true,
  "router_ip": "192.168.1.10",
  "active_clients": [
    {
      "ip": "192.168.1.15",
      "probe_id": 11,
      "records": 4820,
      "connected_at": 1732418000.12
    },
    {
      "ip": "192.168.1.10",
      "probe_id": 10,
      "records": 4820,
      "connected_at": 1732418002.45
    },
    {
      "ip": "192.168.1.16",
      "probe_id": 2,
      "records": 4806,
      "connected_at": 1732418001.08
    }
  ],
  "total_connected": 3
}
```

### Telemetry Ingestion — Raw TCP Port `9000`
Probes establish a single persistent TCP connection to the central server on port `9000`.
* **Transport:** Raw TCP socket with `TCP_NODELAY = 1` (Nagle disabled).
* **Connection Lifecycle:**
  1. **Handshake Preamble (16 bytes):** Sent once immediately upon connection:
     * `0..3` (4 B): Magic bytes `b"MSHK"` (`0x4D53484B`).
     * `4` (1 B): Protocol version (`0x01`).
     * `5` (1 B): Record size in bytes (`0x18` = 24).
     * `6..7` (2 B): Reserved (`0x0000`).
     * `8..11` (4 B): Probe clock epoch seconds (uint32).
     * `12..15` (4 B): Reserved (`0x00000000`).
  2. **Streaming Records (24 bytes each):**
     * `0..7` (8 B): 64-bit BLAKE2b invariant packet fingerprint (`uint64`).
     * `8..15` (8 B): Nanosecond epoch capture timestamp $T$ (`uint64`).
     * `16..19` (4 B): Monotonic sequence counter (`uint32`).
     * `20` (1 B): Probe ID (`uint8`, e.g. 11 = Client, 10 = Router, 2 = Server).
     * `21` (1 B): Type flags (`uint8`, bitmask: type nibble | version nibble `0x11`).
     * `22..23` (2 B): Captured packet length in bytes (`uint16`).
  3. **Batching:** Probes buffer up to 50 records (`1,200` bytes payload $\le$ 1500 Ethernet MTU) or flush after `20 ms`.
  4. **Keepalive:** Heartbeat packet (`type_flags = 0x13`) sent if idle for $> 5$ seconds.

### `POST /correlations/ingest`
Manually injects one 24-byte `ProbeTelemetry` record (used for synthetic testing, lab verification, or replaying raw records).
* **Method:** `POST`
* **Path:** `/correlations/ingest?hex_record=<48_hex_chars>`
* **Query Parameters:**
  * `hex_record` (string, required): 24 bytes formatted as 48 hex characters.
* **Response 200 OK:**
```json
{
  "result": "correlated",
  "record": {
    "fingerprint": "0x8F3A2B194E5C0D1A",
    "match_state": "matched",
    "delay_ms": 3.42,
    "t1_ns": 1732418000100000000,
    "t2_ns": 1732418000103420000,
    "probe1_seq": 104,
    "probe2_seq": 104,
    "drop_link": null
  }
}
```

---

## 3. Wireshark-Parity Offline Captures & Inspection

### `GET /captures`
Lists all stored PCAP/PCAPNG capture sessions.
* **Method:** `GET`
* **Path:** `/captures`
* **Response 200 OK:** Array of capture metadata objects (`id`, `name`, `timestamp`, `packet_count`, `flow_count`).

### `POST /captures`
Uploads a PCAP or PCAPNG trace file, executes the full pipeline ($E1 \to E2 \to E3 \to E4$), commits records to SQLite WAL, runs automated diagnostics, and returns session statistics.
* **Method:** `POST`
* **Path:** `/captures`
* **Content-Type:** `multipart/form-data`
* **Form Field:** `file` (binary PCAP/PCAPNG file)
* **Response 200 OK:**
```json
{
  "capture_id": 1,
  "packets": 500,
  "flows": 24,
  "statistics": {
    "total_packets": 500,
    "total_bytes": 328400,
    "protocols": { "TCP": 420, "UDP": 60, "DNS": 20 }
  },
  "alerts": []
}
```

### `GET /captures/{capture_id}/packets`
Paginated retrieval of raw packets in a capture session.
* **Method:** `GET`
* **Path:** `/captures/{capture_id}/packets?offset=0&limit=50`
* **Query Parameters:**
  * `offset` (int, default: 0): Starting packet index.
  * `limit` (int, default: 50, max: 500): Number of packets to retrieve.
* **Response 200 OK:**
```json
{
  "offset": 0,
  "count": 50,
  "packets": [
    {
      "index": 0,
      "timestamp": 1732418000.124581,
      "length": 1514,
      "raw_bytes_hex": "001a2b3c4d5e..."
    }
  ]
}
```

### `GET /captures/{capture_id}/packets/{packet_index}/tree`
Fetches the fully dissected protocol tree for a specific packet.
* **Method:** `GET`
* **Path:** `/captures/{capture_id}/packets/{packet_index}/tree`
* **Response 200 OK:**
```json
{
  "packet_index": 0,
  "layers": [
    {
      "name": "Ethernet",
      "fields": {
        "src_mac": "00:5f:4e:3d:2c:1b",
        "dst_mac": "00:1a:2b:3c:4d:5e",
        "ethertype": 2048
      }
    },
    {
      "name": "IPv4",
      "fields": {
        "src": "192.168.1.15",
        "dst": "192.168.1.16",
        "proto": 6,
        "ttl": 64,
        "id": 48120
      }
    },
    {
      "name": "TCP",
      "fields": {
        "src_port": 54210,
        "dst_port": 8000,
        "seq": 10001,
        "ack": 0,
        "flags": 2
      }
    }
  ]
}
```

### `GET /captures/{capture_id}/inspector`
Returns a unified Wireshark-style summary table including decoded protocol layers and formatted info strings for fast frontend rendering.
* **Method:** `GET`
* **Path:** `/captures/{capture_id}/inspector?offset=0&limit=100`

### `GET /captures/{capture_id}/flows`
Retrieves aggregated 5-tuple conversations.
* **Method:** `GET`
* **Path:** `/captures/{capture_id}/flows?limit=100`

### `GET /captures/{capture_id}/flows/{flow_id}`
Retrieves detailed metrics for a single 5-tuple conversation (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_count`, `byte_count`, `duration`).

### `GET /captures/{capture_id}/statistics`
Retrieves protocol distribution, packet count, and bandwidth statistics.

---

## 4. Wireshark Display Filter Engine

### `POST /query`
Evaluates a Wireshark display filter expression against stored conversations.
* **Method:** `POST`
* **Path:** `/query`
* **Content-Type:** `application/json`
* **Request Body:**
```json
{
  "filter": "ip.src == 192.168.1.15 && tcp.port == 8000",
  "capture_id": 1
}
```
* **Supported Operators:** `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `and`, `||`, `or`, `!`, `not`.
* **Supported Atoms:** `tcp`, `udp`, `dns`, `http`, `icmp`, `arp`, `ip.src`, `ip.dst`, `ip.addr`, `tcp.port`, `udp.port`, `dns.qry.name`.
* **Response 200 OK:**
```json
{
  "count": 3,
  "flows": [
    {
      "flow_id": 4,
      "five_tuple": ["192.168.1.15", "192.168.1.16", 54210, 8000, "TCP"],
      "packet_count": 142,
      "byte_count": 94820,
      "duration": 4.12
    }
  ]
}
```

### `GET /query/fields`
Returns all supported filterable field identifiers.
* **Method:** `GET`
* **Path:** `/query/fields`
* **Response 200 OK:**
```json
{
  "fields": [
    "ip.src", "ip.dst", "ip.addr", "ip.proto", "ip.id", "ip.ttl",
    "tcp.port", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.flags",
    "udp.port", "udp.srcport", "udp.dstport", "udp.length",
    "dns.qry.name", "dns.qry.type", "http.method", "http.uri", "http.status_code"
  ]
}
```

---

## 5. Live Capture & Real-Time Streams

### `GET /interfaces`
Lists all available local network adapters for live capture.
* **Method:** `GET`
* **Path:** `/interfaces`
* **Response 200 OK:**
```json
[
  { "name": "\\Device\\NPF_{GUID} (Wi-Fi)", "description": "Intel(R) Wi-Fi 6 AX201 160MHz" },
  { "name": "\\Device\\NPF_{GUID} (Ethernet)", "description": "Realtek Gaming GbE Family Controller" }
]
```

### `GET /captures/live`
Executes an active live packet capture session for `timeout` seconds.
* **Method:** `GET`
* **Path:** `/captures/live?timeout=30&iface=Wi-Fi&bpf_filter=tcp&persist=true`
* **Response 200 OK:** Full capture summary with extracted fingerprints, Shannon entropy values, and diagnostic alerts.

### `GET /captures/stream` (SSE Live Wire Stream)
Server-Sent Events (SSE) stream pushing live packets in real-time as they cross the wire.
* **Method:** `GET`
* **Path:** `/captures/stream?iface=auto&bpf_filter=tcp`
* **Media Type:** `text/event-stream`
* **Event Structure:**
  * First Event:
    ```json
    data: {"type": "started", "interface": "Wi-Fi", "session_id": "c7a8b3d1-..."}
    ```
  * Subsequent Events:
    ```json
    data: {
      "type": "packet",
      "index": 12,
      "timestamp": 1732418005.124,
      "src": "192.168.1.15",
      "dst": "192.168.1.16",
      "protocol": "TCP",
      "length": 1420,
      "info": "Seq=10001 [ACK]",
      "fingerprint": "0x8F3A2B194E5C0D1A"
    }
    ```

### `GET /captures/stream/stop`
Terminates an active SSE stream session.
* **Method:** `GET`
* **Path:** `/captures/stream/stop?session_id=<UUID>`

---

## 6. Live WebSocket & Multi-Point Correlation Telemetry

### `WS /ws/live`
Full-duplex WebSocket connection used by the React + Three.js dashboard.
* **Endpoint:** `ws://<SERVER_IP>:8001/ws/live`
* **Pushed Message Types:**
  1. **`metrics` (Sent every 1.0 s):**
     ```json
     {
       "type": "metrics",
       "timestamp": 1732418010.5,
       "stats": {
         "matched": 1284,
         "unmatched": 14,
         "late": 2,
         "loss_rate": 0.0108,
         "avg_delay_ms": 3.42,
         "p95_delay_ms": 8.15
       },
       "probes": {
         "probe1_connected": true,
         "probe2_connected": true,
         "router_connected": true,
         "total_connected": 3
       },
       "recent_alerts": []
     }
     ```
  2. **`correlation` (Pushed instantaneously per matched/unmatched flight):**
     ```json
     {
       "type": "correlation",
       "record": {
         "fingerprint": "0x8F3A2B194E5C0D1A",
         "match_state": "unmatched",
         "delay_ms": null,
         "t1_ns": 1732418000100000000,
         "t2_ns": null,
         "drop_link": "link_1",
         "flags": 0
       }
     }
     ```
  3. **`alert` (Pushed when an anomaly rule triggers):**
     ```json
     {
       "type": "alert",
       "category": "BUFFERBLOAT",
       "severity": "WARNING",
       "confidence": "HIGH",
       "recommended_action": "Inspect router queue length; enable fq_codel or reduce buffer size.",
       "metrics": { "p95_delay_ms": 68.2, "jitter_ms": 24.5 }
     }
     ```

### `GET /correlations`
Queries stored cross-probe correlation records.
* **Method:** `GET`
* **Path:** `/correlations?match_state=matched&limit=50&offset=0`
* **Query Parameters:**
  * `match_state` (`matched`, `unmatched`, `late`, `probe2_only`).

### `GET /correlations/stats`
Returns aggregate correlation statistics for the active session.

---

## 7. Diagnostic Alerts

### `GET /alerts`
Lists stored diagnostic alerts flagged by automated incident detection rules.
* **Method:** `GET`
* **Path:** `/alerts?category=PACKET_LOSS&limit=50&offset=0`
* **Supported Categories:** `PACKET_LOSS`, `BUFFERBLOAT`, `APP_FREEZE`, `DNS_EXFIL_SUSPECTED`.

### `POST /alerts/diagnose`
Forces execution of all four diagnostic rules across all current flows and correlation records.
* **Method:** `POST`
* **Path:** `/alerts/diagnose?capture_id=1`
* **Response 200 OK:**
```json
{
  "alerts_generated": 1,
  "alerts": [
    {
      "category": "PACKET_LOSS",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "detected_at_ns": 1732418020100000000,
      "recommended_action": "Verify physical Link 1 cabling or check intermediate switch drop counters.",
      "metrics": { "drop_rate": 0.082 }
    }
  ]
}
```
