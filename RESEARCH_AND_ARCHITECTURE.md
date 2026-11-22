# Mini-Shark: Single-Laptop Research & Architecture Blueprint

**Project:** 23ECNP301 — Mini-Project (Team 07, CSE-AI)  
**Artefact:** Live Network Packet Capture and Protocol Analysis Tool ("Mini-Shark")  
**Guide:** Prof. Pooja Shettar  
**Target Workspace:** `D:\Sem_5\CNS\CN_Lab\mini_project\Mini_Shark`  

---

## 1. Academic & Engine Register Alignment

Based on the verified curriculum document `Team07_S2_revised.docx`, Mini-Shark is partitioned into four student-owned engines:

| Engine | Name | Student Owner | Core Function | Algorithmic Paradigm |
| :--- | :--- | :--- | :--- | :--- |
| **E1** | **Capture & Ingestion** | **Student A** (M Janaki, `01fe24bci067`) | Captures live wire packets, timestamps with nanosecond precision, assigns sequential IDs, and buffers. | Producer-Consumer Queue + Bounded Buffer |
| **E2** | **Protocol Analysis & Packet Dissection** | **Student B** (Chhavi Mishra, `01fe24bci066`) | Layered protocol decoder down to L7; extracts fields, computes protocol tree, and maps exact byte-offset ranges. | Layered Recursive Dissector + Shannon Entropy |
| **E3** | **Filtering & Query** | **Student C** (Hrishikesh Patil, `01fe24bci043`) | Parses display filters (e.g. `tcp.port == 80 && ip.src == 192.168.1.1`) and selects matching packets. | Lexer + Recursive-Descent AST + Expression Tree |
| **E4** | **Statistics, Flow & Expert Analysis** | **Student D** (Vaibhav Kumar, `01fe24bci0...`) | Aggregates 5-tuple bidirectional conversations, computes bandwidth/packet stats, and detects TCP/DNS anomalies. | Hash-Map Flow Tracker + TCP State Machine |

```mermaid
graph TD
    NIC["Network Interface / PCAP File"] -->|Raw Bytes| E1["E1: Capture & Ingestion (Producer-Consumer Queue)"]
    E1 -->|Raw Frame + Timestamp + ID| E2["E2: Protocol Analysis & Dissection (L2-L7 Tree + Byte Offsets)"]
    E2 -->|Decoded Fields & Protocol Tree| E3["E3: Filtering & Query (Lexer + AST Expression Tree)"]
    E2 -->|Decoded L4/L7 Metadata| E4["E4: Flows, Statistics & Expert Diagnostics (5-Tuple + TCP State)"]
    E3 -->|Filtered Packets| UI["Wireshark 3-Pane UI (Table / Tree / Hex Dump)"]
    E4 -->|Flows, Stats & Expert Warnings| UI
    E1 & E2 & E3 & E4 -->|Batched Async WAL| DB[("SQLite Database mini_shark.db")]
```

---

## 2. Why & How Mini-Shark Works on a Single Laptop

In a multi-host physical lab, testing requires 4 physical machines, routing tables, and NTP clock synchronization. Running Mini-Shark **on a single laptop** provides an immediate, robust environment for academic evaluation, code defense, and feature demonstration.

### Three Capture Modes on One Machine
1. **Live Interface Sniffing (Wi-Fi / Ethernet)**:
   - On Windows: Scapy + Npcap (`\Device\NPF_{GUID}`) in promiscuous or non-promiscuous mode.
   - On Linux: Zero-dependency raw `AF_PACKET` sockets (`socket(AF_PACKET, SOCK_RAW, htons(0x0003))`).
   - Captures real local applications (web browsing, DNS queries, Spotify, YouTube).
2. **Offline PCAP / PCAPNG Replay**:
   - Ingests standard `.pcap` files via binary parser (`struct.unpack_from` for Global and Packet Headers).
   - Guarantees 100% deterministic reproducibility for lab vivas without requiring active internet.
3. **Local Synthetic Traffic Injection**:
   - An integrated script generating controlled HTTP GET/POST, DNS query spikes, ICMP pings, and high-entropy DNS tunneling simulations (`base64` encoded subdomain labels) directly against `127.0.0.1` or the local gateway.

---

## 3. Deep Packet Inspection (DPI) & Wireshark Parity

Wireshark’s dissector architecture relies on two core data structures:
* `tvbuff_t` (*Testy Virtual Buffer*): A bounded byte array slice with safe bounds checking.
* `proto_tree`: A hierarchical tree where each node references the exact `(start_offset, length)` inside the raw packet bytes.

### Mini-Shark Dissection Architecture

To achieve true Wireshark parity, each protocol layer returns:
1. `name`: Protocol name (e.g., `IPv4`, `TCP`, `DNS`).
2. `fields`: Key-value dictionary of dissected fields.
3. `field_spans`: Dictionary mapping each field name to its exact byte range `(start_offset, length)` within the raw Ethernet frame.
4. `undecoded_bytes`: Trailing payload bytes passed to the next dissector in the dispatch chain.

```text
Raw Packet Frame (14 + 20 + 20 + Payload bytes):
[ 0 .. 13 ]  Ethernet II Header     -> dst_mac [0:6], src_mac [6:12], ethertype [12:14]
[ 14 .. 33 ] IPv4 Header           -> ver_ihl [14], total_len [16:18], id [18:20], ttl [22], proto [23], src [26:30], dst [30:34]
[ 34 .. 53 ] TCP Header            -> sport [34:36], dport [36:38], seq [38:42], ack [42:46], flags [47:48], win [48:50]
[ 54 .. N  ] HTTP / DNS / Payload   -> payload bytes
```

### Supported Protocol Hierarchy
* **Layer 2 (Data Link)**:
  - **Ethernet II**: Destination MAC, Source MAC, EtherType (`0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP, `0x8100` VLAN).
  - **ARP**: Hardware Type, Protocol Type, Opcode (Request `1`, Reply `2`), Sender MAC/IP, Target MAC/IP.
* **Layer 3 (Network)**:
  - **IPv4**: Version, IHL, DSCP/ECN, Total Length, Identification, Flags (DF, MF), Fragment Offset, TTL, Protocol, Header Checksum, Source IP, Destination IP.
  - **IPv6**: Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, Source/Destination IPv6.
* **Layer 4 (Transport)**:
  - **TCP**: Source Port, Destination Port, Sequence Number, Acknowledgment Number, Data Offset, Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`), Window Size, Checksum, Urgent Pointer.
  - **UDP**: Source Port, Destination Port, Length, Checksum.
  - **ICMP / ICMPv6**: Type, Code, Checksum, Identifier, Sequence Number (for Echo Request `8` / Echo Reply `0`).
* **Layer 7 (Application)**:
  - **DNS (UDP/TCP 53)**: Transaction ID, Flags (QR, Opcode, AA, TC, RD, RA, RCODE), QDCount, ANCount. Recursive DNS label parser supporting name pointer decompression (`0xC0` offset jump). Computes Shannon entropy $H(X) = -\sum p(b) \log_2 p(b)$ on query names.
  - **HTTP/1.x (TCP 80, 8080, 8000)**: Request/Status line parsing, HTTP Method (`GET`, `POST`, `PUT`, `DELETE`), Request URI, HTTP Version, Headers map, Content-Length.
  - **TLS (TCP 443)**: Handshake Content Type (`0x16`), Handshake Type (`0x01` Client Hello), TLS Version (`0x0303`), SNI (*Server Name Indication*) extension extraction allowing identification of the encrypted destination domain.

---

## 4. Engine E3: Lexer & Expression Tree Query Engine

Engine E3 implements a recursive-descent parser that parses Wireshark-style display filters into an Abstract Syntax Tree (AST), supporting both fast in-memory filtering of live packet streams and SQL compilation for stored sessions.

### Formal Grammar (EBNF)
```ebnf
Expression   := OrExpr
OrExpr       := AndExpr ( ("||" | "or") AndExpr )*
AndExpr      := NotExpr ( ("&&" | "and") NotExpr )*
NotExpr      := ("!" | "not") NotExpr | Primary
Primary      := "(" Expression ")" | Comparison | BareProtocol
Comparison   := FieldName Op Literal
Op           := "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains" | "startswith" | "endswith" | "in"
BareProtocol := "tcp" | "udp" | "icmp" | "dns" | "http" | "arp" | "ip"
```

---

## 5. Engine E4: Statistics, Flow & Expert Analysis

### 1. Canonical 5-Tuple Flow Aggregation
Conversations are grouped using an invariant bidirectional key:
$$\text{Endpoint}_1 = (\text{IP}_A, \text{Port}_A), \quad \text{Endpoint}_2 = (\text{IP}_B, \text{Port}_B)$$
$$\text{FlowKey} = \Big(\min(\text{Endpoint}_1, \text{Endpoint}_2), \; \max(\text{Endpoint}_1, \text{Endpoint}_2), \; \text{Protocol}\Big)$$

Each flow computes:
- Packet count and total byte volume
- Flow start timestamp, end timestamp, and total duration ($\Delta t$)
- Instantaneous throughput ($\text{bps}$, $\text{pps}$)

### 2. TCP State Machine & Expert Diagnostics
E4 monitors packet sequences within each flow to detect network degradation:
* **TCP Retransmission**: A packet arrives with the same `(Seq, Length)` as a previously observed packet.
* **Out-of-Order Packet**: A packet arrives with $\text{Seq} < \text{NextExpectedSeq}$.
* **TCP ZeroWindow**: A receiver advertises $\text{Window} = 0$, indicating buffer saturation.
* **TCP Reset / Abnormal Teardown**: An unexpected `RST` flag terminating a connection.
* **DNS Tunneling / Data Exfiltration**: Query name Shannon entropy $H > 4.2$ bits per character.

---

## 6. Database Schema (SQLite WAL Mode)

In strict accordance with Chapter 4 (Database Design) of `Team07_S2_revised.docx`:

```sql
CREATE TABLE IF NOT EXISTS capture_sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time REAL NOT NULL,
    end_time REAL,
    interface TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
    packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    packet_index INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    length INTEGER NOT NULL,
    raw_data BLOB NOT NULL,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS packet_fields (
    field_id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    field_name TEXT NOT NULL,
    field_value TEXT NOT NULL,
    FOREIGN KEY(packet_id) REFERENCES packets(packet_id)
);

CREATE TABLE IF NOT EXISTS flows (
    flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    src_endpoint TEXT NOT NULL,
    dst_endpoint TEXT NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 1,
    byte_count INTEGER NOT NULL DEFAULT 0,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    duration REAL,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(session_id)
);
```

---

## 7. Phased Implementation Roadmap for `D:\Sem_5\CNS\CN_Lab\mini_project\Mini_Shark`

```text
Mini_Shark/
├── backend/
│   ├── e1_capture/       # [Student A] Live capture, Queue & PCAP parser
│   ├── e2_dissection/    # [Student B] L2-L7 Dissectors + Byte Span Offsets
│   ├── e3_filtering/     # [Student C] Lexer, AST Parser & Filter Evaluator
│   ├── e4_expert/        # [Student D] 5-Tuple Flows, Stats & TCP Expert
│   ├── storage/          # SQLite WAL repository (4 schema tables)
│   ├── api/              # FastAPI REST endpoints & WebSocket streamer
│   └── main.py           # Single-laptop server orchestrator
├── frontend/             # Wireshark 3-Pane UI (Table + Tree + Synchronized Hex)
├── scripts/              # Local multi-protocol traffic generator
├── tests/                # Comprehensive unit test suite (E1 to E4)
└── run_minishark.py      # One-click launcher for single laptop
```

* **Step 1 (E1 & Storage)**: Build the capture engine with producer-consumer queue and SQLite WAL session persistence.
* **Step 2 (E2 Dissection)**: Implement zero-copy byte-offset protocol dissection (Ethernet, ARP, IPv4/6, TCP/UDP/ICMP, DNS, HTTP, TLS) with Shannon entropy.
* **Step 3 (E3 Filtering)**: Build the lexer, AST parser, and evaluator for display filters.
* **Step 4 (E4 Flows & Expert)**: Build the 5-tuple flow aggregator and TCP anomaly diagnostic engine.
* **Step 5 (API & Wireshark UI)**: Serve the 3-pane UI with synchronized hex byte highlighting and real-time WebSocket packet streaming.
* **Step 6 (Verification)**: Run synthetic multi-protocol traffic and verify end-to-end functionality.
