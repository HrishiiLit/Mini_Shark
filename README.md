# 🦈 Mini-Shark · Network Protocol Analyzer

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20Uvicorn-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Wireshark_Spec-100%25_Compliant-brightgreen.svg)]()

> **Mini-Shark** is a high-performance network protocol analyzer and deep packet inspection tool built strictly to official **Wireshark** specifications. It provides real-time packet capture, multi-layer protocol dissection, Wireshark-style 3-pane inspection, display filtering, bi-directional TCP stream reconstruction, and network statistics—running completely locally on a single laptop with zero external cloud dependencies.

---

## 🌟 Key Features

### 1. Classic Wireshark 3-Pane Inspection Architecture
- **Pane 1 (Packet List Table):** High-throughput scrollable table displaying Packet No., Relative Arrival Time, Source IP, Destination IP, Protocol, Length, and Info Summary. Fully color-coded matching official Wireshark protocol palette (TCP purple, HTTP green, DNS blue, UDP cyan, ICMP pink, ARP yellow, TLS slate, DHCP peach).
- **Pane 2 (Protocol Details Tree):** Hierarchical, expandable protocol tree allowing drilling into Frame, Ethernet II, IPv4/IPv6, Transport, and Application layer fields.
- **Pane 3 (Packet Bytes Hex & ASCII Dump):** Standard 16-byte offset hex dump side-by-side with printable ASCII characters. Includes **synchronized hover highlighting**—hovering any header field in Pane 2 highlights the exact corresponding byte slice in Pane 3.

### 2. Multi-Layer Protocol Dissection (Engine E2)
- **Link Layer:** Ethernet II (Source/Destination MAC, EtherType `0x0800`, `0x0806`, `0x86dd`).
- **Network Layer:**
  - **IPv4:** Version, IHL, DSCP/ECN, Total Length, Identification, Flags (DF, MF), TTL, Protocol, Header Checksum, Source/Destination IP.
  - **IPv6:** Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, 128-bit IPv6 addressing.
  - **ARP:** Hardware/Protocol type, Opcode (Request `1` vs Reply `2`), Sender MAC/IP, Target MAC/IP.
- **Transport Layer:**
  - **TCP:** Source/Destination Ports, 32-bit Sequence & Acknowledgment numbers, Header Length, Flags breakdown (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), Window Size, Checksum.
  - **UDP:** Source/Destination Ports, Length, Checksum.
  - **ICMP:** Type, Code, Identifier, Sequence Number, Ping Echo Request/Reply tracking.
- **Application Layer:**
  - **DNS:** Transaction ID, Flags, Queries, Answers, and **Shannon Entropy** calculation on queried domain names to detect algorithmic DNS tunneling and data exfiltration.
  - **HTTP/1.x:** Request methods (`GET`, `POST`), Request URIs, Response Status Codes (`200 OK`, `404 Not Found`), Request/Response Headers, and Payload extraction.
  - **TLS (HTTPS):** TLS Record Layer, Version (`TLS 1.2`, `TLS 1.3`), Content Type, and Handshake Type inspection (`Client Hello`, `Server Hello`, `Certificate`).
  - **DHCP (BOOTP):** DORA exchange cycle (`Discover`, `Offer`, `Request`, `ACK`), Transaction ID, Client MAC (`chaddr`), Offered IP (`yiaddr`), Subnet, Gateway, and DNS options.

### 3. "Follow TCP Stream" Bi-directional Reconstruction (Wireshark §8)
- Reconstructs complete application-layer conversations between client and server across captured frames.
- Distinguishes traffic directions with visual color coding: **Client &rarr; Server in RED** and **Server &rarr; Client in BLUE**.
- Displays total stream byte counts, packet counts, and provides a one-click **"Filter to this Stream"** button.

### 4. Advanced Display Filter Engine (Wireshark §6 & §23)
Supports standard Wireshark display filter syntax with instant visual validation feedback (green glow for valid, red for invalid):
- **Protocol Filters:** `tcp`, `udp`, `http`, `dns`, `icmp`, `arp`, `tls`, `dhcp`
- **IP Filters:** `ip.addr == 192.168.1.1`, `ip.src == 10.0.0.5`, `ip.dst == 8.8.8.8`
- **Port Filters:** `tcp.port == 443`, `udp.port == 53`, `tcp.port == 80`
- **TCP Flags:** `tcp.flags.syn == 1`, `tcp.flags.reset == 1`, `tcp.flags.ack == 1`
- **Frame Lengths:** `frame.len > 100`, `frame.len <= 1514`, `frame.len == 64`
- **Performance / Troubleshooting:** `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack`
- **Logical Operators:** `and` (`&&`), `or` (`||`), `not` (`!`)

### 5. Comprehensive Statistics & Traffic Visualization (Wireshark §15, §17, §18)
- **Tab 1 - Protocol Hierarchy:** Breakdown of traffic percentages by protocol (packet count, byte count, % share).
- **Tab 2 - Conversations & Endpoints:** 5-tuple communication pairs (IP A, Port A &harr; IP B, Port B) and Top Talker endpoint hosts.
- **Tab 3 - I/O Graphs & Packet Lengths:** Live SVG packet-per-second throughput graph over time slices alongside standard Wireshark packet size distribution histograms (`<64B`, `64-127B`, `128-255B`, `256-511B`, `512-1023B`, `1024-1514B`, `>1514B`).
- **Tab 4 - Expert Information:** Color-coded severity tiers (**🔴 Error**, **🟡 Warning**, **🔵 Note**, **⚪ Chat**) highlighting TCP anomalies, resets, retransmissions, and high-entropy DNS queries, with one-click filtering.

### 6. Packet Marking & Capture Export (Wireshark §20)
- **Packet Marking (★):** Flag important packets for investigative review; marked frames stand out with gold stars and highlighted backgrounds.
- **Capture Export:** Download captured frames directly as structured JSON or formatted text summary.
- **PCAP Import:** Open and inspect offline `.pcap` or `.pcapng` capture files.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- (Optional for raw live wire sniffing) Npcap on Windows or libpcap on Linux

### Installation
```bash
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
pip install -r requirements.txt
```

### Running Mini-Shark
Launch the application:
```bash
python run_minishark.py
```
Open your web browser and navigate to:
```
http://localhost:8001
```

---

## 📁 Repository Structure

```
Mini_Shark/
├── backend/
│   ├── api/
│   │   └── routes.py             # FastAPI SSE capture, REST endpoints, and inspector
│   ├── e1_capture/
│   │   ├── engine.py             # PCAP ingestion & packet buffer storage
│   │   └── live.py               # Live network adapter sniffing engine
│   ├── e2_dissection/
│   │   ├── engine.py             # Multi-layer packet dissector engine
│   │   ├── protocols.py          # Eth, IP, ARP, TCP, UDP, ICMP, DNS, HTTP, TLS, DHCP dissectors
│   │   └── registry.py           # Protocol dissector dispatch registry
│   ├── e3_flows/                 # 5-tuple conversation flow tracking
│   ├── e4_query/                 # Statistics, throughput metrics & anomaly diagnostics
│   ├── static/
│   │   └── index.html            # Wireshark 3-Pane UI, Follow Stream modal, & Stats
│   ├── main.py                   # FastAPI server entrypoint
│   └── models.py                 # Core Packet & Layer data models
├── tests/                        # Comprehensive unit & integration test suite
├── run_minishark.py              # Single-command launcher
├── requirements.txt              # Project dependencies
└── README.md                     # Documentation
```

---

## 👥 Authors & Academic Attribution
- **Mini-Shark Project Team (Team 07)** · KLE Technological University
- Built in accordance with standard Network Protocol & Wireshark specifications.
