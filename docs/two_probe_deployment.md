# Mini-Shark — Two-Probe Distributed Deployment Plan

**Project:** Mini-Shark (23ECNP301) · Team 07  
**Guide:** Prof. Pooja Shettar · KLE Technological University  
**Document:** Distributed implementation plan for real two-machine probe deployment  
**Engine owner (E2):** Chhavi Mishra

---

## 1. Overview

Mini-Shark's distributed mode requires **two probe machines** observing the same
network traffic from two different vantage points — one on the client side and one
on the server/gateway side. This document describes exactly how to set up, connect,
and run all four engines across two physical machines on the same local network.

---

## 2. Architecture Recap

```
╔══════════════════════════╗        ╔══════════════════════════╗
║   Machine 1 (Probe 1)    ║        ║   Machine 2 (Probe 2 +   ║
║   CLIENT SIDE            ║        ║   Central Server)        ║
║                          ║        ║                          ║
║  E1: Live packet capture ║        ║  E1: Live packet capture ║
║  E2: Dissect + Fingerprint        ║  E2: Dissect + Fingerprint
║                          ║  TCP   ║                          ║
║  Sends 24-byte telemetry ╠════════╣  Sends 24-byte telemetry ║
║  records → port 9000     ║        ║  records → port 9000     ║
╚══════════════════════════╝        ╚══════════════════════════╝
                                              ║
                                    ╔═════════╩════════════════╗
                                    ║  Central Diagnostic      ║
                                    ║  Server (Machine 2)      ║
                                    ║                          ║
                                    ║  E3: Correlation Hub     ║
                                    ║  · Hash table matching   ║
                                    ║  · Min-heap timeout      ║
                                    ║  · ΔT = T2 − T1          ║
                                    ║                          ║
                                    ║  E4: Diagnostics + DB    ║
                                    ║  · SQLite minishark.db   ║
                                    ║  · FastAPI REST (3000)   ║
                                    ║  · WebSocket live push   ║
                                    ║                          ║
                                    ║  React Dashboard (5173)  ║
                                    ╚══════════════════════════╝
```

---

## 3. Role Assignment

| Role | Machine | Person | What runs |
|------|---------|--------|-----------|
| **Probe 1** | Laptop A (your laptop) | Chhavi | E1 + E2 + probe sender |
| **Probe 2 + Central Server** | Laptop B (teammate's laptop) | Hrishikesh | E1 + E2 + E3 + E4 + Dashboard |
| **Gateway** | Wi-Fi Router | — (passive) | Nothing — just sits between both machines |

> The gateway/router does **not** need any software. Both probes passively
> sniff the traffic passing through the shared Wi-Fi network.

---

## 4. Network Requirements

- Both machines must be on the **same Wi-Fi network** (same router)
- Both machines must be able to **ping each other**
- Machine 2 must **allow inbound TCP on port 9000** (Windows Firewall rule)
- Machine 2 must **allow inbound TCP on port 3000** (for dashboard access)
- **No internet required** — everything runs on the local LAN

### 4.1 Find IP addresses

**On each machine, open PowerShell:**
```powershell
ipconfig
# Note the IPv4 Address — e.g. 192.168.1.10 (Machine 1)
#                               192.168.1.20 (Machine 2)
```

### 4.2 Open firewall ports on Machine 2

Run as Administrator on Machine 2:
```powershell
# Allow E3 telemetry ingestion
netsh advfirewall firewall add rule name="MiniShark E3" dir=in action=allow protocol=TCP localport=9000

# Allow dashboard access from Machine 1
netsh advfirewall firewall add rule name="MiniShark API" dir=in action=allow protocol=TCP localport=3000
```

### 4.3 Verify connectivity

```powershell
# From Machine 1, ping Machine 2
ping 192.168.1.20

# From Machine 1, test port 9000 is reachable
Test-NetConnection -ComputerName 192.168.1.20 -Port 9000
```

---

## 5. Prerequisites on Both Machines

### 5.1 Software required

| Software | Download | Notes |
|----------|----------|-------|
| Python 3.11+ | https://www.python.org/downloads/ | Check "Add to PATH" during install |
| Npcap | https://npcap.com/#download | Required for live packet capture on Windows |
| Git | https://git-scm.com/download/win | For cloning the repo |
| Node.js 18+ | https://nodejs.org/ | Only needed on Machine 2 for the dashboard |

### 5.2 Clone and set up on both machines

```powershell
# Run on BOTH machines
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install scapy   # for live capture
```

---

## 6. Step-by-Step Execution Order

> **Important:** Always start Machine 2 (server) BEFORE Machine 1 (probe).

---

### Step 1 — Machine 2: Start E3 Correlation Hub (port 9000)

Open **Terminal 1** on Machine 2 as **Administrator**:

```powershell
cd C:\path\to\Mini_Shark
.\.venv\Scripts\Activate.ps1
python run_e3_server.py
```

Expected output:
```
════════════════════════════════════════
  Mini-Shark — E3 Correlation Hub
════════════════════════════════════════
  Listening on TCP port 9000
  Waiting for Probe 1 and Probe 2...
────────────────────────────────────────
```

---

### Step 2 — Machine 2: Start FastAPI server (port 3000)

Open **Terminal 2** on Machine 2:

```powershell
cd C:\path\to\Mini_Shark
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.main:app --reload --port 3000 --host 0.0.0.0
```

The `--host 0.0.0.0` makes it accessible from Machine 1's browser.

---

### Step 3 — Machine 2: Start React Dashboard (port 5173)

Open **Terminal 3** on Machine 2:

```powershell
cd C:\path\to\Mini_Shark\frontend
npm run dev -- --host
```

The `--host` flag makes it accessible from any machine on the LAN.

---

### Step 4 — Machine 2: Start Probe 2

Open **Terminal 4** on Machine 2 as **Administrator**:

```powershell
cd C:\path\to\Mini_Shark
.\.venv\Scripts\Activate.ps1
python run_probe.py --probe-id 2 --server 127.0.0.1:9000
```

Expected output:
```
[Probe 2] Connected to E3 server at 127.0.0.1:9000
[Probe 2] Capturing on Wi-Fi...
[Probe 2] Packet #0 sent → fp=0x8F3A2B194E5C0D1A
```

---

### Step 5 — Machine 1: Start Probe 1

Open **Terminal 1** on Machine 1 as **Administrator**:

```powershell
cd C:\path\to\Mini_Shark
.\.venv\Scripts\Activate.ps1
# Replace 192.168.1.20 with Machine 2's actual IP
python run_probe.py --probe-id 1 --server 192.168.1.20:9000
```

Expected output:
```
[Probe 1] Connected to E3 server at 192.168.1.20:9000
[Probe 1] Capturing on Wi-Fi...
[Probe 1] Packet #0 sent → fp=0x8F3A2B194E5C0D1A
```

---

### Step 6 — Open Dashboard

On **any machine's browser**, open:

```
http://192.168.1.20:5173
```

Or on Machine 2 directly:
```
http://127.0.0.1:5173
```

---

## 7. What You Will See

### 7.1 E3 server terminal (Machine 2, Terminal 1)

```
  ✓ MATCHED    fp=0x8F3A2B194E5C0D1A  ΔT = 4.231 ms
  ✓ MATCHED    fp=0x4218AB3E09880FEA  ΔT = 3.987 ms
  ✗ LOST       fp=0xEFAE2A87C136277D
  ✓ MATCHED    fp=0x97C9ED4D0D26DA20  ΔT = 5.012 ms
  ⚠ ALERT: [WARNING] PACKET_LOSS — high confidence
```

### 7.2 Dashboard — Packet Inspector tab

- Packets flowing in real time from both probes
- Each packet colour-coded by protocol (TCP=purple, DNS=blue, HTTP=green)
- Click any row → full protocol tree + hex dump

### 7.3 Dashboard — Stats tab

| Metric | What it means |
|--------|---------------|
| Matched | Packet seen at BOTH probes |
| Unmatched | Packet left Probe 1, never arrived at Probe 2 = **LOST** |
| Late | Arrived at Probe 2 after 500ms timeout |
| ΔT | One-way wire delay between the two observation points |
| Loss Rate | % of packets that never reached the second probe |

### 7.4 Diagnostic Alerts

| Alert | Trigger | What it means |
|-------|---------|---------------|
| PACKET_LOSS | > 5% unmatched | Packets dropped between the two probes |
| BUFFERBLOAT | Rising ΔT slope | Router queue building up (congestion) |
| APP_FREEZE | Avg ΔT > 150ms | Server not responding — application delay |
| DNS_EXFIL_SUSPECTED | H(X) > 4.2 bits | Possible DNS tunnelling / data exfiltration |

---

## 8. Files to run

| File | Machine | Purpose |
|------|---------|---------|
| `run_e3_server.py` | Machine 2 | E3 TCP ingestion server on port 9000 |
| `run_probe.py --probe-id 1` | Machine 1 | Probe 1: capture + fingerprint + send telemetry |
| `run_probe.py --probe-id 2` | Machine 2 | Probe 2: capture + fingerprint + send telemetry |
| `uvicorn backend.main:app` | Machine 2 | FastAPI REST + WebSocket server |
| `npm run dev` | Machine 2 | React dashboard |

> `run_e3_server.py` and `run_probe.py` need to be implemented (Phase 4 code — see below).

---

## 9. What needs to be implemented (pending)

### 9.1 `run_probe.py` — Probe runner script

Responsibilities:
1. Connect to E3 server over TCP on port 9000
2. Send 16-byte MSHK preamble
3. Start live packet capture using E1 (`LiveCapture`)
4. For each captured packet:
   - Run E2 dissection (`ProtocolDissector.dissect_one`)
   - Build `ProbeTelemetry` 24-byte record
   - Send over the TCP connection to E3
5. Handle reconnection if E3 server drops

### 9.2 `run_e3_server.py` — E3 server script

Responsibilities:
1. Listen on TCP port 9000 (already implemented in `CorrelationHub.start_server`)
2. Accept connections from both probes
3. Match packets by fingerprint
4. Compute ΔT = T2 − T1
5. Fire diagnostic rules
6. Store results in SQLite
7. Push updates to dashboard via WebSocket

### 9.3 Clock synchronisation

- Both machines must run **NTP** (Network Time Protocol) for accurate ΔT
- Windows: `w32tm /resync` in admin PowerShell
- Verify clocks are within 1ms of each other using:
  ```powershell
  w32tm /query /status
  ```
- If clocks are off by > 10ms, ΔT values will be unreliable

---

## 10. Demo script for ma'am

### Single machine simulation (today)
```powershell
# Terminal 1
python run_e3_server.py

# Terminal 2 (Probe 1)
python run_probe.py --probe-id 1 --server 127.0.0.1:9000

# Terminal 3 (Probe 2 — same machine, simulates the other side)
python run_probe.py --probe-id 2 --server 127.0.0.1:9000

# Terminal 4
python -m uvicorn backend.main:app --reload --port 3000

# Terminal 5
cd frontend && npm run dev
```

Open browser: `http://127.0.0.1:5173`

### Two machine demo (final)
```powershell
# Machine 2 (run first)
python run_e3_server.py                              # Terminal 1
python run_probe.py --probe-id 2 --server 127.0.0.1:9000  # Terminal 2
python -m uvicorn backend.main:app --host 0.0.0.0 --port 3000  # Terminal 3
cd frontend && npm run dev -- --host              # Terminal 4

# Machine 1 (run after Machine 2 is ready)
python run_probe.py --probe-id 1 --server <Machine2_IP>:9000  # Terminal 1
```

---

## 11. Limitations and known issues

| Issue | Description | Mitigation |
|-------|-------------|------------|
| Clock skew | If machine clocks differ, ΔT will be wrong (possibly negative) | Sync clocks with NTP before starting |
| NAT between probes | If a NAT box rewrites IPs between the two probes, fingerprints won't match | Deploy probes inside same subnet |
| Same-machine simulation | ΔT ≈ 0ms since both probes see packets at the same time | Use for functional testing only; real delays need two machines |
| Wi-Fi adapter required | Npcap + Wi-Fi adapter required on both machines | Use Ethernet if Wi-Fi not available |
| Admin privilege required | Live capture requires Administrator / root | Always run terminals as Administrator |
| Fingerprint collisions | 64-bit fingerprint — negligible collision probability in a 500ms window | Documented in data_contract.md |

---

## 12. Summary

```
WHAT WE HAVE BUILT:
  ✅ E1 — Live capture (Npcap/scapy)
  ✅ E2 — Protocol dissection + BLAKE2b fingerprint + DNS entropy
  ✅ E3 — Correlation hub (hash table + min-heap, TCP server port 9000)
  ✅ E4 — Diagnostic rules + SQLite storage + REST API + WebSocket
  ✅ Dashboard — Wireshark-style UI (React)

WHAT IS NEEDED FOR 2-MACHINE DEPLOYMENT:
  ⬜ run_probe.py — probe runner (connects to E3, sends telemetry)
  ⬜ run_e3_server.py — standalone E3 server script
  ⬜ NTP clock sync on both machines
  ⬜ Firewall rules on Machine 2 (ports 9000, 3000, 5173)
  ⬜ Second machine with Npcap + repo cloned
```

---

*Document prepared by Chhavi Mishra (E2) · Mini-Shark Team 07*  
*KLE Technological University · Hubballi, Karnataka*
