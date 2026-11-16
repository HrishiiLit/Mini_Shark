# Mini-Shark — 4-Laptop Physical Deployment Runbook

**Team 07 · Network Traffic Monitoring & Protocol Analysis Mini-Project (`23ECNP301`)**  
This document provides exact, terminal-by-terminal commands for deploying Mini-Shark across **4 distinct physical laptops** with heterogeneous operating systems:

| Laptop | Role in Topology | Operating System | Primary Components | IP (Example) |
| --- | --- | --- | --- | --- |
| **Laptop 4** | **Central Server Hub** | **macOS** ("mrq") | Backend (`:8001`), E3 Hub (`:9000`), React UI (`:5173`), Egress Probe 2 | `192.168.1.20` |
| **Laptop 3** | **Intermediate Router** | **Windows 10/11** | Pure L3 IP Forwarding (No NAT), Transit Probe 10, Fault Injection | `192.168.1.10` |
| **Laptop 1** | **Client 1** | **Arch Linux** (Mine) | Client Probe (Auto ID / 11), Traffic Generator (`traffic_generator.py`) | `192.168.1.15` |
| **Laptop 2** | **Client 2** | **Windows 10/11** | Client Probe (Auto ID / 12), Concurrent Workload (HTTP / Ping) | `192.168.1.16` |

---

## 1. Network Interconnection Architecture

```text
[Laptop 1: Arch Linux] ──┐
  (Client Probe 11)      │
                         ├──▶ [Laptop 3: Windows Router] ────▶ [Laptop 4: macOS Server]
[Laptop 2: Windows Client] ──┘    (Pure L3 Forwarding / Probe 10)     (Backend :8001 + E3 :9000)
  (Client Probe 12)                                                   (Egress Probe 2 + UI :5173)
```

### Two Ways to Connect the 4 Laptops:

* **Method A (Easiest & 100% Wireless — Single Wi-Fi / Mobile Hotspot):**
  All 4 laptops connect to the same Wi-Fi SSID / Mobile Hotspot (e.g. `192.168.1.0/24`). To force packets to physically traverse Laptop 3 (Windows Router) instead of going direct:
  * On Arch Client: `sudo ip route add <SERVER_IP>/32 via <ROUTER_IP>`
  * On Windows Client: `route add <SERVER_IP> mask 255.255.255.255 <ROUTER_IP>`
  * On Mac Server: `sudo route add -host <ARCH_IP> <ROUTER_IP>` and `sudo route add -host <WIN_CLIENT_IP> <ROUTER_IP>`
  * On Windows Router: Enable IP forwarding (PowerShell script provided).
* **Method B (Physical 2-NIC Router):**
  Windows Router has two NICs (e.g. Wi-Fi connected to Clients on Subnet `192.168.10.0/24` and Ethernet/USB adapter connected to Mac Server on Subnet `192.168.20.0/24`).

---

## 2. Laptop 4: macOS ("mrq") — Central Server Hub & Egress Probe 2

Laptop 4 runs the central FastAPI backend, the E3 TCP correlation hub, the React dashboard, and local Egress Probe 2.

### Step 2.1 — Prerequisites
Ensure Python 3, Git, and Node.js are installed on the Mac:
```bash
brew install python git node
```
Find the Mac's IP address:
```bash
ipconfig getifaddr en0 || ipconfig getifaddr en1
# Note down this IP: e.g. 192.168.1.20
```

### Step 2.2 — Clone & Environment Setup
Open Terminal on macOS:
```bash
cd ~
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa

# Create Python virtual environment & install backend requirements
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install scapy
```

### Step 2.3 — Terminal 1: Start Backend API (`:8001`) & E3 Hub (`:9000`)
```bash
cd ~/Minyaa
source .venv/bin/activate
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```
*Expected log:*
```text
[E3] TCP ingestion server started on 0.0.0.0:9000
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
```

### Step 2.4 — Terminal 2: Start React Web Dashboard (`:5173`)
```bash
cd ~/Minyaa/frontend
npm install
VITE_API_HOST=http://127.0.0.1:8001 npm run dev -- --host 0.0.0.0
```
Open your browser at `http://localhost:5173`. Teammates on other laptops can view the dashboard live at `http://<MAC_SERVER_IP>:5173`.

### Step 2.5 — Terminal 3: Start Egress Probe 2
On macOS, packet capture uses Scapy with root permissions:
```bash
cd ~/Minyaa
source .venv/bin/activate
sudo python3 run_probe.py --server 127.0.0.1:9000 --role server
```
*Expected log:*
```text
  Mini-Shark Probe 2
  OS          : Darwin
  E3 Server   : 127.0.0.1:9000
  [Probe 2] Connected to E3 server at 127.0.0.1:9000
  [Probe 2] Backend    : LiveCapture
  [Probe 2] Live capture started.
```

---

## 3. Laptop 3: Windows Laptop B — Intermediate Router & Probe 10

Laptop 3 acts as the pure Layer-3 IP router between the clients and the server, and runs **Probe 10** to monitor transit packets.

### Step 3.1 — Prerequisites
1. Install **Git for Windows**: [git-scm.com](https://git-scm.com)
2. Install **Python 3.10+**: Make sure to check *"Add Python to PATH"* during installation.
3. Install **Npcap**: [npcap.com](https://npcap.com) (During setup, ensure *"Install Npcap in WinPcap API-compatible Mode"* is **checked**).

### Step 3.2 — Clone & Install Dependencies
Open **Command Prompt (Admin)** or **PowerShell (Admin)**:
```cmd
cd C:\
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa
pip install scapy
```

### Step 3.3 — Terminal 1: Enable Windows Pure Layer-3 Routing
In **PowerShell (Run as Administrator)**:
```powershell
cd C:\Minyaa
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action enable-routing
```
*(This automatically enables `Set-NetIPInterface -Forwarding Enabled`, sets `IPEnableRouter = 1` in the Windows registry, starts the `RemoteAccess` service, and allows forwarded packets through Windows Firewall without NAT).*

Verify status:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action status
```

### Step 3.4 — Terminal 2: Start Router Probe 10
In **Command Prompt (Run as Administrator)**:
```cmd
cd C:\Minyaa
python run_probe.py --server <MAC_SERVER_IP>:9000 --role router
```
*Example:* `python run_probe.py --server 192.168.1.20:9000 --role router`  
*Expected log:*
```text
  Mini-Shark Probe 10
  OS          : Windows
  Role        : router
  [Probe 10] Connected to E3 server at 192.168.1.20:9000
```

### Step 3.5 — Injecting Faults during Evaluation (Hop-by-Hop Drop Demo)
To demonstrate silent drop localization to the evaluators, run these commands on Laptop 3:

* **To simulate Link 1 Drop (`Client ──✖──> Router`):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action drop-link1 -ClientIP <ARCH_CLIENT_IP>
  ```
  *Dashboard Result:* Packets are highlighted in red and attributed as:  
  `Dropped on Link 1: Client PC ──✖──> Router` (Client saw it, Router never received it).

* **To simulate Link 2 Drop (`Router ──✖──> Server Hub`):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action drop-link2 -ServerIP <MAC_SERVER_IP>
  ```
  *Dashboard Result:* Packets are highlighted in red and attributed as:  
  `Dropped on Link 2: Router (Probe 10) ──✖──> Server Hub (Probe 2)` (Router captured it, Server never received it).

* **To restore normal clean transmission:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action clear-drops
  ```

---

## 4. Laptop 1: Arch Linux (Mine) — Client 1

Laptop 1 runs Arch Linux. Because Linux has built-in `AF_PACKET` raw sockets, **zero external capture libraries (no scapy, no npcap, no venv) are required** to run the probe!

### Step 4.1 — Prerequisites
```bash
sudo pacman -Syu --needed git python
```

### Step 4.2 — Clone Repository
```bash
cd ~
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa
```

### Step 4.3 — Route Traffic through Windows Router (Method A)
If all 4 laptops are on the same Wi-Fi, tell Arch Linux to send all traffic destined for the Mac Server via the Windows Router:
```bash
# Replace with your actual Server and Router IPs:
sudo ip route add <MAC_SERVER_IP>/32 via <WINDOWS_ROUTER_IP>
# Example: sudo ip route add 192.168.1.20/32 via 192.168.1.10
```
Verify connectivity:
```bash
traceroute <MAC_SERVER_IP>
# You should see Hop 1: Windows Router IP, Hop 2: Mac Server IP
```

### Step 4.4 — Terminal 1: Start Client Probe (Probe 11)
```bash
cd ~/Minyaa
sudo ./run_probe.sh --server <MAC_SERVER_IP>:9000
```
*Note: Arch Linux will automatically assign your probe ID from your IP octet (e.g. `.15` becomes **Probe 15**) or pass `--probe-id 11`.*  
*Expected log:*
```text
  Mini-Shark Probe 11
  OS          : Linux
  Backend     : AFPacketCapture
  [Probe 11] Connected to E3 server at 192.168.1.20:9000
```

### Step 4.5 — Terminal 2: Generate Workloads
Generate multi-protocol test traffic destined for the Mac Server:
```bash
cd ~/Minyaa

# 1. Mixed realistic workload (Concurrent HTTP + UDP streaming):
python3 scripts/traffic_generator.py --target <MAC_SERVER_IP> --mode mixed --rate 10

# 2. HTTP queries:
python3 scripts/traffic_generator.py --target <MAC_SERVER_IP> --mode http --rate 5

# 3. UDP media stream (1024-byte audio packets):
python3 scripts/traffic_generator.py --target <MAC_SERVER_IP> --mode udp-stream --rate 25

# 4. Live DNS Anomaly test (simulates high-entropy DNS tunneling):
python3 test_anomalies.py --dns --target <MAC_SERVER_IP>
```

---

## 5. Laptop 2: Windows Laptop A — Client 2

Laptop 2 is the second client machine generating concurrent background traffic.

### Step 5.1 — Prerequisites
1. Install **Git for Windows**: [git-scm.com](https://git-scm.com)
2. Install **Python 3.10+** (check *"Add to PATH"*).
3. Install **Npcap**: [npcap.com](https://npcap.com) (check *"WinPcap API-compatible Mode"*).

### Step 5.2 — Clone Repository & Install Scapy
In **Command Prompt (Run as Administrator)**:
```cmd
cd C:\
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa
pip install scapy
```

### Step 5.3 — Route Traffic through Windows Router (Method A)
In **Command Prompt (Run as Administrator)**:
```cmd
route add <MAC_SERVER_IP> mask 255.255.255.255 <WINDOWS_ROUTER_IP>
:: Example: route add 192.168.1.20 mask 255.255.255.255 192.168.1.10
```

### Step 5.4 — Terminal 1: Start Client Probe (Probe 12)
In **Command Prompt (Run as Administrator)**:
```cmd
cd C:\Minyaa
run_probe.bat --server <MAC_SERVER_IP>:9000
```
*Expected log:*
```text
  Mini-Shark Probe 12
  OS          : Windows
  Backend     : LiveCapture
  [Probe 12] Connected to E3 server at <MAC_SERVER_IP>:9000
```

### Step 5.5 — Terminal 2: Generate Concurrent Traffic
In a second Command Prompt:
```cmd
cd C:\Minyaa

:: Continuous HTTP requests
python scripts\traffic_generator.py --target <MAC_SERVER_IP> --mode http --rate 5

:: Or continuous ICMP ping
ping <MAC_SERVER_IP> -t
```

---

## 6. Verification & Evaluation Checklist

| Checkpoint | Expected Observation | Where to Verify |
| --- | --- | --- |
| **All Probes Connected** | Status indicators for Probe 11 (Arch), Probe 12 (Win Client), Probe 10 (Router), and Probe 2 (Server) show **Connected (Green)** | Dashboard Header / Top Bar on `http://<MAC_SERVER_IP>:5173` |
| **Telemetry Ingestion** | Terminal 1 on Mac Server shows continuous 24-byte record ingestion on port `:9000` | Mac Server Terminal 1 |
| **Normal Traffic Matching** | Ingress and Egress observations matched via BLAKE2b hash; latency graph shows sub-millisecond to ~5ms `ΔT = T2 - T1` | Dashboard Packet Table (Green rows, State: `matched`) |
| **Link 1 Drop Test** | Router runs `drop-link1` → Packets turn **Red** on dashboard with badge: `Dropped on Link 1` | Dashboard Alerts & Packet Inspector |
| **Link 2 Drop Test** | Router runs `drop-link2` → Packets turn **Red** on dashboard with badge: `Dropped on Link 2` | Dashboard Alerts & Packet Inspector |
| **DNS Anomaly Rule** | Arch runs `python3 test_anomalies.py --dns` → Alert fires: `DNS_EXFIL_SUSPECTED (H > 4.2 bits)` | Dashboard Diagnostic Alert Drawer / Modal |
| **SQLite Persistence** | Correlation records and alerts written to `mini_shark.db` with WAL mode | Server file `mini_shark.db` |

---

## 7. Troubleshooting Quick Reference

* **Firewall blocks on Mac:** On Mac, if clients cannot connect to `:9000` or `:8001`, open *System Settings → Network → Firewall* and ensure incoming connections for Python are allowed.
* **Windows Router doesn't forward packets:** Ensure PowerShell was opened as **Administrator** when executing `setup_windows_router.ps1 -Action enable-routing`. Run `powershell -File .\scripts\setup_windows_router.ps1 -Action status` to confirm `IPEnableRouter = 1` and `RemoteAccess` is running.
* **Npcap permissions on Windows:** Ensure Command Prompt was launched using *"Run as Administrator"*, otherwise raw socket capture is denied by Windows security.
* **Host routes cleanup after lab demo:**
  * Arch: `sudo ip route del <MAC_SERVER_IP>/32`
  * Windows: `route delete <MAC_SERVER_IP>`
  * Mac: `sudo route delete <CLIENT_IP>`
