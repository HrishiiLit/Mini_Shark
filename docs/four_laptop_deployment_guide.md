# Mini-Shark — 4-Laptop Physical Deployment Runbook

**Team 07 · Network Traffic Monitoring & Protocol Analysis Mini-Project (`23ECNP301`)**  
This document provides exact, terminal-by-terminal commands for deploying Mini-Shark across **4 distinct physical laptops** (2 Linux machines and 2 Windows machines):

| Laptop | Role in Topology | Operating System | Primary Components | IP (Example) |
| --- | --- | --- | --- | --- |
| **Laptop 4** | **Central Server Hub** | **Linux** ("mrq") (Ubuntu/Debian/Fedora/Arch) | Backend (`:8001`), E3 Hub (`:9000`), React UI (`:5173`), Egress Probe 2 | `192.168.1.20` |
| **Laptop 3** | **Intermediate Router** | **Windows 10/11** | Pure L3 IP Forwarding (No NAT), Transit Probe 10, Fault Injection | `192.168.1.10` |
| **Laptop 1** | **Client 1** | **Arch Linux** (Mine) | Client Probe (Auto ID / 11), Traffic Generator (`traffic_generator.py`) | `192.168.1.15` |
| **Laptop 2** | **Client 2** | **Windows 10/11** | Client Probe (Auto ID / 12), Concurrent Workload (HTTP / Ping) | `192.168.1.16` |

---

## 1. Network Interconnection Architecture

```text
[Laptop 1: Arch Linux (Mine)] ──┐
  (Client Probe 11)             │
                                ├──▶ [Laptop 3: Windows Router] ────▶ [Laptop 4: Linux Server ("mrq")]
[Laptop 2: Windows Client] ─────┘    (Pure L3 Forwarding / Probe 10)     (Backend :8001 + E3 :9000)
  (Client Probe 12)                                                      (Egress Probe 2 + UI :5173)
```

### Two Ways to Connect the 4 Laptops:

* **Method A (Easiest & 100% Wireless — Single Wi-Fi / Mobile Hotspot):**
  All 4 laptops connect to the same Wi-Fi SSID / Mobile Hotspot (e.g. `192.168.1.0/24`). To force packets to physically traverse Laptop 3 (Windows Router) instead of going direct:
  * On Arch Client (Laptop 1): `sudo ip route add <SERVER_IP>/32 via <WINDOWS_ROUTER_IP>`
  * On Windows Client (Laptop 2): `route add <SERVER_IP> mask 255.255.255.255 <WINDOWS_ROUTER_IP>`
  * On Linux Server (Laptop 4): `sudo ip route add <ARCH_IP>/32 via <WINDOWS_ROUTER_IP>` and `sudo ip route add <WIN_CLIENT_IP>/32 via <WINDOWS_ROUTER_IP>`
  * On Windows Router (Laptop 3): Enable IP forwarding via `setup_windows_router.ps1`.
* **Method B (Physical 2-NIC Router):**
  Windows Router has two NICs (e.g. Wi-Fi connected to Clients on Subnet `192.168.10.0/24` and Ethernet/USB adapter connected to Linux Server on Subnet `192.168.20.0/24`).

---

## 1.1 Pre-Flight Verification & Critical Pitfalls

Before launching probes, verify these four essential hardware conditions:

1. **AP / Wi-Fi Client Isolation Check:**
   Many campus or public Wi-Fi networks block intra-subnet client communication. Test with a quick ping:
   ```bash
   ping <WINDOWS_ROUTER_IP>
   ping <SERVER_IP>
   ```
   If packets fail to reach peers despite firewall rules, the Wi-Fi network has client isolation enabled. **Fix:** Use a smartphone Mobile Hotspot or an ad-hoc Wi-Fi network.

2. **NTP Physical Clock Synchronization:**
   Estimated one-way delay is computed as $\Delta T = T_2 - T_1$. If clocks differ by even 50 ms, delay values become invalid or negative.
   * **On Linux (Laptop 1 & Laptop 4):**
     ```bash
     sudo timedatectl set-ntp true
     sudo systemctl restart systemd-timesyncd
     timedatectl status
     ```
   * **On Windows (Laptop 2 & Laptop 3):**
     In an Administrator PowerShell prompt:
     ```powershell
     w32tm /resync /nowait
     ```

3. **Disable ICMP Redirects on Arch Linux (Method A Hairpin Routing):**
   When routing packets destined for the Server through the Windows Router on the same Wi-Fi subnet, RFC 792 dictates that the router sends ICMP Type 5 (Redirect) messages to Arch Linux. If Arch accepts redirects, it will bypass the router and send traffic direct to the server!
   ```bash
   sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
   sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
   ```

4. **Npcap NDIS Driver Behavior & Link 1 vs Link 2 Drops:**
   On Windows, Npcap captures packets at the NDIS layer *before* the Windows Firewall drops inbound packets. If Probe 10 runs on the router, it records `router_ts` before an inbound block drops the packet, causing Mini-Shark to attribute the drop to Link 2 (`Router ──✖──> Server`).
   * **To test Link 1 drops authentically (`Client ──✖──> Router`):** Drop packets on the sender (e.g. `iptables OUTPUT` on Arch or outbound Windows firewall on Client 2).
   * **To test Link 2 drops (`Router ──✖──> Server`):** Use `.\scripts\setup_windows_router.ps1 -Action drop-link2 -ServerIP <SERVER_IP>`.

---

## 1.2 Quick Reference: One-Command Automation Scripts

To streamline lab setup, each laptop has a dedicated all-in-one automation script that runs all required components in a single terminal, **interactively prompts for any needed IP addresses**, provides live control benches, and cleanly tears down processes on exit:

| Laptop | Role | Primary One-Run Command | What It Automates |
| :--- | :--- | :--- | :--- |
| **Laptop 4** | **Server Hub** (Linux) | `./start_server.sh`<br>*(Stop: `./stop_server.sh`)* | • Auto-detects Server LAN IP<br>• Asks to configure Method A return routes via Router<br>• Opens UFW ports (`8001`, `9000`, `5173`, `9500`)<br>• Runs Backend (`:8001`), E3 Hub (`:9000`), React UI (`:5173`), & Egress Probe 2<br>• Streams unified logs in one terminal (Ctrl+C cleanly stops all 3) |
| **Laptop 3** | **Router** (Windows 10/11) | `start_router.bat`<br>*(or `.\start_router.ps1`)*<br>*(Linux: `sudo ./start_router.sh`)* | • Self-elevates to Administrator<br>• **Prompts for Server Hub IP**<br>• Enables pure L3 forwarding (No NAT)<br>• Starts Probe 10 in dedicated console<br>• Interactive menu: Link 2 drop, Link 1 drop, status, clear |
| **Laptop 1** | **Client 1** (Arch Linux) | `./start_client_linux.sh` | • **Prompts for Server Hub IP & Router IP**<br>• Disables ICMP redirects & adds `/32` host route via router<br>• Starts Client Probe 11 in background<br>• Interactive menu: mixed workload, HTTP, UDP stream, DNS exfil anomaly test, Link 1 drop |
| **Laptop 2** | **Client 2** (Windows 10/11) | `start_client_windows.bat`<br>*(or `.\start_client_windows.ps1`)* | • Self-elevates to Administrator<br>• **Prompts for Server Hub IP & Router IP**<br>• Adds `/32` static route via router<br>• Starts Client Probe 12<br>• Interactive menu: continuous HTTP / ping, auto-cleanup |

---

## 2. Laptop 4: Linux ("mrq") — Central Server Hub & Egress Probe 2

Laptop 4 runs Linux (Ubuntu, Debian, Fedora, Arch, etc.). It hosts the central FastAPI backend, the E3 TCP correlation hub, the React dashboard, and local Egress Probe 2.

### Step 2.1 — Prerequisites & IP Address
Install Python 3, Git, and Node.js:
* **Ubuntu / Debian / Mint:**
  ```bash
  sudo apt update
  sudo apt install -y python3 python3-venv python3-pip git nodejs npm
  ```
* **Arch Linux:**
  ```bash
  sudo pacman -Syu --needed python git nodejs npm
  ```
* **Fedora / RHEL:**
  ```bash
  sudo dnf install -y python3 python3-pip git nodejs npm
  ```

Find the Linux Server's LAN IP:
```bash
ip -br addr
# Note down your Wi-Fi or Ethernet IP (e.g. 192.168.1.20)
```

### Step 2.2 — Clone & Environment Setup
Open Terminal on Laptop 4:
```bash
cd ~
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa

# Create Python virtual environment & install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
*(Note: Because this is Linux, Probe 2 uses native kernel `AF_PACKET` raw sockets—zero need for Scapy or Npcap!)*

### Step 2.3 — Firewall (Allow Inbound Ports)
If UFW or firewalld is active, open the required ports:
```bash
# Ubuntu UFW:
sudo ufw allow 8001/tcp && sudo ufw allow 9000/tcp && sudo ufw allow 5173/tcp && sudo ufw allow 9500/udp
```

### Step 2.3b — Route Return Traffic through Windows Router (Method A Only)
If all 4 laptops connect to the same Wi-Fi / Hotspot (Method A), add static routes on Laptop 4 so return responses go through the Windows Router instead of bypassing it.

**Option 1: Interactive Automated Script:**
```bash
sudo ./scripts/setup_server_network.sh add
# It will interactively prompt for Router IP and Client IPs in your terminal!
```
*(To remove routes after evaluation: `sudo ./scripts/setup_server_network.sh clear`)*

**Option 2: Manual Commands:**
```bash
# 1. Ignore ICMP redirects from the Windows Router
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

# 2. Route responses to Client 1 and Client 2 via the Windows Router
sudo ip route replace <ARCH_CLIENT_IP>/32 via <WINDOWS_ROUTER_IP>
sudo ip route replace <WIN_CLIENT_IP>/32 via <WINDOWS_ROUTER_IP>
```

### Step 2.4 — Recommended: Run All Server Services with `./start_server.sh`
Instead of opening 3 separate terminals, execute the unified runner:
```bash
./start_server.sh
```
*What this does in one step:*
* Prompts whether you want to configure Method A return routes via Router now (and prompts for IPs).
* Detects your LAN IP address automatically.
* Opens UFW firewall ports (`8001`, `9000`, `5173`, `9500`).
* Launches **FastAPI Backend & E3 Hub (`:8001`, `:9000`)**, **React UI (`:5173`)**, and **Egress Probe 2** in the background.
* Streams clean, color-coded unified logs in this single terminal.
* **Graceful Exit:** Pressing `Ctrl+C` cleanly shuts down all 3 child processes without leaving ports blocked.
* *(Emergency Stopper: Run `./stop_server.sh` at any time to kill any background processes and free ports).*

---

### Alternative: Run Manually in 3 Separate Terminals

#### Terminal 1: Start Backend API (`:8001`) & E3 Hub (`:9000`)
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

#### Terminal 2: Start React Web Dashboard (`:5173`)
```bash
cd ~/Minyaa/frontend
npm install
npm run dev -- --host 0.0.0.0
```
> **Important Note:** Do **not** prefix with `VITE_API_HOST=http://127.0.0.1:8001` when teammates on other laptops need to view the dashboard. Running `npm run dev -- --host 0.0.0.0` alone allows `frontend/src/config.ts` to dynamically resolve `<SERVER_IP>:8001` based on the browser's address bar. Open `http://localhost:5173` locally, or `http://<SERVER_IP>:5173` from other laptops.

#### Terminal 3: Start Egress Probe 2
```bash
cd ~/Minyaa
source .venv/bin/activate
sudo ./run_probe.sh --server 127.0.0.1:9000 --role server
```
*Expected log:*
```text
  Mini-Shark Probe 2
  OS          : Linux
  E3 Server   : 127.0.0.1:9000
  [Probe 2] Connected to E3 server at 127.0.0.1:9000
  [Probe 2] Backend    : AFPacketCapture
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

### Step 3.3 — Recommended: One-Command Router Automation (`start_router.bat` / `start_router.ps1`)

Run the all-in-one script in Administrator PowerShell (or simply double-click `start_router.bat`):
```powershell
.\start_router.ps1
```
*(If the router is running Linux instead, run: `sudo ./start_router.sh`)*

**What this does automatically:**
1. Self-elevates to Administrator if not already elevated.
2. **Prompts for the Server IP:**
   ```text
   Enter Central Server Hub IP (Laptop 4) [e.g. 192.168.1.20]: 
   ```
3. Automatically enables pure L3 IP forwarding, sets `IPEnableRouter = 1`, and starts `RemoteAccess`.
4. Checks and installs `scapy` if missing.
5. Launches **Transit Probe 10** in a dedicated monitor window streaming to `tcp://<SERVER_IP>:9000`.
6. Provides an interactive fault injection control bench in the console:
   ```text
   ======================================================================
                ROUTER FAULT INJECTION & CONTROL BENCH                   
   ======================================================================
     [1] Inject Link 2 Drop  (Router ──✖──> Server Hub)
     [2] Inject Link 1 Drop  (Client ──✖──> Router)
     [3] Clear All Drops     (Restore 100% normal transmission)
     [4] Show Router & Drop Status
     [5] Restart Probe 10
     [6] Exit & Cleanup
   ```
   * Press `1` during demo to inject a Link 2 drop.
   * Press `3` to clear drops and restore 100% clean flight.
   * Press `6` when done to terminate Probe 10 and clean up firewall drop rules.

---

### Alternative: Manual Step-by-Step Configuration

#### Terminal 1: Enable Windows Pure Layer-3 Routing
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

#### Terminal 2: Start Router Probe 10
In **Command Prompt (Run as Administrator)**:
```cmd
cd C:\Minyaa
python run_probe.py --server <SERVER_IP>:9000 --role router
```
*Example:* `python run_probe.py --server 192.168.1.20:9000 --role router`  
*Expected log:*
```text
  Mini-Shark Probe 10
  OS          : Windows
  Role        : router
  [Probe 10] Connected to E3 server at 192.168.1.20:9000
```

#### Manual Fault Injection Commands
* **Simulate Link 2 Drop (`Router ──✖──> Server Hub`):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action drop-link2 -ServerIP <SERVER_IP>
  ```
* **Simulate Link 1 Drop (`Client ──✖──> Router`):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action drop-link1 -ClientIP <ARCH_CLIENT_IP>
  ```
* **Restore clean transmission:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows_router.ps1 -Action clear-drops
  ```

---

## 4. Laptop 1: Arch Linux (Mine) — Client 1

Laptop 1 runs Arch Linux. Because Linux has built-in `AF_PACKET` raw sockets, **zero external capture libraries (no scapy, no npcap, no venv) are required** to run the probe!

### Step 4.1 — Prerequisites & Clone
```bash
sudo pacman -Syu --needed git python
cd ~
git clone https://github.com/Janaki1711/Minyaa.git
cd Minyaa
```

### Step 4.2 — Recommended: One-Command Client 1 Automation (`./start_client_linux.sh`)

Run the interactive all-in-one script:
```bash
./start_client_linux.sh
```

**What this does automatically:**
1. **Prompts for Network IPs in terminal:**
   ```text
   Enter Central Server Hub IP (Laptop 4) [e.g. 192.168.1.20]: 
   Enter Intermediate Router IP (Laptop 3) [e.g. 192.168.1.10]: 
   ```
2. Automatically disables ICMP redirects and sets static `/32` host route to Server via Router.
3. Launches **Client Probe 11** in the background streaming telemetry to the Server.
4. Provides an interactive live test bench in the console:
   ```text
   ======================================================================
            CLIENT 1 TEST BENCH & WORKLOAD GENERATOR (ARCH LINUX)        
   ======================================================================
     [1] Start Mixed Workload (HTTP + UDP stream @ 10 pkts/s)
     [2] Start HTTP Queries Workload (5 req/s)
     [3] Start UDP Audio/Media Stream (25 pkts/s)
     [4] Run Live DNS Exfiltration Test (Triggers H > 4.2 bits alert)
     [5] Inject Link 1 Drop (Sender 30% drop via iptables)
     [6] Clear Link 1 Drop (Restore 100% clean transmission)
     [7] Tail Live Probe 11 Logs
     [8] Stop Running Workload
     [9] Exit & Cleanup
   ```
   * Press `1` to run background traffic.
   * Press `4` to test the DNS anomaly alert on the dashboard.
   * Press `5` to demonstrate a Link 1 drop (Client ──✖──> Router).
   * Press `9` (or `Ctrl+C`) when finished: it stops probe and generators, removes iptables rules, and deletes the static route!

---

### Alternative: Manual Step-by-Step Configuration

#### Step 4.2a — Route Traffic through Windows Router (Method A)
If all 4 laptops are on the same Wi-Fi, route all traffic destined for the Server via the Windows Router:
```bash
# 1. Ignore ICMP redirect packets from the Windows router
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

# 2. Add host route to Server via Windows Router
sudo ip route replace <SERVER_IP>/32 via <WINDOWS_ROUTER_IP>
# Example: sudo ip route replace 192.168.1.20/32 via 192.168.1.10
```
Verify connectivity:
```bash
traceroute <SERVER_IP>
# You should see Hop 1: Windows Router IP, Hop 2: Server IP
```

#### Step 4.2b — Terminal 1: Start Client Probe (Probe 11)
```bash
cd ~/Minyaa
sudo ./run_probe.sh --server <SERVER_IP>:9000
```
*Note: Arch Linux will automatically assign your probe ID from your IP octet (e.g. `.15` becomes **Probe 15**) or pass `--probe-id 11`.*  
*Expected log:*
```text
  Mini-Shark Probe 11
  OS          : Linux
  Backend     : AFPacketCapture
  [Probe 11] Connected to E3 server at 192.168.1.20:9000
```

#### Step 4.2c — Terminal 2: Generate Workloads
Generate multi-protocol test traffic destined for the Server:
```bash
cd ~/Minyaa

# 1. Mixed realistic workload (Concurrent HTTP + UDP streaming):
python3 scripts/traffic_generator.py --target <SERVER_IP> --mode mixed --rate 10

# 2. HTTP queries:
python3 scripts/traffic_generator.py --target <SERVER_IP> --mode http --rate 5

# 3. UDP media stream (1024-byte audio packets):
python3 scripts/traffic_generator.py --target <SERVER_IP> --mode udp-stream --rate 25

# 4. Live DNS Anomaly test (simulates high-entropy DNS tunneling):
python3 test_anomalies.py --dns --target <SERVER_IP>

# 5. Fault Injection: Demonstrate Link 1 Drop (Client ──✖──> Router):
sudo iptables -A OUTPUT -d <SERVER_IP> -m statistic --mode random --probability 0.3 -j DROP
# When finished, remove the drop rule:
sudo iptables -D OUTPUT -d <SERVER_IP> -m statistic --mode random --probability 0.3 -j DROP
```

---

## 5. Laptop 2: Windows Laptop A — Client 2

Laptop 2 is the second client machine generating concurrent background traffic.

### Step 5.1 — Prerequisites & Clone
1. Install **Git for Windows**, **Python 3.10+**, and **Npcap** (WinPcap API-compatible mode).
2. Open **Command Prompt (Run as Administrator)**:
   ```cmd
   cd C:\
   git clone https://github.com/Janaki1711/Minyaa.git
   cd Minyaa
   pip install scapy
   ```

### Step 5.2 — Recommended: One-Command Client 2 Automation (`start_client_windows.bat` / `start_client_windows.ps1`)

In Administrator PowerShell (or simply double-click `start_client_windows.bat`):
```powershell
.\start_client_windows.ps1
```

**What this does automatically:**
1. Self-elevates to Administrator if needed.
2. **Prompts for Network IPs in terminal:**
   ```text
   Enter Central Server Hub IP (Laptop 4) [e.g. 192.168.1.20]: 
   Enter Intermediate Router IP (Laptop 3) [e.g. 192.168.1.10]: 
   ```
3. Adds `/32` static route via Router automatically.
4. Launches **Client Probe 12** in a monitor window.
5. Provides an interactive background traffic control menu:
   ```text
   ======================================================================
                CLIENT 2 CONTROL BENCH & WORKLOAD (WINDOWS)              
   ======================================================================
     [1] Start Continuous HTTP Workload (5 req/s)
     [2] Start Continuous ICMP Ping (ping <SERVER_IP> -t)
     [3] Stop Active Workload
     [4] Restart Probe 12
     [5] Show Route Table & Connectivity
     [6] Exit & Cleanup
   ```
   * Press `1` to run background HTTP requests.
   * Press `2` to run continuous ICMP ping.
   * Press `6` when finished: it stops workloads, terminates Probe 12, and deletes the static route automatically!

---

### Alternative: Manual Step-by-Step Configuration

#### Step 5.2a — Route Traffic through Windows Router (Method A)
In **Command Prompt (Run as Administrator)**:
```cmd
route add <SERVER_IP> mask 255.255.255.255 <WINDOWS_ROUTER_IP>
:: Example: route add 192.168.1.20 mask 255.255.255.255 192.168.1.10
```

#### Step 5.2b — Terminal 1: Start Client Probe (Probe 12)
In **Command Prompt (Run as Administrator)**:
```cmd
cd C:\Minyaa
run_probe.bat --server <SERVER_IP>:9000
```
*Expected log:*
```text
  Mini-Shark Probe 12
  OS          : Windows
  Backend     : LiveCapture
  [Probe 12] Connected to E3 server at <SERVER_IP>:9000
```

#### Step 5.2c — Terminal 2: Generate Concurrent Traffic
In a second Command Prompt:
```cmd
cd C:\Minyaa

:: Continuous HTTP requests:
python scripts\traffic_generator.py --target <SERVER_IP> --mode http --rate 5

:: Or continuous ICMP ping:
ping <SERVER_IP> -t
```

---

## 6. Verification & Evaluation Checklist

| Checkpoint | Expected Observation | Where to Verify |
| --- | --- | --- |
| **All Probes Connected** | Status indicators for Probe 11 (Arch), Probe 12 (Win Client), Probe 10 (Router), and Probe 2 (Server) show **Connected (Green)** | Dashboard Header / Top Bar on `http://<SERVER_IP>:5173` |
| **Telemetry Ingestion** | Terminal 1 on Server shows continuous 24-byte record ingestion on port `:9000` | Server Terminal 1 |
| **Normal Traffic Matching** | Ingress and Egress observations matched via BLAKE2b hash; latency graph shows sub-millisecond to ~5ms `ΔT = T2 - T1` | Dashboard Packet Table (Green rows, State: `matched`) |
| **Link 1 Drop Test** | Router runs `drop-link1` → Packets turn **Red** on dashboard with badge: `Dropped on Link 1: Client ──✖──> Router` | Dashboard Alerts & Packet Inspector |
| **Link 2 Drop Test** | Router runs `drop-link2` → Packets turn **Red** on dashboard with badge: `Dropped on Link 2: Router ──✖──> Server Hub` | Dashboard Alerts & Packet Inspector |
| **DNS Anomaly Rule** | Arch runs `python3 test_anomalies.py --dns` → Alert fires: `DNS_EXFIL_SUSPECTED (H > 4.2 bits)` | Dashboard Diagnostic Alert Drawer / Modal |
| **SQLite Persistence** | Correlation records and alerts written to `mini_shark.db` with WAL mode | Server file `mini_shark.db` |

---

## 7. Troubleshooting Quick Reference

* **Firewall blocks on Linux Server:** Check `sudo ufw status` or `sudo iptables -L -n`. Ensure ports `8001`, `9000`, `5173` are allowed.
* **Windows Router doesn't forward packets:** Ensure PowerShell was opened as **Administrator** when executing `setup_windows_router.ps1 -Action enable-routing`. Run `powershell -File .\scripts\setup_windows_router.ps1 -Action status` to confirm `IPEnableRouter = 1` and `RemoteAccess` is running.
* **Npcap permissions on Windows:** Ensure Command Prompt was launched using *"Run as Administrator"*, otherwise raw socket capture is denied by Windows security.
* **Host routes cleanup after lab demo:**
  * Arch / Linux Server: `sudo ip route del <TARGET_IP>/32`
  * Windows: `route delete <TARGET_IP>`
