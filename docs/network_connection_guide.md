# Mini-Shark — Network Connection Guide
## Laptop 1 (Chhavi) + Laptop 2 (Hrishikesh) Integration

**Project:** Mini-Shark (23ECNP301) · Team 07  
**KLE Technological University**

---

## 1. Laptop 1 — Complete IP Address Map

| Machine / Interface | IP Address | Subnet | Role |
|---------------------|------------|--------|------|
| **Windows Host (Wi-Fi)** | `10.60.0.6` | `10.60.0.0/21` | Physical LAN — use for cross-laptop connection |
| **Windows Host (Ethernet)** | `196.20.10.2` | `196.20.10.0/24` | Physical Ethernet |
| **VMware VMnet1 (Host-Only)** | `192.168.130.1` | `192.168.130.0/24` | VM-to-VM + host communication |
| **VMware VMnet8 (NAT)** | `192.168.46.1` | `192.168.46.0/24` | VMs internet access |
| **VM1 — Ubuntu 64-bit** | `192.168.130.129` | `192.168.130.0/24` | **Central Server + Probe 2** |
| **VM2 — Ubuntu 64-bit (3)** | `192.168.130.128` | `192.168.130.0/24` | **Probe 1** |

---

## 2. What Runs on Each Machine (Laptop 1)

```
Windows Host (10.60.0.6)
├── React Dashboard   → http://localhost:5173
├── Browser client    → generates HTTP/DNS traffic
└── VMware Workstation (host for VM1 and VM2)

VM1 (192.168.130.129) — Ubuntu 64-bit
├── FastAPI Server    → port 8001  (REST + WebSocket)
├── E3 Hub            → port 9000  (TCP telemetry ingestion)
├── SQLite DB         → mini_shark.db
└── Probe 2 (Egress)  → run_probe.py --probe-id 2

VM2 (192.168.130.128) — Ubuntu 64-bit (3)
├── Probe 1 (Ingress) → run_probe.py --probe-id 1
└── Client            → generates HTTP/DNS/ping traffic
```

---

## 3. What Laptop 2 Needs to Do

### Role of Laptop 2 in the system

```
Laptop 2 (Hrishikesh)
├── VM3 (Ubuntu) — Probe 2 (Egress observer / Server side)
│     Connects to: 192.168.130.129:9000 (VM1 E3 Hub)
│     Probe ID: 2
│
└── VM4 (Ubuntu) — Client
      Generates: HTTP, DNS, ping traffic
      Traffic observed by: VM3 Probe 2
```

> **Note:** If Laptop 2 is running Probe 2, then stop Probe 2 on VM1
> because only one Probe 2 should connect at a time.

---

## 4. Network Requirements for Cross-Laptop Connection

Both laptops must be on the **same Wi-Fi network** (same router).

### Check your Wi-Fi IP on Laptop 2

```bash
# Linux (Arch host)
ip addr show
# Look for your Wi-Fi IP e.g. 10.60.0.x

# Inside Ubuntu VM
ip addr show ens33
```

### Verify Laptop 2 can reach Laptop 1's server

```bash
# From Laptop 2 VM, ping VM1
ping 192.168.130.129

# If ping fails — use Windows Host Wi-Fi IP instead
ping 10.60.0.6
```

> **Important:** If Laptop 2's VMs are on NAT they can't reach
> `192.168.130.129` directly. Switch VMs to **Bridged networking**
> so they get a real IP on the same subnet as both laptops.

---

## 5. VM Network Mode Setup on Laptop 2

Both VMs on Laptop 2 must use **Bridged Adapter**:

### VMware:
```
VM Settings → Network Adapter → Bridged: Connected directly to the physical network
```

### VirtualBox:
```
VM Settings → Network → Adapter 1 → Attached to: Bridged Adapter
→ Name: your Wi-Fi adapter
```

After booting check VM gets IP on same subnet:
```bash
ip addr show
# Should show 10.60.x.x (same range as both laptops)
```

---

## 6. Ports to Open on Laptop 1 (Windows Firewall)

Run in **Admin PowerShell on Laptop 1**:

```powershell
# Allow Laptop 2 to reach E3 telemetry server
netsh advfirewall firewall add rule name="MiniShark E3" dir=in action=allow protocol=TCP localport=9000

# Allow Laptop 2 to reach FastAPI server
netsh advfirewall firewall add rule name="MiniShark API" dir=in action=allow protocol=TCP localport=8001

# Allow dashboard access from Laptop 2
netsh advfirewall firewall add rule name="MiniShark Dashboard" dir=in action=allow protocol=TCP localport=5173
```

---

## 7. Execution Commands

### Laptop 1 — Start Everything

**VM1 — Terminal 1 (Central Server):**
```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

**VM1 — Terminal 2 (Probe 2 — only if Laptop 2 is NOT running Probe 2):**
```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 run_probe.py --probe-id 2 --server 127.0.0.1:9000 --iface ens33
```

**VM2 — Terminal 1 (Probe 1):**
```bash
cd ~/Mini_Shark
source .venv/bin/activate
python3 run_probe.py --probe-id 1 --server 192.168.130.129:9000 --iface ens33
```

**Windows — Dashboard:**
```powershell
cd "C:\path\to\Mini_Shark\frontend"
npm run dev
# Open: http://localhost:5173
```

---

### Laptop 2 — Commands to Run

**Step 1 — Clone repo (VM3 and VM4):**
```bash
git clone https://github.com/HrishiiLit/Mini_Shark.git
cd Mini_Shark
git checkout integration
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install scapy
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)
```

**Step 2 — Find interface name:**
```bash
ip link show
# Note the UP interface e.g. ens33, eth0, enp0s3
```

**Step 3 — Verify connectivity to VM1:**
```bash
ping 192.168.130.129      # try VM1 direct
ping 10.60.0.6            # try Windows host Wi-Fi if VM1 not reachable
curl http://192.168.130.129:8001/health
# Expected: {"status":"ok"}
```

**Step 4 — Start Probe 2 (VM3):**
```bash
# Replace 192.168.130.129 with actual reachable IP
# Replace ens33 with your actual interface
python3 run_probe.py --probe-id 2 --server 192.168.130.129:9000 --iface ens33
```

**Step 5 — Generate traffic (VM4):**
```bash
ping 192.168.130.129 -i 0.5
curl http://192.168.130.129:8001/health
nslookup google.com
```

---

## 8. Dashboard Access

| From | URL | What you see |
|------|-----|-------------|
| Laptop 1 Windows | `http://localhost:5173` | Full dashboard |
| Laptop 2 browser | `http://10.60.0.6:5173` | Full dashboard (if Vite started with --host) |
| Any device on LAN | `http://10.60.0.6:5173` | Full dashboard |

To allow access from other devices, start Vite with:
```powershell
npm run dev -- --host
```

---

## 9. How to Tell Which Client's Traffic You Are Seeing

In the dashboard packet table, the **Source** column shows the IP:

| Source IP | Machine |
|-----------|---------|
| `192.168.130.128` | VM2 (Probe 1 machine — Laptop 1) |
| `192.168.130.1` | Windows Host (Laptop 1) |
| `10.60.x.x` | Laptop 2 VMs (Bridged — actual subnet IP) |

---

## 10. Final Architecture with Both Laptops

```
LAPTOP 1 (Chhavi)                    LAPTOP 2 (Hrishikesh)
─────────────────────────            ─────────────────────────
Windows Host: 10.60.0.6             Wi-Fi Host: 10.60.0.x
  └── Dashboard (5173)
                                      VM3 (Bridged: 10.60.0.y)
VM1: 192.168.130.129                   └── Probe 2 ──────────►
  ├── E3 Hub (:9000) ◄────────────────────────────────────────┘
  ├── FastAPI (:8001)                VM4 (Bridged: 10.60.0.z)
  └── Probe 2 (if L2 not ready)      └── Client (ping/HTTP/DNS)

VM2: 192.168.130.128
  └── Probe 1 ──────────────────────► VM1 E3 Hub :9000
```

---

## 11. Quick Connectivity Test Checklist

Before starting probes, verify:

```bash
# From Laptop 2 VM3
ping 192.168.130.129          ✓ VM1 reachable
curl http://192.168.130.129:8001/health  ✓ API responding
nc -zv 192.168.130.129 9000   ✓ E3 port open
```

If `192.168.130.129` is not reachable from Laptop 2, use the
Windows Wi-Fi IP `10.60.0.6` instead (VM1 can also be accessed
through the Windows host if port forwarding is set up).

---

## 12. Port Forwarding on VM1 (if needed)

If Laptop 2 cannot reach `192.168.130.129` directly, set up
port forwarding from the Windows host to VM1:

```powershell
# Forward Windows port 9000 → VM1 port 9000
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=9000 connectaddress=192.168.130.129

# Forward Windows port 8001 → VM1 port 8001  
netsh interface portproxy add v4tov4 listenport=8001 listenaddress=0.0.0.0 connectport=8001 connectaddress=192.168.130.129
```

Then Laptop 2 connects to `10.60.0.6:9000` instead of `192.168.130.129:9000`.

---

*Prepared by Chhavi Mishra (E2) · Mini-Shark Team 07*
*KLE Technological University · Hubballi, Karnataka*
