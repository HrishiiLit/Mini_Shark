# Mini-Shark Physical Implementation Guide (3 Laptops Pilot → 8+ Lab PCs)

Use a two-stage rollout so you validate routing, clocks, telemetry batching, and drop localization on **3 laptops first**, and only then add the remaining lab PCs.

---

## Topology Overview

```text
[Client PC(s) (Auto Probe ID)] ─── Link 1 ───▶ [Linux Router Laptop (Probe 10)] ─── Link 2 ───▶ [Server Hub Laptop (Probe 2)]
                                                eth_in (Link 1) <-> eth_out (Link 2)               Backend :8001 + E3 Hub :9000
                                                Pure L3 IP Forwarding (NO NAT!)                    React + Three.js UI :5173
```

---

## Stage 1: 3-Laptop Pilot Deployment (Prove End-to-End First)

Start with **exactly 3 laptops** before involving a lab switch or 8+ machines.

### Hardware & Addressing Plan (Example Subnets)

| Role | Laptop OS | Interfaces | Example IP / Subnet | Probe ID |
| --- | --- | --- | --- | --- |
| **Laptop 1 — Central Server Hub** | Linux or Windows | 1 NIC (`Link 2`) | `192.168.20.2/24` (GW `192.168.20.1`) | **Probe 2** (`--role server`) |
| **Laptop 2 — Intermediate Router** | **Linux** | 2 NICs (`IFACE_LINK1` + `IFACE_LINK2`, e.g., Ethernet + USB-Ethernet adapter) | Link 1 NIC: `192.168.10.1/24`<br>Link 2 NIC: `192.168.20.1/24` | **Probe 10** (`--role router`) |
| **Laptop 3 — Client** | Linux or Windows | 1 NIC (`Link 1`) | `192.168.10.11/24` (GW `192.168.10.1`) | **Auto (`11`)** from `.11` |

> **Why two subnets?** Putting Clients on `192.168.10.0/24` and the Server on `192.168.20.0/24` forces every packet to physically cross Laptop 2 (`Link 1 → Router → Link 2`), instead of bypassing the router on a shared L2 subnet.
>
> **If testing quickly on 1 shared Wi-Fi/LAN without separate Ethernet cables:** Run without the router (`Link 1 == LAN`) first just to verify Client Probe → Server Hub (`Probe 2`), then add Laptop 2 as the two-NIC router for Link 1 vs Link 2 drop isolation.

---

### Step 1.1 — Prepare Static Routes & Clocks Across the 3 Laptops

1. **Identify real interface names on Laptop 2 (Router):**
   ```bash
   ip -br addr
   ```
   *(Modern Linux names are often `enp...`, `eno1`, `wlan0`, or `enx...` rather than `eth0`/`eth1`.)*

2. **Add static routes (if not using DHCP gateways pointing through Laptop 2):**
   * **On Laptop 3 (Client):** route server subnet `192.168.20.0/24` via Router Link 1 IP `192.168.10.1`:
     * Linux: `sudo ip route add 192.168.20.0/24 via 192.168.10.1`
     * Windows (Admin CMD): `route add 192.168.20.0 mask 255.255.255.0 192.168.10.1`
   * **On Laptop 1 (Server Hub):** route client subnet `192.168.10.0/24` via Router Link 2 IP `192.168.20.1`:
     * Linux: `sudo ip route add 192.168.10.0/24 via 192.168.20.1`
     * Windows (Admin CMD): `route add 192.168.10.0 mask 255.255.255.0 192.168.20.1`

3. **Open Server Firewall Ports on Laptop 1:**
   * Allow inbound **TCP `9000`** (E3 telemetry), **TCP `8001`** (FastAPI + WebSocket `/ws/live`), **TCP `5173`** (Vite UI), and **UDP `9500`** (for `traffic_generator.py --mode udp-stream`).
   * Linux UFW example:
     ```bash
     sudo ufw allow 9000/tcp && sudo ufw allow 8001/tcp && sudo ufw allow 5173/tcp && sudo ufw allow 9500/udp
     ```

4. **Check Clock Synchronization (prevents `CLOCK_SKEW_SUSPECT` on `ΔT = T2 - T1`):**
   * Linux: `timedatectl status` or `chronyc tracking`
   * Windows: `w32tm /query /status`

---

### Step 1.2 — Start Laptop 1 (Central Server Hub + Egress Probe 2 + UI)

1. **Terminal 1 — Start Backend (`:8001`) & E3 Telemetry Hub (`:9000`):**
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
   ```
   *(Windows PowerShell: activate `.\.venv\Scripts\Activate.ps1`, then `python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001`.)*  
   Verify expected log: `[E3] TCP ingestion server listening on 0.0.0.0:9000`.

2. **Terminal 2 — Start React Dashboard (`:5173`):**
   ```bash
   cd frontend
   npm install
   VITE_API_HOST=http://192.168.20.2:8001 npm run dev
   ```
   *(Replace `192.168.20.2` with Laptop 1's LAN IP. Open `http://192.168.20.2:5173` in the browser; if viewing locally on Laptop 1 via `http://localhost:5173`, passing `VITE_API_HOST=http://127.0.0.1:8001` prevents fallback to the default testbed IP in `frontend/src/config.ts`.)*

3. **Terminal 3 — Start Egress Probe 2 (`--role server`):**
   * **Linux:**
     ```bash
     sudo python3 run_probe.py --server 127.0.0.1:9000 --role server --iface <LINK2_IFACE>
     ```
   * **Windows (Administrator CMD; requires [Npcap](https://npcap.com) + `pip install scapy`):**
     ```cmd
     python run_probe.py --server 127.0.0.1:9000 --role server
     ```

---

### Step 1.3 — Start Laptop 2 (Intermediate Linux Router + Probe 10)

1. **Enable Pure Layer-3 Forwarding (NO NAT):**
   ```bash
   sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh enable-routing
   ```
   Confirm `curl http://192.168.20.2:8001/health` works from Laptop 3 (Client) before starting probes.

2. **Start Router Probe 10:**
   ```bash
   sudo ./run_probe.sh --server 192.168.20.2:9000 --role router --iface <LINK2_IFACE>
   ```
   *(Linux probes only need Python 3 stdlib — no `pip install` or `.venv` required.)*

---

### Step 1.4 — Start Laptop 3 (Client Probe + Workload)

1. **Start Client Probe (Auto Probe ID from IP):**
   * **Linux:**
     ```bash
     sudo ./run_probe.sh --server 192.168.20.2:9000
     ```
   * **Windows (Administrator CMD; requires [Npcap](https://npcap.com) + `pip install scapy`):**
     ```cmd
     run_probe.bat --server 192.168.20.2:9000
     ```

2. **Generate Real Traffic (second terminal on Laptop 3):**
   ```bash
   # Mixed HTTP + UDP streaming workload
   python3 scripts/traffic_generator.py --target 192.168.20.2 --mode mixed --rate 10
   ```
   *(Or quick sanity checks: `ping 192.168.20.2`, `curl http://192.168.20.2:8001/health`, `python3 test_anomalies.py --dns --target 192.168.20.2`.)*

---

### Step 1.5 — Stage 1 Verification Checklist (Must Pass on 3 Laptops Before Scaling)

1. **Connectivity:** Dashboard (`:5173`) shows Client Probe (`11`), Router Probe (`10`), and Server Probe (`2`) connected.
2. **Normal Traffic:** Mixed HTTP/UDP packets show green `matched` status with steady `ΔT = T2 - T1`.
3. **Link 1 Drop Localization (`Client ──✖──> Router`):**
   ```bash
   # On Laptop 2 (Router)
   sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh drop-link1 20
   ```
   Confirm dashboard marks unmatched packets as **`link_1`** drops (or inject loss on Laptop 3 egress `tc qdisc add dev <client_iface> root netem loss 20%`).
4. **Link 2 Drop Localization (`Router ──✖──> Server`):**
   ```bash
   sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh drop-link2 20
   ```
   Confirm Probe 10 saw the packet before `tc netem` dropped it on egress → dashboard attributes drops to **`link_2`**.
5. **Restore Clean Link:**
   ```bash
   sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh clear-drops
   ```

---

## Stage 2: Scaling to 8–50 Physical Lab PCs

Once Stage 1 works cleanly on 3 laptops, scale up without changing server code or probe IDs manually.

### Step 2.1 — Physical Switch & Subnet Layout

```text
[Student PC 1 (.11)] ──┐
[Student PC 2 (.12)] ──┼──▶ [L2 Switch / Lab AP] ──Link 1──▶ [Linux Router (Probe 10)] ──Link 2──▶ [Server Hub (Probe 2)]
  ...                  │       192.168.10.0/24                 192.168.10.1 / 192.168.20.1            192.168.20.2
[Student PC 8 (.18)] ──┘
```

* Keep **Laptop 1 (Server Hub)** and **Laptop 2 (Router)** running identically from Stage 1.
* Connect PCs 1..8 (up to 50) to an L2 switch / lab subnet plugged into the Router's `Link 1` NIC (`192.168.10.0/24`), with gateway/route to `192.168.20.0/24` via `192.168.10.1`.

### Step 2.2 — Launch Probes Across All 8+ Client PCs

On every Linux PC (no `pip install` needed):
```bash
sudo ./run_probe.sh --server 192.168.20.2:9000
```

On every Windows PC (Administrator CMD after installing Npcap + `pip install scapy`):
```cmd
run_probe.bat --server 192.168.20.2:9000
```

* **Zero ID collisions automatically:** `_auto_probe_id()` in `run_probe.py` assigns each PC's probe ID from its last IPv4 octet (and offsets `.2` → `102`, `.10` → `110` so clients never collide with Server Probe `2` or Router Probe `10`).
* **Low bandwidth across 8–50 PCs:** Each PC packs `24 B` records into `<= 1,200 B` (`50`-packet) batches or flushes partial batches every `20 ms` with `TCP_NODELAY=1`, while `is_infra` excludes `:9000`, `:5173`, `:22`, `/probes`, `/ws`, and broadcast/multicast noise.

### Step 2.3 — Run Concurrent Lab Workloads & Fault Demos

Have different subsets of the 8 PCs generate varied traffic simultaneously:

```bash
# Group A (PCs 1–3): HTTP REST traffic
python3 scripts/traffic_generator.py --target 192.168.20.2 --mode http --rate 5

# Group B (PCs 4–6): UDP media streaming (1024B frames)
python3 scripts/traffic_generator.py --target 192.168.20.2 --mode udp-stream --rate 25

# Group C (PCs 7–8): Mixed workload
python3 scripts/traffic_generator.py --target 192.168.20.2 --mode mixed --rate 10
```

Demonstrate live diagnostics from the Router laptop:
```bash
# Inject 75ms bufferbloat latency on Link 2
sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh delay <LINK2_IFACE> 75

# Inject 20% Link 2 packet loss
sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh drop-link2 20

# Clear all injected faults
sudo IFACE_LINK1=<LINK1_IFACE> IFACE_LINK2=<LINK2_IFACE> ./scripts/setup_router.sh clear-drops
```

---

## Common Pitfalls & Fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Browser on `:5173` shows disconnected / hits `10.108.157.2:8001` | Opened `http://localhost:5173` without setting `VITE_API_HOST` | Open `http://<SERVER_IP>:5173` or launch Vite with `VITE_API_HOST=http://<SERVER_IP>:8001 npm run dev` |
| Router captures nothing or `setup_router.sh` says device not found | Laptop NICs aren't named `eth0`/`eth1` | Check `ip -br addr` and pass `IFACE_LINK1=... IFACE_LINK2=...` + `--iface ...` |
| Zero matched packets across Router | NAT/Masquerade enabled on router | Keep pure L3 forwarding only (`setup_router.sh enable-routing`, no `MASQUERADE`) so IP/Port headers stay identical |
| Many `CLOCK_SKEW_SUSPECT` flags | Client/Server clocks drifted | Sync system clocks via NTP/Chrony before measuring `ΔT` |
| Windows probe fails with Scapy/Npcap error | Missing Npcap or non-Admin shell | Install [Npcap](https://npcap.com), `pip install scapy`, and run CMD/PowerShell as Administrator |
