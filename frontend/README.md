# Mini-Shark — Observatory & Wireshark Frontend

**Course Project:** Network Traffic Monitoring & Protocol Analysis (`23ECNP301`)  
**Department:** Computer Science & Engineering (Artificial Intelligence), KLE Technological University  
**Team 07** · Guide: **Prof. Pooja Shettar**

---

## 1. Overview

The Mini-Shark frontend is a high-performance web dashboard built with **React 19, TypeScript, Vite, Tailwind CSS, Zustand, and React-Three-Fiber (Three.js)**. It provides two integrated visualization modes:
1. **Interactive 3D Network Topology Observatory:** Renders a WebGL scene of distributed network nodes (Clients, Intermediate Router, and Destination Server) connected by physical fiber cables. Animates real-time packet particle flights traversing quadratic Bézier curves and visualizes silent drops with expanding red shockwave rings at the exact cable location where loss occurs.
2. **Wireshark-Parity 3-Pane Protocol Inspector:** Implements the classic 3-pane packet analysis interface featuring a virtualized Packet Table, a Hierarchical Protocol Tree with invariant field highlights, and a raw Hexadecimal Viewer (Hex Dump).

---

## 2. 3-Way View Switcher (`App.tsx`)

Users can seamlessly toggle between three layout perspectives using the view switcher in the header bar:
* **Split View (Default):** Displays the 3D WebGL Topology Canvas in the top half and the Wireshark 3-Pane Inspector in the bottom half. Ideal for observing overall network topology dynamics while inspecting individual packet headers.
* **3D Topology Canvas:** Maximizes the Three.js WebGL canvas to full screen for multi-point latency monitoring, particle tracing, and silent drop localization.
* **Wireshark Panes:** Maximizes the packet inspection interface for detailed protocol debugging, layer tree traversal, and hex dump verification.

---

## 3. Component Architecture

```text
frontend/src/
├── main.tsx                   # React root mount and strict mode initialization
├── App.tsx                    # Main layout container and 3-way view switcher
├── config.ts                  # Dynamic API and WebSocket host resolution
├── types.ts                   # TypeScript interfaces matching backend models
│
├── components/
│   ├── HeaderBar.tsx          # Status badges, probe pills, client tags, Wireshark filter search
│   ├── SimulationBar.tsx      # Live vs Demo mode toggle and synthetic fault injection buttons
│   ├── TopologyView.tsx       # Three.js 3D WebGL scene with animated packet flights and drop rings
│   ├── Inspector.tsx          # Resizable bottom pane container for Table, Tree, and HexDump
│   ├── PacketTable.tsx        # Correlated packet list with status badges and transit delay deltas
│   └── ProtocolTree.tsx       # Hierarchical protocol layer tree with synchronized Hex Dump
│
├── lib/
│   ├── topology.ts            # 3D spatial node coordinates and quadratic Bézier curve math
│   └── frames.ts              # Wireshark frame parsers and mock packet generators
│
└── store/
    └── useCaptureStore.ts     # Central Zustand store (WebSocket, metrics, ring buffer, filtering)
```

### Component Details
* **`HeaderBar.tsx`**: Displays the active connection status of edge probes:
  * Ingress Probe (`[Client 1]` / `[C1]` in green)
  * Intermediate Router Probe (`[Probe 10]` in purple)
  * Egress Server Probe (`[Probe 2]` in blue)
  * Includes the Wireshark display filter input supporting live filter evaluation.
* **`SimulationBar.tsx`**: Enables switching between **Live Network** mode (real distributed probes) and **Demo Simulation** mode:
  * **Inject 5% Drop Rate:** Synthetically drops 5% of packets mid-cable with red shockwaves.
  * **Inject 60ms Delay Spike:** Introduces high transit delays and triggers Bufferbloat warnings.
  * **Run DNS Tunneling Test:** Injects high-entropy DNS queries to trigger exfiltration alerts.
* **`TopologyView.tsx`**: Three.js WebGL scene using React-Three-Fiber:
  * Computes smooth quadratic Bézier cable paths via `getClientCurve()`.
  * Renders glowing fiber cables with dynamic shader cores.
  * Animates traversing `PacketParticle` meshes based on real-time transit delay $\Delta T$.
  * Visualizes packet drops with expanding red shockwave rings at the exact cable coordinates.
* **`PacketTable.tsx`**: Virtualized list displaying:
  * Status badges (`✅ Matched`, `❌ Dropped on Wire`, `⚠️ High Latency`).
  * Client source tag (`[C1]`, `[C2]`).
  * Protocol label (`TCP`, `HTTP`, `DNS`, `UDP`, `ICMP`, `ARP`).
  * One-way transit delay $\Delta T = T_2 - T_1$ in milliseconds.
* **`ProtocolTree.tsx`**: Hierarchical tree viewer for decoded packet layers:
  * Path-invariant fields (`ip.src`, `ip.dst`, `tcp.seq`) highlighted in glowing cyan.
  * Mutable hop fields (TTL, IP checksum, MACs) displayed with strikethrough styling.
  * Includes a synchronized Hex Dump viewer displaying raw packet bytes.

---

## 4. State Management (`useCaptureStore.ts`)

Global state is managed by Zustand in `frontend/src/store/useCaptureStore.ts`:
* **WebSocket Connection:** Connects to `ws://<HOST>:8001/ws/live` to receive 1-second metric snapshots, live correlation events, and diagnostic alerts.
* **Probe Status Polling:** Polls `/probes` every 2 seconds to discover newly connected client nodes.
* **Dynamic Client Discovery:** Automatically discovers active client source IPs and generates corresponding 3D spatial nodes and Bézier cables.
* **Ring Buffer:** Maintains a high-speed ring buffer of recent packets (up to 240 frames) to ensure smooth 60 FPS rendering without memory leaks.
* **Display Filtering:** Implements in-memory filter matching (`packetMatchesFilter`) for instant search feedback.

---

## 5. Development & Build Setup

### Prerequisites
* Node.js 18+ and npm.

### Quick Start
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your web browser.

### Remote Backend Configuration
When running the frontend on a different machine than the backend:
```bash
# Point to remote server hub IP
VITE_API_HOST=http://192.168.1.20:8001 npm run dev
```
*(By default, `frontend/src/config.ts` automatically infers the backend IP from the current browser URL).*

### Production Build
```bash
npm run build
```
Build output is generated in `frontend/dist/`.
