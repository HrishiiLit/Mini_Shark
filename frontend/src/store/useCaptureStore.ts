import { create } from 'zustand'
import { buildPacket, dnsPayload, httpPayload } from '../lib/frames'
import { DEFAULT_CLIENTS } from '../lib/topology'
import type { ClientNodeInfo, Flight, Packet } from '../types'
import { API, WS } from '../config'

const MAX_PACKETS = 240
const MAX_FLIGHTS = 18

export interface ProbesStatus {
  probe1_connected: boolean
  probe1_ip: string | null
  probe2_connected: boolean
  probe2_ip: string | null
  active_clients: Array<{ ip: string; probe_id: number; records: number }>
  total_connected: number
}

interface CaptureState {
  packets: Packet[]
  flights: Flight[]
  selectedId: number | null
  frozenFlightId: string | null
  running: boolean
  demoMode: boolean
  clientCount: number
  clients: ClientNodeInfo[]
  probesStatus: ProbesStatus
  dropRate: number
  delaySpikeMs: number
  dnsBurst: number
  filter: string
  seq: number
  baseTime: number
  memoryMb: number
  fps: number
  serverRipple: number
  lastDropHash: string | null
  lastDropAt: number
  wsConnected: boolean
  viewMode: 'wireshark' | 'observatory' | 'split'
  autoScroll: boolean
  setViewMode: (mode: 'wireshark' | 'observatory' | 'split') => void
  setAutoScroll: (enabled: boolean) => void
  clearPackets: () => void
  setDemoMode: (enabled: boolean) => void
  setClientCount: (count: number) => void
  start: () => void
  pause: () => void
  startLiveCapture: () => void
  stopLiveCapture: () => void
  setFilter: (filter: string) => void
  selectPacket: (id: number | null, flightId?: string | null) => void
  injectDropRate: () => void
  injectDelaySpike: () => void
  runDnsTest: () => void
  tickTraffic: (now: number) => void
  completeFlight: (flightId: string, packetId: number, kind: Flight['kind']) => void
  resolvePacket: (packetId: number, kind: Flight['kind']) => void
  setFps: (fps: number) => void
  setProbesStatus: (status: ProbesStatus) => void
}

function rand(min: number, max: number) {
  return min + Math.random() * (max - min)
}

function randInt(min: number, max: number) {
  return Math.floor(rand(min, max + 1))
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function randomHex(n: number) {
  return Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join('')
}

export const useCaptureStore = create<CaptureState>((set, get) => ({
  packets: [],
  flights: [],
  selectedId: null,
  frozenFlightId: null,
  running: true,
  demoMode: false,
  clientCount: 2,
  clients: DEFAULT_CLIENTS,
  probesStatus: {
    probe1_connected: false,
    probe1_ip: null,
    probe2_connected: false,
    probe2_ip: null,
    active_clients: [],
    total_connected: 0,
  },
  dropRate: 0,
  delaySpikeMs: 0,
  dnsBurst: 0,
  filter: '',
  seq: 1,
  baseTime: 1_704_000_000_000_000,
  memoryMb: 36.4,
  fps: 60,
  serverRipple: 0,
  lastDropHash: null,
  lastDropAt: 0,
  wsConnected: false,
  viewMode: 'wireshark',
  autoScroll: true,
  setViewMode: (viewMode) => set({ viewMode }),
  setAutoScroll: (autoScroll) => set({ autoScroll }),
  clearPackets: () => set({ packets: [], flights: [], selectedId: null, seq: 1 }),

  setDemoMode: (enabled: boolean) => {
    set({ demoMode: enabled, running: enabled })
  },

  setClientCount: (count: number) => {
    const clamped = Math.max(1, Math.min(DEFAULT_CLIENTS.length, count))
    set({ clientCount: clamped })
  },

  setProbesStatus: (status: ProbesStatus) => {
    // Collect unique client probes (excluding probe 2 which is egress)
    const clientProbesMap = new Map<number, { ip: string; probe_id: number; records: number }>()
    for (const p of status.active_clients || []) {
      if (p.probe_id !== 2) {
        if (!clientProbesMap.has(p.probe_id) || (p.records ?? 0) >= (clientProbesMap.get(p.probe_id)?.records ?? 0)) {
          clientProbesMap.set(p.probe_id, p)
        }
      }
    }
    const clientProbes = Array.from(clientProbesMap.values())
    const detectedClients = clientProbes.length

    set((s) => {
      // Dynamically update client definitions with actual probe IPs and probe IDs
      const updatedClients = s.clients.map((c, i) => {
        if (i < clientProbes.length) {
          const cp = clientProbes[i]
          const isArch = cp.ip.startsWith('10.108.') || cp.probe_id === 3
          return {
            ...c,
            ip: cp.ip,
            name: isArch ? 'Laptop 2 (Arch Host)' : `w2 (Client ${i + 1})`,
            probeBadge: `Probe ${cp.probe_id} · Ingress (${isArch ? 'wlo1' : 'VMnet1'})`,
            vm: isArch ? 'Arch Linux Host' : 'Laptop 1 (VM2)',
          }
        }
        return c
      })

      // In live network mode: reflect the actual number of connected client probes (minimum 2 for multi-client view)
      const newClientCount = !s.demoMode && detectedClients > 0 ? Math.max(2, detectedClients) : s.clientCount

      return {
        probesStatus: status,
        clients: updatedClients,
        clientCount: newClientCount,
      }
    })
  },

  start: () => set({ running: true }),
  pause: () => set({ running: false }),

  startLiveCapture: () => {
    const state = useCaptureStore.getState()

    // If real probes are already connected → just activate live mode
    // Real packets arrive via WebSocket correlation events — no SSE needed
    if (state.probesStatus.probe1_connected || state.probesStatus.probe2_connected) {
      set({ running: true, demoMode: false })
      return
    }

    // No probes connected → fall back to SSE stream from server
    const existingAbort = (window as any).__miniSharkAbort as AbortController | null
    if (existingAbort) { existingAbort.abort(); (window as any).__miniSharkAbort = null }

    set({ running: true, demoMode: false, packets: [], flights: [] })

    const controller = new AbortController()
    ;(window as any).__miniSharkAbort = controller
    ;(window as any).__miniSharkSessionId = null

    ;(async () => {
      try {
        const res = await fetch(`${API}/captures/stream`, {
          signal: controller.signal,
        })
        if (!res.ok || !res.body) return

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''

        while (true) {
          const { value, done } = await reader.read()
          if (done) break

          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''

          for (const line of lines) {
            const trimmed = line.trim()
            if (!trimmed.startsWith('data:')) continue
            if (controller.signal.aborted) return

            try {
              const msg = JSON.parse(trimmed.slice(5).trim())

              // Save session_id so stop can call the server endpoint
              if (msg.type === 'started' && msg.session_id) {
                ;(window as any).__miniSharkSessionId = msg.session_id
              }

              if (msg.type === 'stopped') return
              if (msg.type !== 'packet') continue

              const state = useCaptureStore.getState()
              if (!state.running) return

              const status: Packet['status'] =
                msg.dns_exfil_suspect ? 'dropped' : 'matched'

              const rawIpId = Number(msg.ip_id) || 0
              const ipId = rawIpId > 0 ? rawIpId : randInt(0x1000, 0xffee)
              const tcpSeq = msg.tcp_seq != null ? Number(msg.tcp_seq) : undefined

              const packet = buildPacket({
                id: state.seq,
                timeUs: Math.round((msg.timestamp ?? Date.now() / 1000) * 1_000_000),
                protocol: (msg.protocol || 'TCP') as any,
                srcPort: Number(msg.src_port) || 0,
                dstPort: Number(msg.dst_port) || 0,
                ipId,
                tcpSeq,
                ttl: 64,
                payload: [],
                status,
                deltaTms: undefined,
                note: msg.dns_exfil_suspect ? `DNS H=${msg.dns_entropy}` : undefined,
                srcIp: msg.src_ip || '',
                dstIp: msg.dst_ip || '',
                hash64: msg.fingerprint || undefined,
              })

              useCaptureStore.setState((s) => ({
                seq: s.seq + 1,
                packets: [packet, ...s.packets].slice(0, MAX_PACKETS),
              }))
            } catch {}
          }
        }
      } catch (err: any) {
        if (err?.name === 'AbortError') return
      } finally {
        useCaptureStore.setState({ running: false })
      }
    })()
  },

  stopLiveCapture: () => {
    // 1. Tell the SERVER to stop via session_id
    const sessionId = (window as any).__miniSharkSessionId
    if (sessionId) {
      fetch(`${API}/captures/stream/stop?session_id=${sessionId}`).catch(() => {})
      ;(window as any).__miniSharkSessionId = null
    }

    // 2. Abort the fetch stream on the client side
    const controller = (window as any).__miniSharkAbort as AbortController | null
    if (controller) {
      controller.abort()
      ;(window as any).__miniSharkAbort = null
    }

    set({ running: false })
  },
  setFilter: (filter) => set({ filter }),

  selectPacket: (id, flightId) =>
    set({
      selectedId: id,
      frozenFlightId: flightId ?? (id == null ? null : get().frozenFlightId),
    }),

  injectDropRate: () => set({ dropRate: 0.05, running: true, demoMode: true }),
  injectDelaySpike: () => set({ delaySpikeMs: 60, running: true, demoMode: true }),
  runDnsTest: () => set({ dnsBurst: 8, running: true, demoMode: true }),

  resolvePacket: (packetId, kind) => {
    set((s) => ({
      serverRipple: kind === 'drop' ? s.serverRipple : Date.now(),
      packets: s.packets.map((p) =>
        p.id === packetId && p.status === 'in-flight'
          ? {
              ...p,
              status: kind === 'drop' ? 'dropped' : kind === 'slow' ? 'high-latency' : 'matched',
            }
          : p,
      ),
    }))
  },

  completeFlight: (flightId, packetId, kind) => {
    set((s) => ({
      flights: s.flights.filter((f) => f.id !== flightId),
    }))
    get().resolvePacket(packetId, kind)
  },

  setFps: (fps) => set({ fps }),

  tickTraffic: (now) => {
    const s = get()
    if (!s.running) return
    // If real probes are connected — do NOT generate fake demo traffic
    // Real packets come via WebSocket correlation events
    if (s.probesStatus.probe1_connected || s.probesStatus.probe2_connected) return
    if (!s.demoMode) return

    const dnsMode = s.dnsBurst > 0
    const protocol = dnsMode ? 'DNS' : pick(['TCP', 'TCP', 'TCP', 'UDP', 'DNS', 'ICMP'] as const)

    const drop = Math.random() < s.dropRate
    const spike = s.delaySpikeMs > 0 && Math.random() < 0.55
    const jitter = rand(1.8, 6.4)
    const deltaTms = drop ? undefined : spike ? rand(60, 78) : jitter
    const kind: Flight['kind'] = drop ? 'drop' : spike || (deltaTms ?? 0) > 20 ? 'slow' : 'normal'

    const clientIdx = Math.floor(Math.random() * s.clientCount)
    const client = s.clients[clientIdx] || s.clients[0]

    const srcPort = protocol === 'DNS' ? randInt(53000, 58000) : protocol === 'ICMP' ? 0 : randInt(49152, 60999)
    const dstPort = protocol === 'TCP' ? 80 : protocol === 'DNS' ? 53 : protocol === 'UDP' ? 443 : 0
    const ipId = randInt(0x1000, 0xffee)
    const tcpSeq = protocol === 'TCP' ? randInt(100000, 9_000_000) : undefined
    const payload =
      protocol === 'TCP'
        ? httpPayload()
        : protocol === 'DNS'
          ? dnsPayload(
              dnsMode
                ? `${randomHex(18)}.exfil.tunnel.lab`
                : pick(['www.kle.ac.in', 'ntp.ubuntu.com', 'api.minishark.lab']),
            )
          : protocol === 'ICMP'
            ? Array.from({ length: 32 }, () => randInt(0, 255))
            : Array.from({ length: 24 }, () => randInt(32, 126))

    const packet = buildPacket({
      id: s.seq,
      timeUs: s.baseTime + s.seq * 97_331 + randInt(0, 800),
      protocol,
      srcPort,
      dstPort,
      ipId,
      tcpSeq,
      ttl: 63,
      payload,
      status: 'in-flight',
      deltaTms,
      note: dnsMode ? 'DNS tunneling probe (long QNAME)' : drop ? 'Silent drop on the wire' : undefined,
      srcIp: s.probesStatus.probe1_ip || client.ip,
      clientId: clientIdx,
    })

    const duration =
      kind === 'drop' ? 1.15 : kind === 'slow' ? 2.6 + ((deltaTms ?? 60) - 60) * 0.04 : 0.85 + (deltaTms ?? 4) * 0.04

    const flight: Flight = {
      id: `f-${packet.id}`,
      packetId: packet.id,
      hash64: packet.hash64,
      kind,
      duration,
      spawnedAt: now,
      clientId: clientIdx,
      srcIp: packet.srcIp,
    }

    set({
      seq: s.seq + 1,
      selectedId: s.selectedId ?? packet.id,
      dnsBurst: Math.max(0, s.dnsBurst - (dnsMode ? 1 : 0)),
      delaySpikeMs: Math.max(0, s.delaySpikeMs - (spike ? 12 : 4)),
      dropRate: s.dropRate > 0 ? Math.max(0, s.dropRate - 0.002) : 0,
      memoryMb: 36 + Math.min(24, s.packets.length * 0.11) + Math.sin(now / 900) * 0.4,
      lastDropHash: drop ? packet.hash64 : s.lastDropHash,
      lastDropAt: drop ? now : s.lastDropAt,
      packets: [packet, ...s.packets].slice(0, MAX_PACKETS),
      flights: [flight, ...s.flights].slice(0, MAX_FLIGHTS),
    })

    window.setTimeout(() => {
      get().resolvePacket(packet.id, kind)
    }, duration * 1000)
  },
}))

// Live WebSocket integration + Probe Health Check
if (typeof window !== 'undefined') {
  const wsHost = window as Window & { __miniSharkWS?: WebSocket }

  function fetchProbesStatus() {
    fetch(`${API}/probes`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then((data: ProbesStatus) => {
        if (data && typeof data.total_connected === 'number') {
          useCaptureStore.getState().setProbesStatus(data)
        }
      })
      .catch(() => {})
  }

  // Poll probe status every 2 seconds
  fetchProbesStatus()
  setInterval(fetchProbesStatus, 2000)

  function connectWs() {
    try {
      const ws = new WebSocket(WS)
      wsHost.__miniSharkWS = ws
      ws.onopen = () => {
        useCaptureStore.setState({ wsConnected: true })
        fetchProbesStatus()
      }
      ws.onmessage = ({ data }) => {
        try {
          const msg = JSON.parse(data)

          // 1. Metrics and probe status updates from server
          if (msg.type === 'metrics' && msg.probes) {
            useCaptureStore.getState().setProbesStatus(msg.probes)
          }

          // 2. Real-time correlation events from active probe daemons
          if (msg.type === 'correlation') {
            const isDrop = msg.match_state?.includes('unmatched')
            const isSlow = msg.delay_ms != null && Number(msg.delay_ms) > 20
            const status: Packet['status'] = isDrop ? 'dropped' : isSlow ? 'high-latency' : 'matched'
            const kind: Flight['kind'] = isDrop ? 'drop' : isSlow ? 'slow' : 'normal'

            const state = useCaptureStore.getState()
            const activeClientProbes = (state.probesStatus.active_clients || []).filter((p) => p.probe_id !== 2)
            const uniqueProbes = Array.from(new Set(activeClientProbes.map((p) => p.probe_id)))

            let clientIdx = 0
            if (uniqueProbes.length <= 1) {
              // If only one client probe is connected, route all events to active Client 1
              clientIdx = 0
            } else if (msg.client_id !== undefined && msg.client_id < state.clientCount) {
              clientIdx = msg.client_id
            } else if (msg.src_ip) {
              const idx = state.clients.findIndex((c) => c.ip === msg.src_ip)
              if (idx !== -1 && idx < state.clientCount) clientIdx = idx
            } else if (msg.probe_id && msg.probe_id !== 2) {
              clientIdx = msg.probe_id === 1 ? 0 : 1
            } else {
              clientIdx = state.seq % Math.max(1, state.clientCount)
            }

            if (clientIdx >= state.clientCount) {
              clientIdx = 0
            }

            const client = state.clients[clientIdx] || state.clients[0]
            const srcIp = msg.src_ip || client.ip

            const id = state.seq
            const now = performance.now()
            const deltaTms = msg.delay_ms != null ? Number(msg.delay_ms) : undefined

            const ipId =
              msg.probe1_seq != null
                ? (((msg.probe1_seq * 137) & 0xffff) || randInt(0x1000, 0xffee))
                : randInt(0x1000, 0xffee)
            const tcpSeq =
              msg.probe1_seq != null
                ? 100000 + msg.probe1_seq * 1460
                : undefined

            const packet = buildPacket({
              id,
              timeUs: msg.t1_ns ? Math.round(msg.t1_ns / 1000) : 1_704_000_000_000_000 + id * 97_331,
              protocol: (msg.proto || 'TCP').toUpperCase() as any,
              srcPort: msg.src_port || 54210,
              dstPort: msg.dst_port || 80,
              ipId,
              tcpSeq,
              ttl: 63,
              payload: httpPayload(),
              status,
              deltaTms,
              note: isDrop
                ? `Silent drop on wire (timeout 500ms)`
                : msg.fingerprint
                  ? `fp: ${msg.fingerprint}`
                  : undefined,
              srcIp,
              dstIp: msg.dst_ip || '192.168.130.129',
              clientId: clientIdx,
              hash64: msg.fingerprint || undefined,
            })

            const duration = kind === 'drop' ? 1.15 : kind === 'slow' ? 2.6 : 0.85
            const flight: Flight = {
              id: `f-${packet.id}`,
              packetId: packet.id,
              hash64: packet.hash64,
              kind,
              duration,
              spawnedAt: now,
              clientId: clientIdx,
              srcIp,
            }

            useCaptureStore.setState((s) => ({
              seq: s.seq + 1,
              selectedId: s.selectedId ?? packet.id,
              packets: [packet, ...s.packets].slice(0, MAX_PACKETS),
              flights: [flight, ...s.flights].slice(0, MAX_FLIGHTS),
              lastDropHash: isDrop ? packet.hash64 : s.lastDropHash,
              lastDropAt: isDrop ? now : s.lastDropAt,
            }))

            window.setTimeout(() => {
              useCaptureStore.getState().resolvePacket(packet.id, kind)
            }, duration * 1000)
          }
        } catch {}
      }
      ws.onclose = () => {
        useCaptureStore.setState({ wsConnected: false })
        setTimeout(connectWs, 3000)
      }
      ws.onerror = () => {
        ws.close()
      }
    } catch {}
  }
  connectWs()
}

const tickHost = window as Window & { __miniSharkTick?: number }
if (tickHost.__miniSharkTick) window.clearInterval(tickHost.__miniSharkTick)
tickHost.__miniSharkTick = window.setInterval(() => {
  useCaptureStore.getState().tickTraffic(performance.now())
}, 100)

export function packetMatchesFilter(packet: Packet, filter: string): boolean {
  const q = filter.trim().toLowerCase()
  if (!q) return true

  const clauses = q.split(/\s*&&\s*/)
  return clauses.every((clause) => {
    const orParts = clause.split(/\s*\|\|\s*/)
    return orParts.some((part) => matchAtom(packet, part.trim()))
  })
}

function matchAtom(packet: Packet, atom: string): boolean {
  if (!atom) return true
  if (atom === 'tcp') return packet.protocol === 'TCP'
  if (atom === 'udp') return packet.protocol === 'UDP'
  if (atom === 'dns') return packet.protocol === 'DNS'
  if (atom === 'icmp') return packet.protocol === 'ICMP'
  if (atom === 'drop' || atom.includes('dropped')) return packet.status === 'dropped'
  if (atom === 'latency' || atom.includes('high-latency') || atom.includes('slow'))
    return packet.status === 'high-latency'
  if (atom === 'matched') return packet.status === 'matched'

  const eq = atom.match(/^([a-z0-9._]+)\s*==\s*(.+)$/)
  if (eq) {
    const [, key, raw] = eq
    const val = raw.replace(/['"]/g, '')
    if (key === 'ip.addr') return packet.srcIp === val || packet.dstIp === val
    if (key === 'ip.src') return packet.srcIp === val
    if (key === 'ip.dst') return packet.dstIp === val
    if (key === 'client' || key === 'client.id')
      return (packet.clientId ?? 0) === Number(val) - 1 || String(packet.clientId) === val
    if (key === 'tcp.port')
      return packet.protocol === 'TCP' && (packet.srcPort === Number(val) || packet.dstPort === Number(val))
    if (key === 'udp.port')
      return (
        (packet.protocol === 'UDP' || packet.protocol === 'DNS') &&
        (packet.srcPort === Number(val) || packet.dstPort === Number(val))
      )
    if (key === 'frame.len') return packet.length === Number(val)
  }

  return (
    packet.hash64.toLowerCase().includes(atom) ||
    packet.srcIp.includes(atom) ||
    packet.dstIp.includes(atom) ||
    packet.protocol.toLowerCase() === atom
  )
}
