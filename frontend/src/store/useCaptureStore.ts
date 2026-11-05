import { create } from 'zustand'
import { buildPacket, dnsPayload, httpPayload } from '../lib/frames'
import { DEFAULT_CLIENTS } from '../lib/topology'
import type { ClientNodeInfo, Flight, Packet } from '../types'
import { WS } from '../config'

const MAX_PACKETS = 240
const MAX_FLIGHTS = 18

interface CaptureState {
  packets: Packet[]
  flights: Flight[]
  selectedId: number | null
  frozenFlightId: string | null
  running: boolean
  clientCount: number
  clients: ClientNodeInfo[]
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
  setClientCount: (count: number) => void
  start: () => void
  pause: () => void
  setFilter: (filter: string) => void
  selectPacket: (id: number | null, flightId?: string | null) => void
  injectDropRate: () => void
  injectDelaySpike: () => void
  runDnsTest: () => void
  tickTraffic: (now: number) => void
  completeFlight: (flightId: string, packetId: number, kind: Flight['kind']) => void
  resolvePacket: (packetId: number, kind: Flight['kind']) => void
  setFps: (fps: number) => void
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

function seedPackets(clients: ClientNodeInfo[]): Packet[] {
  const specs: Array<{
    clientIdx: number
    protocol: Packet['protocol']
    srcPort: number
    dstPort: number
    ipId: number
    tcpSeq?: number
    status: Packet['status']
    deltaTms?: number
    note?: string
  }> = [
    { clientIdx: 0, protocol: 'TCP', srcPort: 54210, dstPort: 80, ipId: 0x4b21, tcpSeq: 1_042_918, status: 'matched', deltaTms: 4.2 },
    { clientIdx: 1, protocol: 'DNS', srcPort: 53112, dstPort: 53, ipId: 0x9a4f, status: 'dropped', note: 'Silent drop on the wire' },
    { clientIdx: 0, protocol: 'TCP', srcPort: 49881, dstPort: 80, ipId: 0x71c0, tcpSeq: 2_881_044, status: 'high-latency', deltaTms: 68.1 },
    { clientIdx: 1, protocol: 'ICMP', srcPort: 0, dstPort: 0, ipId: 0x12ab, status: 'matched', deltaTms: 3.4 },
  ]
  return specs.map((spec, i) => {
    const c = clients[spec.clientIdx] || clients[0]
    return buildPacket({
      id: i + 1,
      timeUs: 1_704_000_000_000_000 + (i + 1) * 97_331,
      protocol: spec.protocol,
      srcPort: spec.srcPort,
      dstPort: spec.dstPort,
      ipId: spec.ipId,
      tcpSeq: spec.tcpSeq,
      ttl: 63,
      payload:
        spec.protocol === 'TCP'
          ? httpPayload()
          : spec.protocol === 'DNS'
            ? dnsPayload('www.kle.ac.in')
            : Array.from({ length: 32 }, () => 48 + i),
      status: spec.status,
      deltaTms: spec.deltaTms,
      note: spec.note,
      srcIp: c.ip,
      clientId: spec.clientIdx,
    })
  })
}

export const useCaptureStore = create<CaptureState>((set, get) => ({
  packets: seedPackets(DEFAULT_CLIENTS),
  flights: [],
  selectedId: 1,
  frozenFlightId: null,
  running: false,
  clientCount: 2,
  clients: DEFAULT_CLIENTS,
  dropRate: 0,
  delaySpikeMs: 0,
  dnsBurst: 0,
  filter: '',
  seq: 5,
  baseTime: 1_704_000_000_000_000,
  memoryMb: 38.2,
  fps: 60,
  serverRipple: 0,
  lastDropHash: null,
  lastDropAt: 0,
  wsConnected: false,

  setClientCount: (count: number) => {
    const clamped = Math.max(1, Math.min(DEFAULT_CLIENTS.length, count))
    set({ clientCount: clamped })
  },

  start: () => set({ running: true }),
  pause: () => set({ running: false }),
  setFilter: (filter) => set({ filter }),

  selectPacket: (id, flightId) =>
    set({
      selectedId: id,
      frozenFlightId: flightId ?? (id == null ? null : get().frozenFlightId),
    }),

  injectDropRate: () => set({ dropRate: 0.05, running: true }),
  injectDelaySpike: () => set({ delaySpikeMs: 60, running: true }),
  runDnsTest: () => set({ dnsBurst: 8, running: true }),

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
      srcIp: client.ip,
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
      srcIp: client.ip,
    }

    set({
      seq: s.seq + 1,
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

// Live WebSocket integration
if (typeof window !== 'undefined') {
  const wsHost = window as Window & { __miniSharkWS?: WebSocket }
  function connectWs() {
    try {
      const ws = new WebSocket(WS)
      wsHost.__miniSharkWS = ws
      ws.onopen = () => {
        useCaptureStore.setState({ wsConnected: true })
      }
      ws.onmessage = ({ data }) => {
        try {
          const msg = JSON.parse(data)
          if (msg.type === 'correlation') {
            const isDrop = msg.match_state?.includes('unmatched')
            const isSlow = msg.delay_ms != null && Number(msg.delay_ms) > 20
            const status: Packet['status'] = isDrop ? 'dropped' : isSlow ? 'high-latency' : 'matched'
            const kind: Flight['kind'] = isDrop ? 'drop' : isSlow ? 'slow' : 'normal'

            const state = useCaptureStore.getState()
            const srcIp = msg.src_ip || '192.168.10.11'

            let clientIdx = state.clients.findIndex((c) => c.ip === srcIp)
            if (clientIdx === -1) {
              clientIdx = state.seq % state.clientCount
            }

            const id = state.seq
            const now = performance.now()
            const deltaTms = msg.delay_ms != null ? Number(msg.delay_ms) : undefined

            const packet = buildPacket({
              id,
              timeUs: 1_704_000_000_000_000 + id * 97_331,
              protocol: (msg.proto || 'TCP').toUpperCase() as any,
              srcPort: msg.src_port || 54210,
              dstPort: msg.dst_port || 80,
              ipId: randInt(0x1000, 0xffee),
              ttl: 63,
              payload: httpPayload(),
              status,
              deltaTms,
              note: isDrop ? 'Silent drop on the wire' : undefined,
              srcIp,
              clientId: clientIdx,
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
