import type { ByteKind, Packet, Protocol, ProtocolLayer } from '../types'

const CLIENT_IP = '192.168.10.11'
const SERVER_IP = '192.168.20.20'
const CLIENT_MAC = [0x00, 0x0c, 0x29, 0xa4, 0x10, 0x11]
const SERVER_MAC = [0x00, 0x0c, 0x29, 0xb8, 0x20, 0x20]
const ROUTER_MAC = [0x00, 0x0c, 0x29, 0x7e, 0x00, 0x01]

function ipBytes(ip: string): number[] {
  return ip.split('.').map((n) => Number(n) & 0xff)
}

function u16(n: number): [number, number] {
  return [(n >> 8) & 0xff, n & 0xff]
}

function u32(n: number): [number, number, number, number] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
}

function hex64FromParts(h1: number, h2: number): string {
  const body = `${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0).toString(16).padStart(8, '0')}`
    .slice(0, 12)
    .toUpperCase()
  return `0x${body}`
}

function checksum(bytes: number[]): number {
  let sum = 0
  for (let i = 0; i < bytes.length; i += 2) {
    sum += (bytes[i] << 8) + (bytes[i + 1] ?? 0)
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16)
  return ~sum & 0xffff
}

export function hashInvariant(ipId: number, src: string, dst: string, proto: number, seq: number): string {
  const key = `${ipId}|${src}|${dst}|${proto}|${seq}`
  let h1 = 0x811c9dc5
  let h2 = 0x9e3779b9
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i)
    h1 = Math.imul(h1 ^ c, 16777619)
    h2 = Math.imul(h2 ^ Math.imul(c, 33), 2246822519)
  }
  return hex64FromParts(h1, h2)
}

function asciiPayload(text: string): number[] {
  return Array.from(text).map((c) => c.charCodeAt(0) & 0xff)
}

export interface FrameSpec {
  id: number
  timeUs: number
  protocol: Protocol
  srcPort: number
  dstPort: number
  ipId: number
  tcpSeq?: number
  ttl: number
  payload: number[]
  status: Packet['status']
  deltaTms?: number
  note?: string
}

export function buildPacket(spec: FrameSpec): Packet {
  const protoNum = spec.protocol === 'ICMP' ? 1 : spec.protocol === 'TCP' ? 6 : 17
  const payload = spec.payload
  const l4Len =
    spec.protocol === 'TCP' ? 20 : spec.protocol === 'ICMP' ? 8 : spec.protocol === 'DNS' ? 12 : 8
  const ipLen = 20 + l4Len + payload.length
  const total = 14 + ipLen

  const bytes = new Array<number>(total).fill(0)
  const kinds: ByteKind[] = new Array(total).fill('payload')

  const mark = (start: number, len: number, kind: ByteKind) => {
    for (let i = start; i < start + len; i++) kinds[i] = kind
  }

  // Ethernet II (mutating MACs)
  bytes.splice(0, 6, ...SERVER_MAC)
  bytes.splice(6, 6, ...CLIENT_MAC)
  bytes[12] = 0x08
  bytes[13] = 0x00
  mark(0, 12, 'mutating')
  mark(12, 2, 'invariant')

  // IPv4
  bytes[14] = 0x45
  bytes[15] = 0x00
  const [tl0, tl1] = u16(ipLen)
  bytes[16] = tl0
  bytes[17] = tl1
  const [id0, id1] = u16(spec.ipId)
  bytes[18] = id0
  bytes[19] = id1
  bytes[20] = 0x40
  bytes[21] = 0x00
  bytes[22] = spec.ttl
  bytes[23] = protoNum
  bytes.splice(26, 4, ...ipBytes(CLIENT_IP))
  bytes.splice(30, 4, ...ipBytes(SERVER_IP))
  const ipHdr = bytes.slice(14, 34)
  ipHdr[10] = 0
  ipHdr[11] = 0
  const [c0, c1] = u16(checksum(ipHdr))
  bytes[24] = c0
  bytes[25] = c1

  mark(14, 4, 'invariant')
  mark(18, 2, 'invariant')
  mark(20, 2, 'invariant')
  mark(22, 1, 'mutating')
  mark(23, 1, 'invariant')
  mark(24, 2, 'mutating')
  mark(26, 8, 'invariant')

  let l4 = 34
  if (spec.protocol === 'TCP') {
    const seq = spec.tcpSeq ?? 0
    bytes.splice(34, 2, ...u16(spec.srcPort))
    bytes.splice(36, 2, ...u16(spec.dstPort))
    bytes.splice(38, 4, ...u32(seq))
    bytes.splice(42, 4, ...u32(seq + 1))
    bytes[46] = 0x50
    bytes[47] = 0x18
    bytes.splice(48, 2, ...u16(8192))
    bytes[50] = 0x00
    bytes[51] = 0x00
    mark(34, 16, 'invariant')
    mark(50, 2, 'mutating')
    l4 = 54
  } else if (spec.protocol === 'ICMP') {
    bytes[34] = 8
    bytes[35] = 0
    bytes.splice(38, 2, ...u16(spec.ipId))
    bytes.splice(40, 2, ...u16(1))
    mark(34, 2, 'invariant')
    mark(36, 2, 'mutating')
    mark(38, 4, 'invariant')
    l4 = 42
  } else {
    bytes.splice(34, 2, ...u16(spec.srcPort))
    bytes.splice(36, 2, ...u16(spec.dstPort))
    bytes.splice(38, 2, ...u16(8 + payload.length))
    mark(34, 4, 'invariant')
    mark(38, 2, 'invariant')
    mark(40, 2, 'mutating')
    l4 = 42
  }

  for (let i = 0; i < payload.length; i++) bytes[l4 + i] = payload[i]
  mark(l4, payload.length, spec.protocol === 'DNS' ? 'payload' : 'payload')

  const hash64 = hashInvariant(
    spec.ipId,
    CLIENT_IP,
    SERVER_IP,
    protoNum,
    spec.tcpSeq ?? spec.srcPort * 1000 + spec.dstPort,
  )

  const layers: ProtocolLayer[] = [
    {
      id: 'frame',
      title: `Frame ${spec.id}`,
      summary: `${total} bytes captured on eth0 · dual-probe correlated`,
      kind: 'meta',
      fields: [
        { label: 'Ingress iface', value: 'vmnet2 (Client VM)' },
        { label: 'Egress iface', value: 'vmnet3 (Server VM)' },
        { label: 'Capture length', value: `${total} bytes` },
        { label: 'ΔT timer', value: spec.status === 'dropped' ? '500ms timeout' : `${spec.deltaTms?.toFixed(2) ?? '—'} ms` },
      ],
    },
    {
      id: 'eth',
      title: 'Ethernet II',
      summary: `Src: ${CLIENT_MAC.map((b) => b.toString(16).padStart(2, '0')).join(':')} → Dst: ${SERVER_MAC.map((b) => b.toString(16).padStart(2, '0')).join(':')}`,
      kind: 'mutating',
      fields: [
        { label: 'Destination', value: SERVER_MAC.map((b) => b.toString(16).padStart(2, '0')).join(':'), kind: 'mutating' },
        { label: 'Source', value: CLIENT_MAC.map((b) => b.toString(16).padStart(2, '0')).join(':'), kind: 'mutating' },
        { label: 'Type', value: 'IPv4 (0x0800)' },
        { label: 'Gateway MAC', value: ROUTER_MAC.map((b) => b.toString(16).padStart(2, '0')).join(':') + '  (rewritten on MiniShark-Host)', kind: 'mutating' },
        { label: 'Hash policy', value: '[MUTATING — excluded from hash]  rewritten at MiniShark-Host', kind: 'mutating' },
      ],
    },
    {
      id: 'ip',
      title: 'Internet Protocol Version 4',
      summary: `Src: ${CLIENT_IP}, Dst: ${SERVER_IP}, IP ID: 0x${spec.ipId.toString(16).toUpperCase().padStart(4, '0')}`,
      kind: 'invariant',
      fields: [
        { label: 'Version', value: '4' },
        { label: 'Header Length', value: '20 bytes' },
        { label: 'Identification', value: `0x${spec.ipId.toString(16).toUpperCase().padStart(4, '0')}  [INVARIANT — hashed]`, kind: 'invariant' },
        { label: 'TTL', value: `${spec.ttl}  [MUTATING — rewritten ${spec.ttl + 1} → ${spec.ttl}]`, kind: 'mutating' },
        { label: 'Protocol', value: `${spec.protocol} (${protoNum})`, kind: 'invariant' },
        { label: 'Header checksum', value: `0x${c0.toString(16).padStart(2, '0')}${c1.toString(16).padStart(2, '0')}  [MUTATING]`, kind: 'mutating' },
        { label: 'Source', value: CLIENT_IP, kind: 'invariant' },
        { label: 'Destination', value: SERVER_IP, kind: 'invariant' },
      ],
    },
    spec.protocol === 'TCP'
      ? {
          id: 'tcp',
          title: 'Transmission Control Protocol',
          summary: `Src Port: ${spec.srcPort}, Dst Port: ${spec.dstPort}, Seq: ${spec.tcpSeq}`,
          kind: 'invariant',
          fields: [
            { label: 'Source Port', value: String(spec.srcPort), kind: 'invariant' },
            { label: 'Destination Port', value: String(spec.dstPort), kind: 'invariant' },
            { label: 'Sequence Number', value: String(spec.tcpSeq), kind: 'invariant' },
            { label: 'Flags', value: 'PSH, ACK' },
            { label: 'Window', value: '8192' },
            { label: 'Checksum', value: '0x0000  [MUTATING]', kind: 'mutating' },
          ],
        }
      : spec.protocol === 'ICMP'
        ? {
            id: 'icmp',
            title: 'Internet Control Message Protocol',
            summary: 'Echo (ping) request',
            kind: 'invariant',
            fields: [
              { label: 'Type', value: '8 (Echo request)', kind: 'invariant' },
              { label: 'Code', value: '0' },
              { label: 'Identifier', value: `0x${spec.ipId.toString(16).toUpperCase().padStart(4, '0')}`, kind: 'invariant' },
            ],
          }
        : {
            id: spec.protocol === 'DNS' ? 'dns' : 'udp',
            title: spec.protocol === 'DNS' ? 'Domain Name System (query)' : 'User Datagram Protocol',
            summary:
              spec.protocol === 'DNS'
                ? `Standard query 0x${spec.ipId.toString(16).padStart(4, '0')} A ${payloadToName(payload)}`
                : `Src Port: ${spec.srcPort} → Dst Port: ${spec.dstPort}`,
            kind: 'invariant',
            fields: [
              { label: 'Source Port', value: String(spec.srcPort), kind: 'invariant' },
              { label: 'Destination Port', value: String(spec.dstPort), kind: 'invariant' },
              ...(spec.protocol === 'DNS'
                ? [
                    { label: 'Transaction ID', value: `0x${spec.ipId.toString(16).toUpperCase().padStart(4, '0')}`, kind: 'invariant' as const },
                    { label: 'QNAME', value: payloadToName(payload) },
                  ]
                : []),
            ],
          },
    {
      id: 'fingerprint',
      title: 'Mini-Shark Invariant Fingerprint',
      summary: `BLAKE2b 64-bit = ${hash64}`,
      kind: 'invariant',
      fields: [
        { label: 'Algorithm', value: 'BLAKE2b truncated to 64-bit' },
        { label: 'Hash64', value: hash64, kind: 'invariant' },
        { label: 'Inputs', value: 'IP ID · Src/Dst · L4 proto · TCP Seq/ports' },
        { label: 'Excluded', value: 'MAC · TTL · checksums · NAT-rewritten headers' },
        { label: 'Correlation', value: 'E3 O(1) hash table over TCP :9000' },
      ],
    },
  ]

  return {
    id: spec.id,
    timeUs: spec.timeUs,
    status: spec.status,
    deltaTms: spec.deltaTms,
    hash64,
    srcIp: CLIENT_IP,
    srcPort: spec.srcPort,
    dstIp: SERVER_IP,
    dstPort: spec.dstPort,
    protocol: spec.protocol,
    length: total,
    ipId: `0x${spec.ipId.toString(16).toUpperCase().padStart(4, '0')}`,
    tcpSeq: spec.tcpSeq,
    layers,
    bytes,
    byteKinds: kinds,
    note: spec.note,
  }
}

function payloadToName(payload: number[]): string {
  try {
    return String.fromCharCode(...payload.filter((b) => b >= 32 && b < 127)) || '(binary)'
  } catch {
    return '(binary)'
  }
}

export function httpPayload(path = '/index.html'): number[] {
  return asciiPayload(`GET ${path} HTTP/1.1\r\nHost: 192.168.20.20\r\n\r\n`)
}

export function dnsPayload(name: string): number[] {
  return asciiPayload(name)
}

export { CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC, ROUTER_MAC }
