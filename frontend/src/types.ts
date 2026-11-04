export type Protocol = 'TCP' | 'UDP' | 'DNS' | 'ICMP'
export type PacketStatus = 'matched' | 'dropped' | 'high-latency' | 'in-flight'

export type ByteKind = 'invariant' | 'mutating' | 'payload'

export interface ProtocolLayer {
  id: string
  title: string
  summary: string
  kind: ByteKind | 'meta'
  fields: { label: string; value: string; kind?: ByteKind }[]
  children?: ProtocolLayer[]
}

export interface Packet {
  id: number
  timeUs: number
  status: PacketStatus
  deltaTms?: number
  hash64: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  protocol: Protocol
  length: number
  ipId: string
  tcpSeq?: number
  layers: ProtocolLayer[]
  bytes: number[]
  byteKinds: ByteKind[]
  note?: string
}

export interface Flight {
  id: string
  packetId: number
  hash64: string
  kind: 'normal' | 'drop' | 'slow'
  duration: number
  spawnedAt: number
}
