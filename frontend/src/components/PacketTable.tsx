import { useEffect } from 'react'
import { packetMatchesFilter, useCaptureStore } from '../store/useCaptureStore'
import type { Packet, PacketStatus, Protocol } from '../types'

export function PacketTable() {
  const packets = useCaptureStore((s) => s.packets)
  const filter = useCaptureStore((s) => s.filter)
  const selectedId = useCaptureStore((s) => s.selectedId)
  const selectPacket = useCaptureStore((s) => s.selectPacket)
  const rows = packets.filter((p) => packetMatchesFilter(p, filter))

  useEffect(() => {
    if (selectedId == null) return
    document.querySelector(`[data-packet-id="${selectedId}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [selectedId])

  return (
    <div className="flex min-h-0 flex-1 flex-col border-b border-slate-200 bg-white">
      <div className="flex items-center justify-between px-3 py-1.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">
        <span>Panel A · Multi-hop correlated packet table</span>
        <span className="font-mono normal-case tracking-normal text-slate-500">{rows.length} frames</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left text-[12px]">
          <thead className="sticky top-0 z-10 bg-slate-50 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              {['No.', 'Time', 'Status', 'Hash64', 'Source → Dest', 'Protocol', 'Length', 'Invariants'].map((h) => (
                <th key={h} className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((p) => (
              <tr
                key={p.id}
                data-packet-id={p.id}
                onClick={() => selectPacket(p.id)}
                className={`cursor-pointer border-b border-slate-100 transition ${
                  selectedId === p.id
                    ? 'bg-sky-50'
                    : p.status === 'dropped'
                      ? 'bg-red-50/70 hover:bg-red-50'
                      : p.status === 'high-latency'
                        ? 'bg-amber-50/60 hover:bg-amber-50'
                        : 'hover:bg-slate-50'
                }`}
              >
                <td className="px-3 py-1.5 text-slate-500">{p.id}</td>
                <td className="px-3 py-1.5 text-slate-600">{formatTime(p.timeUs)}</td>
                <td className="px-3 py-1.5">
                  <StatusCell packet={p} />
                </td>
                <td className="px-3 py-1.5 text-slate-800">{p.hash64}</td>
                <td className="whitespace-nowrap px-3 py-1.5 text-slate-700">
                  <span className="mr-1.5 inline-block rounded bg-blue-100 px-1 py-0.5 text-[9.5px] font-semibold text-blue-700">
                    C{p.clientId != null ? p.clientId + 1 : 1}
                  </span>
                  {p.srcIp}:{p.srcPort} → {p.dstIp}:{p.dstPort}
                </td>
                <td className="px-3 py-1.5">
                  <ProtoTag protocol={p.protocol} />
                </td>
                <td className="px-3 py-1.5 text-slate-600">{p.length}</td>
                <td className="px-3 py-1.5 text-slate-500">
                  IP ID {p.ipId}
                  {p.tcpSeq != null ? ` · TCP Seq ${p.tcpSeq}` : ''}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-10 text-center font-sans text-slate-400">
                  Start live capture to correlate ingress and egress probes.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function formatTime(us: number) {
  const s = us / 1_000_000
  return s.toFixed(6)
}

function StatusCell({ packet }: { packet: Packet }) {
  const map: Record<PacketStatus, string> = {
    matched: `✅ Matched (ΔT = ${packet.deltaTms?.toFixed(1) ?? '—'}ms)`,
    dropped: '❌ Dropped on Wire (Timeout 500ms)',
    'high-latency': `⚠️ High Latency (ΔT = ${packet.deltaTms?.toFixed(1) ?? '—'}ms)`,
    'in-flight': '◎ In-flight · correlating',
  }
  const color: Record<PacketStatus, string> = {
    matched: 'text-emerald-700',
    dropped: 'text-red-700',
    'high-latency': 'text-amber-700',
    'in-flight': 'text-sky-700',
  }
  return <span className={color[packet.status]}>{map[packet.status]}</span>
}

function ProtoTag({ protocol }: { protocol: Protocol }) {
  const cls: Record<Protocol, string> = {
    TCP: 'bg-blue-100 text-blue-800',
    UDP: 'bg-violet-100 text-violet-800',
    DNS: 'bg-sky-100 text-sky-800',
    ICMP: 'bg-emerald-100 text-emerald-800',
  }
  return <span className={`rounded-md px-1.5 py-0.5 text-[10px] font-semibold ${cls[protocol]}`}>{protocol}</span>
}
