import { useEffect, useRef } from 'react'
import { packetMatchesFilter, useCaptureStore } from '../store/useCaptureStore'
import type { Packet, Protocol } from '../types'

export function PacketTable() {
  const packets = useCaptureStore((s) => s.packets)
  const filter = useCaptureStore((s) => s.filter)
  const selectedId = useCaptureStore((s) => s.selectedId)
  const selectPacket = useCaptureStore((s) => s.selectPacket)
  const autoScroll = useCaptureStore((s) => s.autoScroll)
  const rows = packets.filter((p) => packetMatchesFilter(p, filter))
  const tableBottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (selectedId != null) {
      document
        .querySelector(`[data-packet-id="${selectedId}"]`)
        ?.scrollIntoView({ block: 'nearest' })
    } else if (autoScroll && rows.length > 0) {
      tableBottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
    }
  }, [selectedId, rows.length, autoScroll])

  const totalFrames = packets.length
  const droppedCount = packets.filter((p) => p.status === 'dropped').length
  const lossRate = totalFrames > 0 ? ((droppedCount / totalFrames) * 100).toFixed(1) : '0.0'

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col bg-white">
      {/* Wireshark Panel Banner */}
      <div className="flex items-center justify-between border-b border-slate-200 bg-[#F1F5F9] px-3 py-1 text-[11px] font-medium text-slate-700">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-900">Packet List</span>
          <span className="text-slate-400">|</span>
          <span className="font-mono text-[10.5px] text-slate-600">
            {rows.length} displayed of {totalFrames} captured
          </span>
          {droppedCount > 0 && (
            <span className="rounded bg-rose-100 px-1.5 py-0.2 text-[10px] font-semibold text-rose-700">
              {droppedCount} Dropped ({lossRate}%)
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-[#10B981]" /> HTTP
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-[#0284C7]" /> TCP
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-[#8B5CF6]" /> DNS/UDP
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-[#0D9488]" /> ICMP
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-[#EF4444]" /> Drop
          </span>
        </div>
      </div>

      {/* Table Container */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left font-mono text-[11px]">
          <thead className="sticky top-0 z-10 border-b border-slate-300 bg-[#E2E8F0] font-sans text-[10.5px] font-semibold tracking-wider text-slate-700 shadow-2xs">
            <tr>
              <th className="w-[50px] px-2.5 py-1 text-center">No.</th>
              <th className="w-[90px] px-2 py-1">Time</th>
              <th className="w-[90px] px-2 py-1">ΔT Latency</th>
              <th className="w-[200px] px-2 py-1">Source (Ingress)</th>
              <th className="w-[180px] px-2 py-1">Destination (Egress)</th>
              <th className="w-[75px] px-2 py-1 text-center">Protocol</th>
              <th className="w-[55px] px-2 py-1 text-right">Length</th>
              <th className="w-[260px] px-2 py-1">Correlation & Link Status</th>
              <th className="px-2 py-1">Info / BLAKE2b Digest</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => {
              const isSelected = selectedId === p.id
              const isArch = p.srcIp === '10.108.157.186' || p.clientId === 1
              const rowColor = getWiresharkRowClass(p, isSelected)

              return (
                <tr
                  key={p.id}
                  data-packet-id={p.id}
                  onClick={() => selectPacket(p.id)}
                  className={`cursor-pointer border-b border-slate-100 transition-colors ${rowColor}`}
                >
                  <td className={`px-2.5 py-1 text-center font-sans ${isSelected ? 'text-white' : 'text-slate-500'}`}>
                    {p.id}
                  </td>
                  <td className={`px-2 py-1 whitespace-nowrap ${isSelected ? 'text-slate-100' : 'text-slate-600'}`}>
                    {formatTime(p.timeUs)}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap">
                    {p.status === 'dropped' ? (
                      <span className={`font-semibold ${isSelected ? 'text-white' : 'text-rose-600'}`}>
                        Timeout
                      </span>
                    ) : (
                      <span
                        className={`rounded px-1.5 py-0.2 text-[10px] font-bold ${
                          isSelected
                            ? 'bg-blue-800 text-white'
                            : (p.deltaTms ?? 0) > 20
                              ? 'bg-amber-200 text-amber-900'
                              : 'bg-emerald-100 text-emerald-800'
                        }`}
                      >
                        {p.deltaTms != null ? `${p.deltaTms.toFixed(2)} ms` : '—'}
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap">
                    <span
                      className={`mr-1 inline-block rounded px-1 text-[9px] font-bold ${
                        isSelected
                          ? 'bg-white/20 text-white'
                          : isArch
                            ? 'bg-emerald-100 text-emerald-800'
                            : 'bg-blue-100 text-blue-800'
                      }`}
                    >
                      {isArch ? 'Arch Host' : 'VM2'}
                    </span>
                    <span className={isSelected ? 'text-white' : 'text-slate-800'}>
                      {p.srcIp}{p.protocol === 'ICMP' || !p.srcPort ? '' : `:${p.srcPort}`}
                    </span>
                  </td>
                  <td className={`px-2 py-1 whitespace-nowrap ${isSelected ? 'text-slate-100' : 'text-slate-800'}`}>
                    <span
                      className={`mr-1 inline-block rounded px-1 text-[9px] font-bold ${
                        isSelected ? 'bg-white/20 text-white' : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      Server
                    </span>
                    {p.dstIp || '192.168.130.129'}{p.protocol === 'ICMP' || !p.dstPort ? '' : `:${p.dstPort}`}
                  </td>
                  <td className="px-2 py-1 text-center">
                    <ProtoBadge protocol={p.protocol} isSelected={isSelected} />
                  </td>
                  <td className={`px-2 py-1 text-right ${isSelected ? 'text-slate-100' : 'text-slate-600'}`}>
                    {p.length}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap">
                    <StatusCell packet={p} isSelected={isSelected} />
                  </td>
                  <td className={`px-2 py-1 truncate max-w-[420px] ${isSelected ? 'text-slate-100' : 'text-slate-600'}`}>
                    {getInfoText(p)}
                  </td>
                </tr>
              )
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={9} className="px-3 py-12 text-center font-sans text-slate-400">
                  <div className="flex flex-col items-center gap-1.5">
                    <span className="font-semibold text-slate-600">No correlated packets captured yet</span>
                    <span className="text-[12px] text-slate-500">
                      Start live probes on VM2, Arch Linux host, and VM1 Server to stream live traffic.
                    </span>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div ref={tableBottomRef} />
      </div>
    </div>
  )
}

function getWiresharkRowClass(p: Packet, isSelected: boolean): string {
  if (isSelected) {
    return 'bg-[#0B5ED7] text-white shadow-xs'
  }
  if (p.status === 'dropped') {
    return 'bg-[#FDEDEC] text-slate-900 hover:bg-[#FADBD8]'
  }
  if (p.status === 'high-latency') {
    return 'bg-[#FEF9E7] text-slate-900 hover:bg-[#FCF3CF]'
  }
  switch (p.protocol) {
    case 'HTTP':
      return 'bg-[#E8F8F5] text-slate-900 hover:bg-[#D1F2EB]'
    case 'TCP':
      return 'bg-[#EBF5FB] text-slate-900 hover:bg-[#D4E6F1]'
    case 'DNS':
    case 'UDP':
      return 'bg-[#F4ECF7] text-slate-900 hover:bg-[#E8DAEF]'
    case 'ICMP':
      return 'bg-[#EAF2F8] text-slate-900 hover:bg-[#D4E6F1]'
    default:
      return 'hover:bg-slate-50 text-slate-900'
  }
}

function formatTime(us: number) {
  const s = us / 1_000_000
  return s.toFixed(6)
}

function StatusCell({ packet, isSelected }: { packet: Packet; isSelected: boolean }) {
  if (packet.status === 'dropped') {
    return (
      <span className={`font-semibold ${isSelected ? 'text-white' : 'text-rose-700'}`}>
        ❌ Dropped on Link: {packet.srcIp} → {packet.dstIp || '192.168.130.129'}
      </span>
    )
  }
  if (packet.status === 'high-latency') {
    return (
      <span className={isSelected ? 'text-white' : 'text-amber-800'}>
        ⚠️ High Latency ({packet.deltaTms?.toFixed(2) ?? '—'} ms)
      </span>
    )
  }
  return (
    <span className={isSelected ? 'text-white' : 'text-emerald-700'}>
      ✅ Matched · Cross-Probe Verified
    </span>
  )
}

function ProtoBadge({ protocol, isSelected }: { protocol: Protocol; isSelected: boolean }) {
  if (isSelected) {
    return (
      <span className="rounded bg-white/20 px-1.5 py-0.2 text-[9.5px] font-bold text-white uppercase">
        {protocol}
      </span>
    )
  }
  const cls: Record<Protocol, string> = {
    TCP: 'bg-blue-100 text-blue-800',
    UDP: 'bg-violet-100 text-violet-800',
    DNS: 'bg-sky-100 text-sky-800',
    ICMP: 'bg-emerald-100 text-emerald-800',
    HTTP: 'bg-emerald-200 text-emerald-900 font-bold',
  }
  return (
    <span className={`rounded px-1.5 py-0.2 text-[9.5px] font-semibold ${cls[protocol] || 'bg-slate-100 text-slate-800'}`}>
      {protocol}
    </span>
  )
}

function getInfoText(p: Packet): string {
  if (p.protocol === 'HTTP') {
    return `GET / HTTP/1.1 · Port ${p.dstPort} · Invariant Hash: ${p.hash64.slice(0, 10)}…`
  }
  if (p.protocol === 'DNS') {
    return `Standard query A · Transaction 0x${p.ipId} · Invariant Hash: ${p.hash64.slice(0, 10)}…`
  }
  if (p.protocol === 'ICMP') {
    return `Echo (ping) request · id=0x${p.ipId} · Invariant Hash: ${p.hash64.slice(0, 10)}…`
  }
  return `${p.srcPort} → ${p.dstPort} [ACK] Seq=${p.tcpSeq ?? 0} · Invariant Hash: ${p.hash64.slice(0, 10)}…`
}
