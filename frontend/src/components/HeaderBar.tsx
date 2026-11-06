import {
  Bookmark,
  Clock,
  Pause,
  Play,
  Trash2,
  X,
} from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

export function HeaderBar() {
  const filter = useCaptureStore((s) => s.filter)
  const setFilter = useCaptureStore((s) => s.setFilter)
  const running = useCaptureStore((s) => s.running)
  const start = useCaptureStore((s) => s.start)
  const pause = useCaptureStore((s) => s.pause)
  const clearPackets = useCaptureStore((s) => s.clearPackets)
  const autoScroll = useCaptureStore((s) => s.autoScroll)
  const setAutoScroll = useCaptureStore((s) => s.setAutoScroll)
  const probes = useCaptureStore((s) => s.probesStatus)
  const demoMode = useCaptureStore((s) => s.demoMode)

  const p1Online = probes.probe1_connected || demoMode
  const p2Online = probes.probe2_connected || demoMode

  const clientProbes = (probes.active_clients || []).filter((p) => p.probe_id !== 2)
  const hasArch = clientProbes.some((p) => p.ip.startsWith('10.108.') || p.probe_id === 3)
  const hasVM2 = clientProbes.some((p) => p.ip.startsWith('192.168.130.128') || p.probe_id === 1)

  const quickFilters = [
    { label: 'All Traffic', filter: '' },
    { label: 'Arch Host (10.108.157.186)', filter: 'ip.src == 10.108.157.186 || ip.dst == 10.108.157.186' },
    { label: 'VM2 Client (192.168.130.128)', filter: 'ip.src == 192.168.130.128 || ip.dst == 192.168.130.128' },
    { label: 'HTTP Only', filter: 'http' },
    { label: 'DNS Queries', filter: 'dns' },
    { label: 'Ping (ICMP)', filter: 'icmp' },
    { label: 'TCP Handshakes', filter: 'tcp' },
    { label: '❌ Silent Drops', filter: 'drop' },
  ]

  return (
    <header className="flex flex-col border-b border-slate-300 bg-[#F1F5F9] select-none">
      {/* Upper Navigation & Status Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/90 bg-white px-3.5 py-1.5">
        <div className="flex items-center gap-2.5">
          <WiresharkSharkFin />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display text-[15px] font-bold tracking-tight text-slate-900">
                Mini-Shark
              </span>
              <span className="rounded bg-[#0B5ED7] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-white">
                Wireshark Expert
              </span>
              <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-500 font-medium">
                Team 07 · KLE Tech
              </span>
            </div>
            <div className="text-[10px] text-slate-500">
              Distributed Multi-Point Packet Correlation & Latency/Drop Tracing
            </div>
          </div>
        </div>

        {/* Probe Health Indicator Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {/* Probe 1 (VM2 Client) */}
          <ProbeIndicator
            label="Probe 1 (VM2)"
            ip="192.168.130.128"
            online={p1Online || hasVM2}
            color="blue"
          />
          {/* Probe 3 (Arch Host) */}
          <ProbeIndicator
            label="Probe 3 (Arch Host)"
            ip="10.108.157.186"
            online={hasArch}
            color="emerald"
          />
          {/* Probe 2 (Server Hub) */}
          <ProbeIndicator
            label="Probe 2 (Server)"
            ip="192.168.130.129"
            online={p2Online}
            color="indigo"
          />
        </div>
      </div>

      {/* Main Wireshark Action Controls & Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-1.5">
        {/* Play / Stop / Restart Buttons */}
        <div className="flex items-center gap-1">
          {running ? (
            <button
              type="button"
              onClick={pause}
              className="flex items-center gap-1.5 rounded border border-rose-300 bg-rose-50 px-2.5 py-1 text-[11px] font-semibold text-rose-700 shadow-sm transition hover:bg-rose-100 active:scale-95"
              title="Stop capturing live wire packets"
            >
              <Pause size={12} className="fill-rose-700" />
              <span>Stop</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={start}
              className="flex items-center gap-1.5 rounded border border-emerald-400 bg-emerald-600 px-2.5 py-1 text-[11px] font-semibold text-white shadow-sm transition hover:bg-emerald-700 active:scale-95"
              title="Start live multi-probe capture"
            >
              <Play size={12} className="fill-white" />
              <span>Capture</span>
            </button>
          )}

          <button
            type="button"
            onClick={clearPackets}
            className="flex items-center gap-1 rounded border border-slate-300 bg-white px-2 py-1 text-[11px] font-medium text-slate-700 shadow-sm transition hover:bg-slate-100 hover:text-slate-900 active:scale-95"
            title="Clear packet buffer and start fresh"
          >
            <Trash2 size={12} className="text-slate-500" />
            <span>Clear</span>
          </button>

          <button
            type="button"
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-medium shadow-sm transition active:scale-95 ${
              autoScroll
                ? 'border-blue-300 bg-blue-50 text-blue-700'
                : 'border-slate-300 bg-white text-slate-600 hover:bg-slate-50'
            }`}
            title="Auto-scroll to latest packet on arrival"
          >
            <Clock size={12} />
            <span>Auto-Scroll {autoScroll ? 'ON' : 'OFF'}</span>
          </button>
        </div>

        {/* Authentic Wireshark Display Filter Input */}
        <div className="flex min-w-[280px] flex-1 items-center">
          <div className="relative flex w-full items-center">
            <span className="pointer-events-none absolute left-2.5 flex items-center text-emerald-700">
              <Bookmark size={13} className="fill-emerald-600 text-emerald-700" />
            </span>
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Apply a display filter ... e.g. ip.src == 10.108.157.186, tcp, http, drop"
              className={`w-full rounded border py-1 pl-7 pr-7 font-mono text-[11.5px] text-slate-900 shadow-inner outline-none transition ${
                filter
                  ? 'border-emerald-500 bg-[#E8F8F5] focus:ring-1 focus:ring-emerald-400'
                  : 'border-slate-300 bg-white focus:border-blue-400 focus:ring-1 focus:ring-blue-300'
              }`}
            />
            {filter && (
              <button
                type="button"
                onClick={() => setFilter('')}
                className="absolute right-2 text-slate-400 hover:text-slate-700"
                title="Clear filter"
              >
                <X size={13} />
              </button>
            )}
          </div>
        </div>

        {/* Quick Filter Chips */}
        <div className="hidden items-center gap-1 lg:flex">
          {quickFilters.map((qf) => {
            const active = filter === qf.filter
            return (
              <button
                key={qf.label}
                type="button"
                onClick={() => setFilter(active ? '' : qf.filter)}
                className={`rounded px-1.5 py-0.5 text-[10px] font-medium transition ${
                  active
                    ? 'bg-[#0B5ED7] font-semibold text-white shadow-sm'
                    : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
                }`}
              >
                {qf.label}
              </button>
            )
          })}
        </div>
      </div>
    </header>
  )
}

function WiresharkSharkFin() {
  return (
    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-[#0B5ED7] to-[#0284C7] shadow-sm">
      <svg viewBox="0 0 32 32" className="h-5 w-5 text-white" fill="none">
        <path
          d="M4 18c8-1 10-8 14-12 1.2 4 3 7 10 9-6 1.5-9 4-10 9-3-4-8-5-14-6Z"
          fill="currentColor"
        />
        <path
          d="M9 19.5c2 .4 3.4 1.6 4.2 3.6"
          stroke="#BAE6FD"
          strokeWidth="1.8"
          strokeLinecap="round"
        />
      </svg>
    </div>
  )
}

function ProbeIndicator({
  label,
  ip,
  online,
  color,
}: {
  label: string
  ip: string
  online: boolean
  color: 'blue' | 'emerald' | 'indigo'
}) {
  const borderCol = online
    ? color === 'emerald'
      ? 'border-emerald-300 bg-emerald-50/80 text-emerald-800'
      : color === 'indigo'
        ? 'border-indigo-300 bg-indigo-50/80 text-indigo-800'
        : 'border-blue-300 bg-blue-50/80 text-blue-800'
    : 'border-slate-200 bg-slate-50 text-slate-500'

  const dotCol = online
    ? color === 'emerald'
      ? 'bg-emerald-500'
      : color === 'indigo'
        ? 'bg-indigo-500'
        : 'bg-blue-500'
    : 'bg-slate-300'

  return (
    <div className={`flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10.5px] font-medium shadow-2xs ${borderCol}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dotCol} ${online ? 'animate-pulse' : ''}`} />
      <span>{label}:</span>
      <span className="font-mono text-[10px] font-semibold">{ip}</span>
      <span className="text-[9px] uppercase tracking-wide opacity-75">
        {online ? 'Online' : 'Standby'}
      </span>
    </div>
  )
}
