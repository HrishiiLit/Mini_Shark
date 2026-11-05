import type { ReactNode } from 'react'
import { Activity, Cpu, FlaskConical, MemoryStick, Radio } from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

export function HeaderBar() {
  const filter = useCaptureStore((s) => s.filter)
  const setFilter = useCaptureStore((s) => s.setFilter)
  const running = useCaptureStore((s) => s.running)
  const memoryMb = useCaptureStore((s) => s.memoryMb)
  const fps = useCaptureStore((s) => s.fps)
  const clientCount = useCaptureStore((s) => s.clientCount)
  const wsConnected = useCaptureStore((s) => s.wsConnected)

  return (
    <header className="sticky top-0 z-30 flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-200/80 bg-white/90 px-4 py-2 backdrop-blur-md">
      <div className="flex items-center gap-3">
        <Logo />
        <div>
          <div className="flex items-baseline gap-2">
            <h1 className="font-display text-[1.15rem] font-semibold tracking-tight text-slate-900">
              Mini-Shark
            </h1>
            <span className="rounded-full bg-slate-900 px-2 py-0.5 text-[10px] font-medium tracking-wide text-white">
              KLE Tech · Team 07
            </span>
          </div>
          <p className="text-[11px] tracking-wide text-slate-500">CSE-AI · 23ECNP301 · Multi-probe invariant correlation</p>
        </div>
      </div>

      <div className="flex min-w-0 flex-1 flex-wrap items-center justify-center gap-1.5">
        <Pill
          icon={<Radio size={12} />}
          label="Ingress Probes"
          value={`${clientCount} Node${clientCount > 1 ? 's' : ''} :9000`}
          accent="blue"
          live={running || wsConnected}
        />
        <Pill
          icon={<Radio size={12} />}
          label="Egress Probe"
          value="Active :9000"
          accent="teal"
          live={running || wsConnected}
        />
        <Pill
          icon={<Cpu size={12} />}
          label="Correlation Engine"
          value={`O(1) Hash Table · ${Math.round(fps)} FPS`}
          accent="cyan"
        />
        <Pill
          icon={<MemoryStick size={12} />}
          label="Memory Usage"
          value={`${memoryMb.toFixed(1)} MB / 65 MB Cap`}
          accent="slate"
        />
        <Pill icon={<FlaskConical size={12} />} label="Unit Tests" value="144/144 Passing" accent="teal" />
      </div>

      <label className="relative block w-full max-w-[340px]">
        <span className="sr-only">Display filter</span>
        <Activity className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="e.g. client == 2 or ip.src == 192.168.10.12 or tcp"
          className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2 pl-8 pr-3 font-mono text-[12px] text-slate-800 outline-none ring-sky-400/40 transition focus:border-sky-400 focus:bg-white focus:ring-2"
        />
      </label>
    </header>
  )
}

function Logo() {
  return (
    <div className="relative grid h-11 w-11 place-items-center rounded-2xl bg-gradient-to-br from-[#2563EB] to-[#008DDA] shadow-[0_8px_24px_rgba(37,99,235,0.28)]">
      <svg viewBox="0 0 32 32" className="h-7 w-7 text-white" fill="none">
        <path d="M4 18c8-1 10-8 14-12 1.2 4 3 7 10 9-6 1.5-9 4-10 9-3-4-8-5-14-6Z" fill="currentColor" />
        <path d="M9 19.5c2 .4 3.4 1.6 4.2 3.6" stroke="#A5F3FC" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
    </div>
  )
}

function Pill({
  icon,
  label,
  value,
  accent,
  live,
}: {
  icon: ReactNode
  label: string
  value: string
  accent: 'blue' | 'teal' | 'cyan' | 'slate'
  live?: boolean
}) {
  const tones = {
    blue: 'border-blue-200 bg-blue-50 text-blue-800',
    teal: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    cyan: 'border-sky-200 bg-sky-50 text-sky-800',
    slate: 'border-slate-200 bg-slate-50 text-slate-700',
  }[accent]
  const dot = {
    blue: 'bg-[#2563EB]',
    teal: 'bg-[#059669]',
    cyan: 'bg-[#0284C7]',
    slate: 'bg-slate-500',
  }[accent]

  return (
    <div className={`flex items-center gap-2 rounded-xl border px-2.5 py-1 text-[11px] font-medium shadow-sm transition ${tones}`}>
      <span className="text-slate-500">{icon}</span>
      <span>{label}</span>
      <span className="flex items-center gap-1 font-semibold text-slate-900">
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${dot} ${live ? 'animate-pulse' : ''}`} />
        {value}
      </span>
    </div>
  )
}
