import type { ReactNode } from 'react'
import { FlaskConical, Pause, Play, Timer, Zap } from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

export function SimulationBar() {
  const running = useCaptureStore((s) => s.running)
  const start = useCaptureStore((s) => s.start)
  const pause = useCaptureStore((s) => s.pause)
  const injectDropRate = useCaptureStore((s) => s.injectDropRate)
  const injectDelaySpike = useCaptureStore((s) => s.injectDelaySpike)
  const runDnsTest = useCaptureStore((s) => s.runDnsTest)

  return (
    <div className="pointer-events-none absolute inset-x-0 top-3 z-40 flex justify-center px-3">
      <div className="pointer-events-auto flex flex-wrap items-center justify-center gap-1.5 rounded-2xl border border-white/80 bg-white/88 p-1.5 shadow-[0_16px_48px_rgba(15,23,42,0.08)] backdrop-blur-md">
        <SimButton onClick={start} tone="blue" active={running}>
          <Play size={14} />
          Start Live Capture
        </SimButton>
        <SimButton onClick={pause} tone="slate" active={!running}>
          <Pause size={14} />
          Pause
        </SimButton>
        <SimButton onClick={injectDropRate} tone="crimson">
          <Zap size={14} />
          Inject 5% Drop Rate
        </SimButton>
        <SimButton onClick={injectDelaySpike} tone="amber">
          <Timer size={14} />
          Inject 60ms Delay Spike
        </SimButton>
        <SimButton onClick={runDnsTest} tone="cyan">
          <FlaskConical size={14} />
          Run DNS Tunneling Test
        </SimButton>
      </div>
    </div>
  )
}

function SimButton({
  children,
  onClick,
  tone,
  active,
}: {
  children: ReactNode
  onClick: () => void
  tone: 'blue' | 'slate' | 'crimson' | 'amber' | 'cyan'
  active?: boolean
}) {
  const cls = {
    blue: 'bg-[#2563EB] text-white hover:bg-blue-700',
    slate: 'bg-slate-800 text-white hover:bg-slate-900',
    crimson: 'bg-white text-[#DC2626] ring-1 ring-red-200 hover:bg-red-50',
    amber: 'bg-white text-[#D97706] ring-1 ring-amber-200 hover:bg-amber-50',
    cyan: 'bg-white text-[#008DDA] ring-1 ring-sky-200 hover:bg-sky-50',
  }[tone]

  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-1.5 rounded-xl px-3 py-2 text-[12px] font-medium transition ${cls} ${active ? 'ring-2 ring-offset-1 ring-sky-300' : ''}`}
    >
      {children}
    </button>
  )
}
