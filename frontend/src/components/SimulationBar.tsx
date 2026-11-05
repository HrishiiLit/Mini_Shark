import type { ReactNode } from 'react'
import { FlaskConical, Play, Timer, Users, Wifi, Zap } from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

export function SimulationBar() {
  const demoMode = useCaptureStore((s) => s.demoMode)
  const setDemoMode = useCaptureStore((s) => s.setDemoMode)
  const injectDropRate = useCaptureStore((s) => s.injectDropRate)
  const injectDelaySpike = useCaptureStore((s) => s.injectDelaySpike)
  const runDnsTest = useCaptureStore((s) => s.runDnsTest)
  const clientCount = useCaptureStore((s) => s.clientCount)
  const setClientCount = useCaptureStore((s) => s.setClientCount)
  const probes = useCaptureStore((s) => s.probesStatus)

  return (
    <div className="pointer-events-none absolute inset-x-0 top-3 z-40 flex justify-center px-3">
      <div className="pointer-events-auto flex flex-wrap items-center justify-center gap-1.5 rounded-2xl border border-white/80 bg-white/92 p-1.5 shadow-[0_16px_48px_rgba(15,23,42,0.08)] backdrop-blur-md">
        {/* Mode Toggle: Live Network vs Simulation */}
        <div className="mr-1 flex items-center rounded-xl bg-slate-100 p-0.5 text-[11px] font-semibold text-slate-600">
          <button
            type="button"
            onClick={() => setDemoMode(false)}
            className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 transition ${
              !demoMode
                ? 'bg-white text-blue-700 shadow-sm'
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                probes.total_connected > 0 ? 'bg-emerald-500 animate-pulse' : 'bg-amber-400'
              }`}
            />
            Live Network ({probes.total_connected} Probes)
          </button>
          <button
            type="button"
            onClick={() => setDemoMode(true)}
            className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 transition ${
              demoMode
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            <Play size={12} />
            Demo Simulation
          </button>
        </div>

        {/* Defense Test Case Buttons */}
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

        {/* Dynamic Multi-Client Nodes Selector (active in demo mode) */}
        {demoMode ? (
          <div className="flex items-center gap-1 border-l border-slate-200/80 pl-2">
            <span className="flex items-center gap-1 text-[11px] font-medium text-slate-500">
              <Users size={12} />
              Clients:
            </span>
            {[1, 2, 3, 4].map((n) => (
              <button
                key={n}
                type="button"
                onClick={() => setClientCount(n)}
                className={`h-6 w-6 rounded-lg text-[11px] font-semibold transition ${
                  clientCount === n
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
                title={`Simulate with ${n} Client Node${n > 1 ? 's' : ''}`}
              >
                {n}
              </button>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-1.5 border-l border-slate-200/80 pl-2 text-[11px] font-medium text-slate-500">
            <Wifi size={12} className={probes.total_connected > 0 ? 'text-emerald-500' : 'text-slate-400'} />
            <span>
              {probes.total_connected === 0
                ? 'Waiting for Linux VM probes...'
                : `${probes.total_connected} VM Probe${probes.total_connected > 1 ? 's' : ''} Connected`}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}

function SimButton({
  children,
  onClick,
  tone,
}: {
  children: ReactNode
  onClick: () => void
  tone: 'blue' | 'slate' | 'crimson' | 'amber' | 'cyan'
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
      className={`flex items-center gap-1.5 rounded-xl px-3 py-2 text-[12px] font-medium transition ${cls}`}
    >
      {children}
    </button>
  )
}
