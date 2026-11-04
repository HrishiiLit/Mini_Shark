import { useState } from 'react'
import { HeaderBar } from './components/HeaderBar'
import { Inspector } from './components/Inspector'
import { TopologyView } from './components/TopologyView'
// @ts-expect-error JSX component
import MiniShark from './components/MiniShark'

export default function App() {
  const [view, setView] = useState<'3d' | 'classic'>('3d')

  return (
    <div className="flex h-svh flex-col bg-white text-slate-800">
      <HeaderBar view={view} onViewChange={setView} />
      {view === '3d' ? (
        <main className="grid min-h-0 flex-1 grid-rows-2">
          <TopologyView />
          <Inspector />
        </main>
      ) : (
        <main className="min-h-0 flex-1 overflow-hidden">
          <MiniShark onSwitchView={() => setView('3d')} />
        </main>
      )}
    </div>
  )
}
