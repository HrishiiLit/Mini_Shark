import { HeaderBar } from './components/HeaderBar'
import { Inspector } from './components/Inspector'
import { TopologyView } from './components/TopologyView'

export default function App() {
  return (
    <div className="flex h-svh flex-col bg-white text-slate-800">
      <HeaderBar />
      <main className="grid min-h-0 flex-1 grid-rows-2">
        <TopologyView />
        <Inspector />
      </main>
    </div>
  )
}
