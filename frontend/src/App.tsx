import { HeaderBar } from './components/HeaderBar'
import { Inspector } from './components/Inspector'
import { TopologyView } from './components/TopologyView'
import { PacketTable } from './components/PacketTable'
import { ProtocolTree, HexDump } from './components/ProtocolTree'
import { useCaptureStore } from './store/useCaptureStore'

export default function App() {
  const viewMode = useCaptureStore((s) => s.viewMode)
  const selectedId = useCaptureStore((s) => s.selectedId)
  const packets = useCaptureStore((s) => s.packets)
  const packet = packets.find((p) => p.id === selectedId)

  return (
    <div className="flex h-svh flex-col bg-[#F8FAFC] font-sans text-slate-800">
      <HeaderBar />
      {viewMode === 'wireshark' && (
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden bg-white">
          <div className="flex min-h-0 flex-[3] flex-col border-b border-slate-300">
            <PacketTable />
          </div>
          <div className="grid min-h-0 flex-[2] grid-cols-2 overflow-hidden bg-white">
            <ProtocolTree packet={packet} />
            <HexDump packet={packet} />
          </div>
        </main>
      )}
      {viewMode === 'observatory' && (
        <main className="grid min-h-0 flex-1 grid-rows-2 overflow-hidden">
          <TopologyView />
          <Inspector />
        </main>
      )}
      {viewMode === 'split' && (
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="min-h-0 flex-[4] border-b border-slate-300">
            <TopologyView />
          </div>
          <div className="flex min-h-0 flex-[3] flex-col border-b border-slate-300">
            <PacketTable />
          </div>
          <div className="grid min-h-0 flex-[3] grid-cols-2 overflow-hidden bg-white">
            <ProtocolTree packet={packet} />
            <HexDump packet={packet} />
          </div>
        </main>
      )}
    </div>
  )
}
