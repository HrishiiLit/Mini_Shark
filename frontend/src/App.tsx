import { HeaderBar } from './components/HeaderBar'
import { PacketTable } from './components/PacketTable'
import { ProtocolTree, HexDump } from './components/ProtocolTree'
import { useCaptureStore } from './store/useCaptureStore'

export default function App() {
  const selectedId = useCaptureStore((s) => s.selectedId)
  const packets = useCaptureStore((s) => s.packets)
  const viewMode = useCaptureStore((s) => s.viewMode)
  const packet = packets.find((p) => p.id === selectedId)

  return (
    <div className="flex h-svh flex-col bg-[#F8FAFC] font-sans text-slate-800 select-none">
      <HeaderBar />
      {viewMode === 'observatory' ? (
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden bg-[#090D16]">
          <iframe
            src="/dashboard.html"
            title="Mini-Shark 3D Observatory"
            className="h-full w-full border-none"
          />
        </main>
      ) : viewMode === 'split' ? (
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden bg-white">
          <div className="flex min-h-0 flex-1 flex-col border-b border-slate-300">
            <iframe
              src="/dashboard.html"
              title="Mini-Shark 3D Observatory"
              className="h-full w-full border-none"
            />
          </div>
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="flex min-h-0 flex-[3] flex-col border-b border-slate-300">
              <PacketTable />
            </div>
            <div className="grid min-h-0 flex-[2] grid-cols-2 overflow-hidden bg-white">
              <ProtocolTree packet={packet} />
              <HexDump packet={packet} />
            </div>
          </div>
        </main>
      ) : (
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden bg-white">
          {/* Pane 1: Wireshark Packet List */}
          <div className="flex min-h-0 flex-[3] flex-col border-b border-slate-300">
            <PacketTable />
          </div>
          {/* Pane 2 & 3: Protocol Tree & Hex Dump */}
          <div className="grid min-h-0 flex-[2] grid-cols-2 overflow-hidden bg-white">
            <ProtocolTree packet={packet} />
            <HexDump packet={packet} />
          </div>
        </main>
      )}
    </div>
  )
}
