import { ProtocolTree, HexDump } from './ProtocolTree'
import { PacketTable } from './PacketTable'
import { useCaptureStore } from '../store/useCaptureStore'

export function Inspector() {
  const selectedId = useCaptureStore((s) => s.selectedId)
  const packets = useCaptureStore((s) => s.packets)
  const packet = packets.find((p) => p.id === selectedId)

  return (
    <section className="flex min-h-0 flex-1 flex-col border-t border-slate-200 bg-white">
      <PacketTable />
      <div className="grid min-h-0 flex-1 grid-cols-2 overflow-hidden">
        <ProtocolTree packet={packet} />
        <HexDump packet={packet} />
      </div>
    </section>
  )
}
