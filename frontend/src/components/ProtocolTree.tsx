import { useMemo, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import type { ByteKind, Packet, ProtocolLayer } from '../types'

export function ProtocolTree({ packet }: { packet: Packet | undefined }) {
  if (!packet) {
    return (
      <EmptyPane
        title="Packet Details · Protocol Tree"
        body="Select a packet in the table above to dissect Ethernet → IPv4 → L4 Protocol → BLAKE2b Invariant Fingerprint."
      />
    )
  }

  const isArch = packet.srcIp === '10.108.157.186' || packet.clientId === 1

  return (
    <div className="flex h-full min-h-0 flex-col bg-[#F8FAFC]">
      <div className="flex items-center justify-between border-b border-slate-200 bg-[#E2E8F0] px-3 py-1 text-[11px] font-semibold text-slate-700">
        <div className="flex items-center gap-2">
          <span>Packet Details</span>
          <span className="text-slate-400">·</span>
          <span className="font-mono text-slate-900">Frame {packet.id}</span>
          <span className="text-slate-400">·</span>
          <span className="rounded bg-blue-100 px-1.5 text-[10px] font-bold text-blue-800">
            {isArch ? 'Ingress: Laptop 2 (Arch Host)' : 'Ingress: Laptop 1 (VM2 Client)'}
          </span>
        </div>
        <span className="font-mono text-[10px] text-slate-500">{packet.length} bytes on wire</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-2.5 font-sans">
        {packet.layers.map((layer) => (
          <Layer key={layer.id} layer={layer} defaultOpen />
        ))}
      </div>
    </div>
  )
}

function Layer({ layer, defaultOpen }: { layer: ProtocolLayer; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? true)
  const isInvariant = layer.kind === 'invariant'
  const isMutating = layer.kind === 'mutating'

  return (
    <div className="mb-1.5 overflow-hidden rounded border border-slate-200 bg-white shadow-2xs">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-1.5 bg-slate-50/70 px-2.5 py-1.5 text-left hover:bg-slate-100/80 transition"
      >
        <ChevronRight
          size={14}
          className={`mt-0.5 shrink-0 text-slate-500 transition-transform ${open ? 'rotate-90' : ''}`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium text-[12px] text-slate-900">{layer.title}</span>
            {isInvariant && (
              <span className="rounded bg-sky-100 px-1 text-[9px] font-bold uppercase text-sky-800">
                BLAKE2b Invariant
              </span>
            )}
            {isMutating && (
              <span className="rounded bg-slate-200 px-1 text-[9px] font-semibold uppercase text-slate-600">
                Mutating (Excluded)
              </span>
            )}
          </div>
          <div className="truncate font-mono text-[10.5px] text-slate-500">{layer.summary}</div>
        </div>
      </button>

      {open && (
        <div className="divide-y divide-slate-100 border-t border-slate-200 bg-white px-3 py-1 font-mono text-[11px]">
          {layer.fields.map((f) => {
            const isFieldMut = f.kind === 'mutating'
            const isFieldInv = f.kind === 'invariant'

            return (
              <div key={f.label} className="grid grid-cols-[160px_1fr] items-center gap-2 py-0.5">
                <span className="text-slate-500 font-sans text-[11px]">{f.label}:</span>
                <span
                  className={`${
                    isFieldMut
                      ? 'text-slate-400 line-through decoration-slate-300'
                      : isFieldInv
                        ? 'font-bold text-sky-800'
                        : 'text-slate-800'
                  }`}
                >
                  {f.value}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export function HexDump({ packet }: { packet: Packet | undefined }) {
  const [hover, setHover] = useState<number | null>(null)
  const rows = useMemo(() => {
    if (!packet) return []
    const out: { off: number; bytes: { b: number; k: ByteKind }[]; ascii: string }[] = []
    for (let i = 0; i < packet.bytes.length; i += 16) {
      const slice = packet.bytes.slice(i, i + 16)
      const ascii = slice.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('')
      out.push({
        off: i,
        bytes: slice.map((b, j) => ({ b, k: packet.byteKinds[i + j] })),
        ascii,
      })
    }
    return out
  }, [packet])

  if (!packet) {
    return (
      <EmptyPane
        title="Packet Bytes · Hex Dump"
        body="Raw wire bytes. Invariant hashed bytes glow blue. Mutating MACs, TTL, and checksums are struck."
      />
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col border-l border-slate-300 bg-white">
      <div className="flex items-center justify-between border-b border-slate-200 bg-[#E2E8F0] px-3 py-1 text-[11px] font-semibold text-slate-700">
        <span>Packet Bytes (Hex & ASCII Dump)</span>
        <div className="flex items-center gap-2 font-mono text-[9.5px]">
          <span className="rounded bg-sky-100 px-1.5 text-sky-800 font-bold">Hashed (Invariant)</span>
          <span className="rounded bg-slate-200 px-1.5 text-slate-500 line-through">Mutating</span>
          <span className="rounded bg-slate-100 px-1.5 text-slate-700">Payload</span>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3 font-mono text-[11px] leading-5 bg-[#FAFAFA]">
        {rows.map((row) => (
          <div key={row.off} className="grid grid-cols-[55px_1fr_130px] gap-2 hover:bg-slate-100/60 rounded px-1">
            <span className="text-slate-400 select-none">
              {row.off.toString(16).padStart(4, '0')}
            </span>
            <div className="flex items-center gap-x-1.5">
              {/* Group 1: bytes 0-7 */}
              <span className="flex gap-x-1">
                {row.bytes.slice(0, 8).map((cell, idx) => {
                  const abs = row.off + idx
                  return (
                    <span
                      key={idx}
                      title={`${cell.k} @ 0x${abs.toString(16)}`}
                      onMouseEnter={() => setHover(abs)}
                      onMouseLeave={() => setHover(null)}
                      className={`cursor-default ${
                        cell.k === 'invariant'
                          ? 'rounded-xs bg-sky-100 px-0.5 text-sky-900 font-bold'
                          : cell.k === 'mutating'
                            ? 'rounded-xs bg-slate-200 px-0.5 text-slate-400 line-through'
                            : 'px-0.5 text-slate-700'
                      } ${hover === abs ? 'ring-1 ring-blue-500' : ''}`}
                    >
                      {cell.b.toString(16).padStart(2, '0')}
                    </span>
                  )
                })}
              </span>
              <span className="text-slate-300">|</span>
              {/* Group 2: bytes 8-15 */}
              <span className="flex gap-x-1">
                {row.bytes.slice(8, 16).map((cell, idx) => {
                  const abs = row.off + 8 + idx
                  return (
                    <span
                      key={idx}
                      title={`${cell.k} @ 0x${abs.toString(16)}`}
                      onMouseEnter={() => setHover(abs)}
                      onMouseLeave={() => setHover(null)}
                      className={`cursor-default ${
                        cell.k === 'invariant'
                          ? 'rounded-xs bg-sky-100 px-0.5 text-sky-900 font-bold'
                          : cell.k === 'mutating'
                            ? 'rounded-xs bg-slate-200 px-0.5 text-slate-400 line-through'
                            : 'px-0.5 text-slate-700'
                      } ${hover === abs ? 'ring-1 ring-blue-500' : ''}`}
                    >
                      {cell.b.toString(16).padStart(2, '0')}
                    </span>
                  )
                })}
              </span>
            </div>
            <span className="text-slate-600 tracking-wider">{row.ascii}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function EmptyPane({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex h-full flex-col bg-[#F8FAFC]">
      <div className="border-b border-slate-200 bg-[#E2E8F0] px-3 py-1 text-[11px] font-semibold text-slate-700">
        {title}
      </div>
      <div className="grid flex-1 place-items-center px-8 text-center text-xs text-slate-400">
        {body}
      </div>
    </div>
  )
}
