import { useMemo, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import type { ByteKind, Packet, ProtocolLayer } from '../types'

export function ProtocolTree({ packet }: { packet: Packet | undefined }) {
  if (!packet) {
    return (
      <EmptyPane title="Panel B · Hierarchical protocol tree" body="Select a correlated frame to expand Ethernet → IPv4 → L4 → Mini-Shark fingerprint." />
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-[#F8FAFC]">
      <div className="border-b border-slate-200 px-3 py-1.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">
        Panel B · Protocol tree · Frame {packet.id}
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-2">
        {packet.layers.map((layer) => (
          <Layer key={layer.id} layer={layer} defaultOpen />
        ))}
      </div>
    </div>
  )
}

function Layer({ layer, defaultOpen }: { layer: ProtocolLayer; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? true)
  const tone =
    layer.kind === 'mutating'
      ? 'border-slate-200 bg-white'
      : layer.kind === 'invariant'
        ? 'border-sky-200 bg-sky-50/70'
        : 'border-slate-200 bg-white'

  return (
    <div className={`mb-2 overflow-hidden rounded-xl border ${tone}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-2 px-3 py-2 text-left"
      >
        <ChevronRight size={14} className={`mt-0.5 shrink-0 text-slate-400 transition ${open ? 'rotate-90' : ''}`} />
        <div>
          <div className="font-display text-[13px] font-medium text-slate-900">{layer.title}</div>
          <div className="font-mono text-[11px] text-slate-500">{layer.summary}</div>
        </div>
      </button>
      {open && (
        <div className="border-t border-slate-100 px-3 py-2">
          {layer.fields.map((f) => (
            <div key={f.label} className="grid grid-cols-[140px_1fr] gap-2 py-0.5 text-[12px]">
              <span className="text-slate-500">{f.label}</span>
              <span
                className={`font-mono ${
                  f.kind === 'mutating' ? 'text-slate-400 line-through decoration-slate-300' : f.kind === 'invariant' ? 'text-sky-800' : 'text-slate-800'
                }`}
              >
                {f.value}
              </span>
            </div>
          ))}
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
      <EmptyPane title="Panel C · Color-coded hex dump" body="Immutable hashed bytes glow blue. Mutating MAC / TTL / checksums are grayed and struck." />
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col border-l border-slate-200 bg-white">
      <div className="flex items-center justify-between border-b border-slate-200 px-3 py-1.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">
        <span>Panel C · Hex dump</span>
        <span className="flex gap-2 normal-case tracking-normal">
          <i className="rounded bg-sky-100 px-1.5 py-0.5 text-sky-800">hashed</i>
          <i className="rounded bg-slate-200 px-1.5 py-0.5 text-slate-500">mutating</i>
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3 font-mono text-[11px] leading-5">
        {rows.map((row) => (
          <div key={row.off} className="grid grid-cols-[64px_1fr_140px] gap-3">
            <span className="text-slate-400">{row.off.toString(16).padStart(4, '0')}</span>
            <span className="flex flex-wrap gap-x-1">
              {row.bytes.map((cell, idx) => {
                const abs = row.off + idx
                return (
                  <span
                    key={idx}
                    title={`${cell.k} @ 0x${abs.toString(16)}`}
                    onMouseEnter={() => setHover(abs)}
                    onMouseLeave={() => setHover(null)}
                    className={`cursor-default ${
                      cell.k === 'invariant'
                        ? 'rounded-sm bg-sky-100 px-0.5 text-sky-900'
                        : cell.k === 'mutating'
                          ? 'rounded-sm bg-slate-200 px-0.5 text-slate-400 line-through'
                          : 'px-0.5 text-slate-700'
                    } ${hover === abs ? 'outline outline-1 outline-sky-500' : ''}`}
                  >
                    {cell.b.toString(16).padStart(2, '0')}
                  </span>
                )
              })}
            </span>
            <span className="text-slate-500">{row.ascii}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function EmptyPane({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex h-full flex-col bg-[#F8FAFC]">
      <div className="border-b border-slate-200 px-3 py-1.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <div className="grid flex-1 place-items-center px-8 text-center text-sm text-slate-400">{body}</div>
    </div>
  )
}
