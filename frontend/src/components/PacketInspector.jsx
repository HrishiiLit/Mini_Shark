/**
 * Wireshark-style packet inspector with continuous live capture via SSE.
 *
 * Three-pane layout:
 *   TOP    — scrollable packet list (No, Time, Src, Dst, Protocol, Length, Info)
 *   MIDDLE — protocol tree for selected packet (expandable layers)
 *   BOTTOM — hex dump
 */

import { useState, useEffect, useRef, useCallback } from 'react'

const API = 'http://127.0.0.1:8001'

// ── protocol colour coding ────────────────────────────────────────────────────
const PROTO = {
  TCP:     { bg:'#dbeafe', fg:'#1e40af', border:'#93c5fd' },
  UDP:     { bg:'#dcfce7', fg:'#166534', border:'#86efac' },
  DNS:     { bg:'#fef9c3', fg:'#854d0e', border:'#fde047' },
  HTTP:    { bg:'#fee2e2', fg:'#991b1b', border:'#fca5a5' },
  ICMP:    { bg:'#f3e8ff', fg:'#6b21a8', border:'#d8b4fe' },
  ARP:     { bg:'#ffedd5', fg:'#9a3412', border:'#fdba74' },
  IPv4:    { bg:'#f1f5f9', fg:'#334155', border:'#cbd5e1' },
  IPv6:    { bg:'#e0f2fe', fg:'#0c4a6e', border:'#7dd3fc' },
  DEFAULT: { bg:'#f8fafc', fg:'#475569', border:'#e2e8f0' },
}
const pc = (p) => PROTO[p] || PROTO.DEFAULT

// ── hex dump ──────────────────────────────────────────────────────────────────
function hexDump(hexStr) {
  if (!hexStr) return []
  const bytes = []
  for (let i = 0; i < hexStr.length; i += 2)
    bytes.push(parseInt(hexStr.slice(i, i+2), 16))
  const rows = []
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i+16)
    const hex   = chunk.map(b => b.toString(16).padStart(2,'0')).join(' ')
    const ascii = chunk.map(b => (b>=32&&b<127) ? String.fromCharCode(b) : '.').join('')
    rows.push({ offset: i.toString(16).padStart(4,'0'), hex, ascii })
  }
  return rows
}

// ── layer tree node ───────────────────────────────────────────────────────────
function LayerNode({ layer, depth = 0 }) {
  const [open, setOpen] = useState(true)
  const c = pc(layer.name)
  const fields = Object.entries(layer.fields || {})
    .filter(([k]) => k !== 'malformed' && k !== 'truncated')

  return (
    <div style={{ marginLeft: depth * 14, marginBottom: 2 }}>
      <div onClick={() => setOpen(o => !o)} style={{
        display:'flex', alignItems:'center', gap:5, cursor:'pointer',
        padding:'2px 6px', borderRadius:3, userSelect:'none',
        background: c.bg, color: c.fg, fontWeight:600, fontSize:12,
        border:`1px solid ${c.border}`,
      }}>
        <span style={{ fontSize:9, opacity:0.7 }}>{open ? '▼' : '▶'}</span>
        {layer.name}
        {layer.fields?.malformed && <span style={{ color:'#dc2626', marginLeft:4, fontSize:10 }}>[MALFORMED]</span>}
        {layer.fields?.truncated && <span style={{ color:'#d97706', marginLeft:4, fontSize:10 }}>[TRUNCATED]</span>}
      </div>
      {open && fields.length > 0 && (
        <div style={{ marginLeft:12, marginTop:1, borderLeft:`2px solid ${c.border}`,
                      paddingLeft:6 }}>
          {fields.map(([k, v]) => (
            <div key={k} style={{
              display:'flex', gap:8, padding:'1px 2px', fontSize:11,
              fontFamily:'Consolas,monospace',
            }}>
              <span style={{ color:'#1d4ed8', minWidth:150, flexShrink:0 }}>{k}</span>
              <span style={{ color:'#111827', wordBreak:'break-all' }}>
                {typeof v === 'object' ? JSON.stringify(v) : String(v)}
              </span>
            </div>
          ))}
          {layer.undecoded_hex?.length > 0 && (
            <div style={{ fontSize:10, color:'#9ca3af', fontFamily:'monospace', padding:'1px 2px' }}>
              undecoded: {layer.undecoded_hex.slice(0,80)}{layer.undecoded_hex.length>80?'…':''}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── hex view ──────────────────────────────────────────────────────────────────
function HexView({ layers, length }) {
  const allHex = (layers||[]).map(l => l.undecoded_hex||'').join('')
  if (!allHex) return (
    <div style={{ fontSize:11, color:'#94a3b8', fontFamily:'monospace', padding:4 }}>
      <div style={{ color:'#34d399' }}>Frame: {length} bytes — fully decoded</div>
    </div>
  )
  const rows = hexDump(allHex)
  return (
    <div style={{ fontFamily:'Consolas,monospace', fontSize:11 }}>
      {rows.slice(0,20).map((row,i) => (
        <div key={i} style={{ display:'flex', gap:12, lineHeight:'18px' }}>
          <span style={{ color:'#94a3b8', minWidth:32 }}>{row.offset}</span>
          <span style={{ color:'#93c5fd', letterSpacing:'0.3px', minWidth:290 }}>{row.hex.padEnd(47,' ')}</span>
          <span style={{ color:'#6ee7b7' }}>{row.ascii}</span>
        </div>
      ))}
      {rows.length > 20 && <div style={{ color:'#64748b' }}>… {rows.length-20} more rows</div>}
    </div>
  )
}

// ── main PacketInspector ──────────────────────────────────────────────────────
export default function PacketInspector({ captureId }) {
  // stored-capture state
  const [storedPkts, setStoredPkts] = useState([])
  const [loadingStored, setLoadingStored] = useState(false)

  // live-stream state
  const [livePkts,    setLivePkts]    = useState([])
  const [streaming,   setStreaming]   = useState(false)
  const [streamStatus,setStreamStatus]= useState('')
  const [iface,       setIface]       = useState('')
  const [bpfFilter,   setBpfFilter]   = useState('')
  const esRef   = useRef(null)
  const scrollRef = useRef(null)

  // shared
  const [selected,   setSelected]  = useState(null)
  const [filterText, setFilterText] = useState('')
  const [mode,       setMode]       = useState('stored') // 'stored' | 'live'
  const [autoScroll, setAutoScroll] = useState(true)

  // ── load stored capture ──────────────────────────────────────────────────
  useEffect(() => {
    if (captureId == null || mode !== 'stored') return
    setLoadingStored(true)
    fetch(`${API}/captures/${captureId}/inspector?offset=0&limit=200`)
      .then(r => r.json())
      .then(d => { setStoredPkts(d.packets||[]); setSelected(null) })
      .catch(() => {})
      .finally(() => setLoadingStored(false))
  }, [captureId, mode])

  // ── start/stop SSE stream ─────────────────────────────────────────────────
  const startStream = useCallback(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null }
    setLivePkts([])
    setSelected(null)
    setStreamStatus('Connecting...')
    setStreaming(true)

    const params = new URLSearchParams()
    if (iface)     params.set('iface', iface)
    if (bpfFilter) params.set('bpf_filter', bpfFilter)

    const url = `${API}/captures/stream?${params}`
    const es  = new EventSource(url)
    esRef.current = es

    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'started')   setStreamStatus(`Capturing on ${msg.interface}`)
        if (msg.type === 'heartbeat') setStreamStatus(`${msg.total} packets captured`)
        if (msg.type === 'error')     setStreamStatus(`Error: ${msg.message}`)
        if (msg.type === 'packet') {
          setLivePkts(prev => {
            const next = [...prev, msg]
            return next.length > 2000 ? next.slice(-2000) : next // keep last 2000
          })
        }
      } catch {}
    }
    es.onerror = () => {
      setStreamStatus('Stream ended or connection lost')
      setStreaming(false)
    }
  }, [iface, bpfFilter])

  const stopStream = useCallback(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null }
    setStreaming(false)
    setStreamStatus('Stopped')
  }, [])

  useEffect(() => () => { esRef.current?.close() }, [])

  // auto-scroll packet list when new packets arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current && mode === 'live') {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [livePkts, autoScroll, mode])

  // ── which packets to show ─────────────────────────────────────────────────
  const allPkts = mode === 'live' ? livePkts : storedPkts
  const visible = filterText.trim()
    ? allPkts.filter(p =>
        p.protocol?.toLowerCase().includes(filterText.toLowerCase()) ||
        p.src_ip?.includes(filterText) ||
        p.dst_ip?.includes(filterText) ||
        p.info?.toLowerCase().includes(filterText.toLowerCase()) ||
        String(p.src_port).includes(filterText) ||
        String(p.dst_port).includes(filterText)
      )
    : allPkts

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ display:'flex', flexDirection:'column', background:'#fff',
                  border:'1px solid #e2e8f0', borderRadius:8, overflow:'hidden',
                  fontFamily:"'Segoe UI',system-ui,sans-serif" }}>

      {/* ── toolbar ── */}
      <div style={{ padding:'8px 10px', background:'#f8fafc',
                    borderBottom:'2px solid #e2e8f0', display:'flex',
                    gap:8, alignItems:'center', flexWrap:'wrap' }}>

        {/* mode toggle */}
        <div style={{ display:'flex', border:'1px solid #cbd5e1', borderRadius:5, overflow:'hidden' }}>
          {[['stored','📂 Stored'],['live','📡 Live']].map(([m,label]) => (
            <button key={m} onClick={() => setMode(m)} style={{
              padding:'4px 12px', border:'none', cursor:'pointer', fontSize:12, fontWeight:600,
              background: mode===m ? '#1e40af' : '#fff',
              color:      mode===m ? '#fff'    : '#64748b',
            }}>{label}</button>
          ))}
        </div>

        {/* live controls */}
        {mode === 'live' && (
          <>
            <input value={iface} onChange={e=>setIface(e.target.value)}
              placeholder="Interface (blank = auto Wi-Fi)"
              style={{ width:160, padding:'4px 8px', border:'1px solid #cbd5e1',
                       borderRadius:4, fontSize:12 }} />
            <input value={bpfFilter} onChange={e=>setBpfFilter(e.target.value)}
              placeholder="BPF filter (e.g. port 53)"
              style={{ width:140, padding:'4px 8px', border:'1px solid #cbd5e1',
                       borderRadius:4, fontSize:12 }} />
            {!streaming
              ? <button onClick={startStream} style={{
                    padding:'4px 14px', borderRadius:4, border:'none',
                    background:'#16a34a', color:'#fff', cursor:'pointer',
                    fontWeight:600, fontSize:12 }}>▶ Start</button>
              : <button onClick={stopStream} style={{
                    padding:'4px 14px', borderRadius:4, border:'none',
                    background:'#dc2626', color:'#fff', cursor:'pointer',
                    fontWeight:600, fontSize:12 }}>■ Stop</button>
            }
            {streaming && (
              <span style={{ fontSize:11, color:'#16a34a', fontWeight:600 }}>
                🔴 {streamStatus}
              </span>
            )}
            {!streaming && streamStatus && (
              <span style={{ fontSize:11, color:'#64748b' }}>{streamStatus}</span>
            )}
            <label style={{ fontSize:11, color:'#64748b', display:'flex', gap:4, alignItems:'center' }}>
              <input type="checkbox" checked={autoScroll}
                onChange={e=>setAutoScroll(e.target.checked)} />
              Auto-scroll
            </label>
          </>
        )}

        {/* filter */}
        <input value={filterText} onChange={e=>setFilterText(e.target.value)}
          placeholder="Display filter: ip, port, DNS, HTTP, 8.8.8.8 ..."
          style={{ flex:1, minWidth:180, padding:'4px 8px',
                   border:'1px solid #0550ae', borderRadius:4,
                   fontSize:12, outline:'none' }} />
        {filterText && (
          <button onClick={()=>setFilterText('')} style={{
            padding:'4px 10px', border:'1px solid #cbd5e1', borderRadius:4,
            background:'#fff', cursor:'pointer', fontSize:12 }}>✕</button>
        )}
        <span style={{ fontSize:11, color:'#94a3b8', whiteSpace:'nowrap' }}>
          {visible.length}{mode==='live'?' live':''} / {allPkts.length} pkts
        </span>
      </div>

      {/* ── packet list ── */}
      <div ref={scrollRef} style={{ overflowY:'auto', height:280,
                                    borderBottom:'2px solid #e2e8f0' }}>
        {loadingStored && (
          <div style={{ padding:20, textAlign:'center', color:'#94a3b8', fontSize:13 }}>
            Loading packets...
          </div>
        )}
        {mode === 'live' && !streaming && livePkts.length === 0 && (
          <div style={{ padding:32, textAlign:'center', color:'#94a3b8', fontSize:13 }}>
            Click <strong>▶ Start</strong> to begin live capture from your Wi-Fi adapter.<br/>
            Packets appear here in real time as they arrive.
          </div>
        )}
        {mode === 'stored' && !loadingStored && storedPkts.length === 0 && (
          <div style={{ padding:32, textAlign:'center', color:'#94a3b8', fontSize:13 }}>
            {captureId ? 'No packets in this capture' : 'Select or upload a capture first'}
          </div>
        )}

        {visible.length > 0 && (
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ position:'sticky', top:0, background:'#f1f5f9', zIndex:1 }}>
                {['No.','Time','Source','Destination','Protocol','Len','Info'].map(h => (
                  <th key={h} style={{ padding:'4px 8px', borderBottom:'1px solid #e2e8f0',
                                        textAlign:'left', fontWeight:600, color:'#475569',
                                        whiteSpace:'nowrap', fontSize:11 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((pkt, i) => {
                const c = pc(pkt.protocol)
                const isSel = selected?.index === pkt.index && selected?._mode === mode
                return (
                  <tr key={`${mode}-${pkt.index}`}
                    onClick={() => setSelected({...pkt, _mode: mode})}
                    style={{
                      cursor: 'pointer',
                      background: isSel ? '#1e40af' : (i%2===0 ? c.bg : '#fff'),
                      color:      isSel ? '#fff'    : c.fg,
                    }}>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9', fontFamily:'monospace' }}>
                      {pkt.index}
                    </td>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9', fontFamily:'monospace', whiteSpace:'nowrap' }}>
                      {typeof pkt.timestamp === 'number' ? pkt.timestamp.toFixed(6) : pkt.timestamp}
                    </td>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9', whiteSpace:'nowrap' }}>
                      {pkt.src_ip}{pkt.src_port ? `:${pkt.src_port}` : ''}
                    </td>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9', whiteSpace:'nowrap' }}>
                      {pkt.dst_ip}{pkt.dst_port ? `:${pkt.dst_port}` : ''}
                    </td>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9', fontWeight:700 }}>
                      {pkt.protocol}
                      {pkt.dns_exfil_suspect && <span title="High entropy DNS" style={{ marginLeft:4, color:'#dc2626' }}>⚠</span>}
                    </td>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9', fontFamily:'monospace' }}>
                      {pkt.length}
                    </td>
                    <td style={{ padding:'2px 8px', borderBottom:'1px solid #f1f5f9',
                                 maxWidth:320, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {pkt.info}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* ── detail panes ── */}
      {selected && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', minHeight:220 }}>
          {/* protocol tree */}
          <div style={{ padding:10, overflowY:'auto', maxHeight:260,
                        borderRight:'1px solid #e2e8f0', background:'#fafafa' }}>
            <div style={{ fontSize:10, color:'#64748b', marginBottom:6, fontWeight:600, letterSpacing:'0.5px' }}>
              FRAME {selected.index} · {selected.length} BYTES · {selected.protocol}
              {selected.fingerprint && (
                <span style={{ marginLeft:8, fontFamily:'monospace', color:'#1d4ed8' }}>
                  {selected.fingerprint}
                </span>
              )}
              {selected.dns_entropy != null && (
                <span style={{ marginLeft:8, color: selected.dns_exfil_suspect?'#dc2626':'#16a34a' }}>
                  H={selected.dns_entropy.toFixed(3)} bits{selected.dns_exfil_suspect?' ⚠ HIGH ENTROPY':''}
                </span>
              )}
            </div>
            {(selected.layers||[]).map((layer, i) => (
              <LayerNode key={i} layer={layer} depth={i} />
            ))}
          </div>

          {/* hex dump */}
          <div style={{ padding:10, overflowY:'auto', maxHeight:260,
                        background:'#0f172a' }}>
            <div style={{ fontSize:10, color:'#64748b', marginBottom:6, fontWeight:600,
                          letterSpacing:'0.5px', color:'#94a3b8' }}>
              HEX DUMP
            </div>
            <HexView layers={selected.layers} length={selected.length} />
          </div>
        </div>
      )}

      {!selected && (
        <div style={{ padding:12, textAlign:'center', color:'#94a3b8', fontSize:12,
                      background:'#f8fafc', borderTop:'1px solid #e2e8f0' }}>
          Click any row to see protocol tree and hex dump
        </div>
      )}
    </div>
  )
}
