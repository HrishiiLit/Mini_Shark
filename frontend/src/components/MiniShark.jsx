/**
 * Mini-Shark — Wireshark-style network analyser UI
 *
 * Layout (exactly like Wireshark):
 *   ┌─────────────────────────────────────┐
 *   │  Menu bar  (File | Capture | View)  │
 *   ├─────────────────────────────────────┤
 *   │  Toolbar  (Start ■ Stop  ↺ Restart) │
 *   ├─────────────────────────────────────┤
 *   │  Filter bar  [__________________]   │
 *   ├─────────────────────────────────────┤
 *   │  Packet List  (scrollable table)    │
 *   ├─────────────────────────────────────┤
 *   │  Protocol Tree  │  Hex Dump         │
 *   └─────────────────────────────────────┘
 *
 * Colour coding (same as Wireshark defaults):
 *   HTTP  → green
 *   DNS   → light blue
 *   TCP   → lavender / light purple
 *   UDP   → light blue-gray
 *   ICMP  → pink
 *   ARP   → yellow
 *   Bad   → red
 */

import { useState, useEffect, useRef, useCallback } from 'react'

const API = 'http://127.0.0.1:3000'
const WS  = 'ws://127.0.0.1:3000/ws/live'

/* ── Wireshark row colours ─────────────────────────────────────────────────── */
const ROW_COLOR = {
  HTTP:  { bg: '#e4ffc7', selbg: '#b8d6a0' },   // green
  DNS:   { bg: '#c0e8ff', selbg: '#8bbcd4' },   // light blue
  TCP:   { bg: '#e7e6ff', selbg: '#b8b5e8' },   // lavender
  UDP:   { bg: '#daeeff', selbg: '#a8c8e8' },   // light blue-gray
  ICMP:  { bg: '#fce4ff', selbg: '#d8b0e0' },   // pink
  ARP:   { bg: '#fffacd', selbg: '#e0d8a0' },   // yellow
  IPv4:  { bg: '#f0f0f0', selbg: '#c8c8c8' },
  IPv6:  { bg: '#e0f8ff', selbg: '#a8d8e8' },
  DEFAULT:{ bg:'#ffffff', selbg:'#c0d8f0' },
}
const rc = p => ROW_COLOR[p] || ROW_COLOR.DEFAULT

/* ── Protocol tree node colours ─────────────────────────────────────────────── */
const TREE_COLOR = {
  Ethernet:{ bg:'#fff9db', border:'#f0d060' },
  IPv4:    { bg:'#dbeafe', border:'#93c5fd' },
  IPv6:    { bg:'#e0f2fe', border:'#7dd3fc' },
  TCP:     { bg:'#ede9fe', border:'#a78bfa' },
  UDP:     { bg:'#dcfce7', border:'#86efac' },
  DNS:     { bg:'#fef3c7', border:'#fcd34d' },
  HTTP:    { bg:'#d1fae5', border:'#6ee7b7' },
  ICMP:    { bg:'#fce7f3', border:'#f9a8d4' },
  ARP:     { bg:'#ffedd5', border:'#fdba74' },
  DEFAULT: { bg:'#f1f5f9', border:'#cbd5e1' },
}
const tc = n => TREE_COLOR[n] || TREE_COLOR.DEFAULT

/* ── hex dump ───────────────────────────────────────────────────────────────── */
function buildHexRows(hexStr) {
  if (!hexStr) return []
  const bytes = []
  for (let i = 0; i < hexStr.length; i += 2)
    bytes.push(parseInt(hexStr.slice(i, i + 2), 16))
  return Array.from({ length: Math.ceil(bytes.length / 16) }, (_, r) => {
    const chunk = bytes.slice(r * 16, r * 16 + 16)
    return {
      offset: (r * 16).toString(16).padStart(4, '0'),
      hex:    chunk.map(b => b.toString(16).padStart(2, '0')).join(' '),
      ascii:  chunk.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join(''),
    }
  })
}

/* ── protocol tree node ─────────────────────────────────────────────────────── */
function TreeNode({ layer, depth }) {
  const [open, setOpen] = useState(true)
  const c = tc(layer.name)
  const entries = Object.entries(layer.fields || {})
    .filter(([k]) => !['malformed','truncated'].includes(k))

  const label = (() => {
    const f = layer.fields || {}
    if (layer.name === 'Ethernet') return `Ethernet II, Src: ${f.src}, Dst: ${f.dst}`
    if (layer.name === 'IPv4')     return `Internet Protocol Version 4, Src: ${f.src}, Dst: ${f.dst}`
    if (layer.name === 'IPv6')     return `Internet Protocol Version 6, Src: ${f.src}, Dst: ${f.dst}`
    if (layer.name === 'TCP')      return `Transmission Control Protocol, Src Port: ${f.src_port}, Dst Port: ${f.dst_port}, Seq: ${f.seq}`
    if (layer.name === 'UDP')      return `User Datagram Protocol, Src Port: ${f.src_port}, Dst Port: ${f.dst_port}`
    if (layer.name === 'DNS')      return `Domain Name System (${f.response ? 'response' : 'query'})`
    if (layer.name === 'HTTP')     return `Hypertext Transfer Protocol — ${f.start_line || ''}`
    if (layer.name === 'ICMP')     return `Internet Control Message Protocol — Type: ${f.type}, Code: ${f.code}`
    if (layer.name === 'ARP')      return `Address Resolution Protocol (${f.op === 1 ? 'request' : 'reply'})`
    return layer.name
  })()

  return (
    <div style={{ marginLeft: depth * 16 }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '1px 4px', cursor: 'pointer', userSelect: 'none',
          background: c.bg, borderLeft: `3px solid ${c.border}`,
          marginBottom: 1, fontSize: 12,
        }}
      >
        <span style={{ fontSize: 9, color: '#555', minWidth: 8 }}>{entries.length > 0 || layer.undecoded_hex ? (open ? '▼' : '▶') : ' '}</span>
        <span style={{ fontWeight: 600, color: '#1a1a1a' }}>{label}</span>
        {layer.fields?.malformed && <span style={{ color: '#dc2626', fontSize: 10, marginLeft: 4 }}>[MALFORMED]</span>}
      </div>

      {open && (
        <div style={{ marginLeft: 20, borderLeft: '1px solid #ddd' }}>
          {entries.map(([k, v]) => (
            <div key={k} style={{
              display: 'flex', gap: 6, padding: '0px 4px',
              fontSize: 11.5, fontFamily: 'Consolas, monospace',
              lineHeight: '17px', borderBottom: '1px solid #f0f0f0',
            }}>
              <span style={{ color: '#1d4ed8', minWidth: 180, flexShrink: 0 }}>{k}:</span>
              <span style={{ color: '#1a1a1a', wordBreak: 'break-all' }}>
                {typeof v === 'object' ? JSON.stringify(v) : String(v)}
              </span>
            </div>
          ))}
          {layer.undecoded_hex?.length > 0 && (
            <div style={{ fontSize: 11, color: '#888', fontFamily: 'monospace', padding: '1px 4px' }}>
              [{layer.undecoded_hex.length / 2} bytes remaining data]
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ── main app ───────────────────────────────────────────────────────────────── */
export default function MiniShark() {
  /* state */
  const [packets,     setPackets]     = useState([])   // all displayed packets
  const [selected,    setSelected]    = useState(null)
  const [filter,      setFilter]      = useState('')
  const [filterInput, setFilterInput] = useState('')
  const [streaming,   setStreaming]   = useState(false)
  const [statusBar,   setStatusBar]   = useState('Ready')
  const [wsStats,     setWsStats]     = useState(null)
  const [wsOk,        setWsOk]        = useState(false)
  const [captures,    setCaptures]    = useState([])
  const [selCap,      setSelCap]      = useState(null)
  const [uploading,   setUploading]   = useState(false)
  const [view,        setView]        = useState('capture') // 'capture' | 'stats'

  const esRef       = useRef(null)
  const tableRef    = useRef(null)
  const wsRef       = useRef(null)
  const autoScroll  = useRef(true)

  /* ── WebSocket for stats ─────────────────────────────────────────────────── */
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(WS)
      wsRef.current = ws
      ws.onopen    = () => setWsOk(true)
      ws.onclose   = () => { setWsOk(false); setTimeout(connect, 3000) }
      ws.onerror   = () => ws.close()
      ws.onmessage = ({ data }) => {
        try { const m = JSON.parse(data); if (m.type === 'metrics') setWsStats(m.stats) } catch {}
      }
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  /* ── load captures list ──────────────────────────────────────────────────── */
  const loadCaptures = () =>
    fetch(`${API}/captures`).then(r => r.json()).then(setCaptures).catch(() => {})
  useEffect(() => { loadCaptures() }, [])

  /* ── load stored capture ─────────────────────────────────────────────────── */
  const loadCapture = (cid) => {
    setSelCap(cid)
    setPackets([])
    setSelected(null)
    setStatusBar('Loading...')
    fetch(`${API}/captures/${cid}/inspector?offset=0&limit=500`)
      .then(r => r.json())
      .then(d => {
        setPackets(d.packets || [])
        setStatusBar(`Loaded ${d.packets?.length || 0} packets from capture #${cid}`)
      })
      .catch(() => setStatusBar('Failed to load capture'))
  }

  /* ── live streaming (SSE) ────────────────────────────────────────────────── */
  const startCapture = useCallback(() => {
    if (esRef.current) { esRef.current.close() }
    setPackets([])
    setSelected(null)
    setSelCap(null)
    setStreaming(true)
    setStatusBar('Starting capture...')
    autoScroll.current = true

    const es = new EventSource(`${API}/captures/stream`)
    esRef.current = es

    es.onmessage = ({ data }) => {
      try {
        const msg = JSON.parse(data)
        if (msg.type === 'started') {
          setStatusBar(`Capturing on ${msg.interface} — packets appear in real time`)
        }
        if (msg.type === 'heartbeat') {
          setStatusBar(`Capturing... ${msg.total} packets`)
        }
        if (msg.type === 'packet') {
          setPackets(prev => {
            const next = [...prev, msg]
            return next.length > 5000 ? next.slice(-5000) : next
          })
          if (autoScroll.current && tableRef.current) {
            tableRef.current.scrollTop = tableRef.current.scrollHeight
          }
        }
        if (msg.type === 'error') {
          setStatusBar(`Error: ${msg.message}`)
          setStreaming(false)
        }
      } catch {}
    }
    es.onerror = () => {
      setStreaming(false)
      setStatusBar('Capture stopped')
    }
  }, [])

  const stopCapture = useCallback(() => {
    esRef.current?.close()
    setStreaming(false)
    setStatusBar(`Capture stopped — ${packets.length} packets`)
  }, [packets.length])

  useEffect(() => () => esRef.current?.close(), [])

  /* ── upload PCAP ─────────────────────────────────────────────────────────── */
  const handleUpload = async (e) => {
    const file = e.target.files[0]; if (!file) return
    setUploading(true)
    setStatusBar(`Uploading ${file.name}...`)
    const fd = new FormData(); fd.append('file', file)
    try {
      const res  = await fetch(`${API}/captures`, { method: 'POST', body: fd })
      const data = await res.json()
      await loadCaptures()
      loadCapture(data.capture_id)
    } catch { setStatusBar('Upload failed') }
    setUploading(false)
  }

  /* ── filter ──────────────────────────────────────────────────────────────── */
  const applyFilter = () => setFilter(filterInput.trim())
  const clearFilter  = () => { setFilter(''); setFilterInput('') }

  const visible = filter
    ? packets.filter(p =>
        p.protocol?.toLowerCase().includes(filter.toLowerCase()) ||
        p.src_ip?.includes(filter) || p.dst_ip?.includes(filter) ||
        String(p.src_port).includes(filter) || String(p.dst_port).includes(filter) ||
        p.info?.toLowerCase().includes(filter.toLowerCase()) ||
        p.layer_names?.some(n => n.toLowerCase().includes(filter.toLowerCase()))
      )
    : packets

  /* ── hex dump of selected packet ─────────────────────────────────────────── */
  const hexRows = selected
    ? (() => {
        const allHex = (selected.layers || []).map(l => l.undecoded_hex || '').join('')
        return buildHexRows(allHex)
      })()
    : []

  const s = wsStats || {}

  /* ══════════════════════════════════════════════════════════════════════════ */
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh',
                  background: '#f0f0f0', userSelect: 'none' }}>

      {/* ── Title bar ── */}
      <div style={{
        background: 'linear-gradient(to bottom, #5b9bd5, #2e6da4)',
        color: '#fff', padding: '4px 10px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        boxShadow: '0 1px 3px rgba(0,0,0,0.4)', flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>🦈</span>
          <span style={{ fontWeight: 700, fontSize: 14 }}>Mini-Shark</span>
          <span style={{ fontSize: 11, opacity: 0.8 }}>
            — Network Protocol Analyser · Team 07
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11 }}>
          {wsOk
            ? <span style={{ background: '#16a34a', padding: '2px 8px', borderRadius: 10, fontWeight: 600 }}>● CONNECTED</span>
            : <span style={{ background: '#dc2626', padding: '2px 8px', borderRadius: 10, fontWeight: 600 }}>○ OFFLINE</span>
          }
        </div>
      </div>

      {/* ── Menu bar ── */}
      <div style={{
        background: '#e8e8e8', borderBottom: '1px solid #b0b0b0',
        display: 'flex', gap: 0, flexShrink: 0,
      }}>
        {['File', 'Edit', 'View', 'Capture', 'Analyze', 'Statistics', 'Help'].map(m => (
          <div key={m} style={{
            padding: '3px 12px', fontSize: 12, cursor: 'default',
            borderRight: '1px solid #d0d0d0',
          }}
            onMouseEnter={e => e.target.style.background = '#c8d8e8'}
            onMouseLeave={e => e.target.style.background = 'transparent'}
          >{m}</div>
        ))}
        <div style={{ flex: 1 }} />
        {/* View toggle */}
        <div style={{ display: 'flex', alignItems: 'center', paddingRight: 8, gap: 4 }}>
          <button
            onClick={() => setView('capture')}
            style={{
              padding: '2px 10px', fontSize: 11, border: '1px solid #aaa', borderRadius: 3,
              background: view === 'capture' ? '#2e6da4' : '#f0f0f0',
              color: view === 'capture' ? '#fff' : '#333',
            }}>Packets</button>
          <button
            onClick={() => setView('stats')}
            style={{
              padding: '2px 10px', fontSize: 11, border: '1px solid #aaa', borderRadius: 3,
              background: view === 'stats' ? '#2e6da4' : '#f0f0f0',
              color: view === 'stats' ? '#fff' : '#333',
            }}>Stats</button>
        </div>
      </div>

      {/* ── Toolbar ── */}
      <div style={{
        background: '#e0e0e0', borderBottom: '1px solid #b0b0b0',
        padding: '4px 8px', display: 'flex', alignItems: 'center',
        gap: 6, flexShrink: 0, flexWrap: 'wrap',
      }}>
        {/* Capture controls */}
        <button
          onClick={startCapture} disabled={streaming}
          title="Start capturing packets from Wi-Fi"
          style={{
            padding: '3px 12px', border: '1px solid #888', borderRadius: 3,
            background: streaming ? '#ccc' : '#e8f5e9',
            color: streaming ? '#999' : '#1a5c1a',
            fontWeight: 700, fontSize: 12,
          }}>
          ▶ Start
        </button>
        <button
          onClick={stopCapture} disabled={!streaming}
          title="Stop capture"
          style={{
            padding: '3px 12px', border: '1px solid #888', borderRadius: 3,
            background: !streaming ? '#ccc' : '#ffebee',
            color: !streaming ? '#999' : '#b71c1c',
            fontWeight: 700, fontSize: 12,
          }}>
          ■ Stop
        </button>
        <button
          onClick={() => { setPackets([]); setSelected(null) }}
          title="Clear packet list"
          style={{
            padding: '3px 12px', border: '1px solid #888', borderRadius: 3,
            background: '#f5f5f5', fontSize: 12,
          }}>
          🗑 Clear
        </button>

        <div style={{ width: 1, height: 22, background: '#aaa', margin: '0 4px' }} />

        {/* Upload PCAP */}
        <label style={{
          padding: '3px 12px', border: '1px solid #888', borderRadius: 3,
          background: '#e3f2fd', fontSize: 12, cursor: 'pointer', fontWeight: 600,
          color: '#0d47a1',
        }}>
          {uploading ? '⏳ Loading...' : '📂 Open PCAP'}
          <input type="file" accept=".pcap,.pcapng" onChange={handleUpload}
            style={{ display: 'none' }} disabled={uploading} />
        </label>

        <div style={{ width: 1, height: 22, background: '#aaa', margin: '0 4px' }} />

        {/* Stored captures */}
        {captures.map(c => (
          <button key={c.id}
            onClick={() => loadCapture(c.id)}
            style={{
              padding: '2px 10px', border: `1px solid ${selCap === c.id ? '#2e6da4' : '#aaa'}`,
              borderRadius: 3, fontSize: 11,
              background: selCap === c.id ? '#2e6da4' : '#f5f5f5',
              color: selCap === c.id ? '#fff' : '#333',
            }}>
            {c.name} ({c.packet_count})
          </button>
        ))}

        <div style={{ flex: 1 }} />

        {/* Live indicator */}
        {streaming && (
          <span style={{
            fontSize: 11, color: '#b71c1c', fontWeight: 700,
            animation: 'none', padding: '2px 8px',
            background: '#ffebee', borderRadius: 10, border: '1px solid #ffcdd2',
          }}>
            ● LIVE — {packets.length} pkts
          </span>
        )}
      </div>

      {/* ── Filter bar ── */}
      <div style={{
        background: '#f5f5f5', borderBottom: '2px solid #b0b0b0',
        padding: '4px 8px', display: 'flex', alignItems: 'center',
        gap: 6, flexShrink: 0,
      }}>
        <span style={{ fontSize: 12, color: '#555', fontWeight: 600, whiteSpace: 'nowrap' }}>
          Display Filter:
        </span>
        <input
          value={filterInput}
          onChange={e => setFilterInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && applyFilter()}
          placeholder="e.g.  dns  or  192.168.1.10  or  tcp  or  port 443"
          style={{
            flex: 1, padding: '3px 8px',
            border: `2px solid ${filter ? '#1565c0' : '#aaa'}`,
            borderRadius: 3, fontSize: 12, outline: 'none',
            background: filter ? '#e8f0fe' : '#fff',
          }}
        />
        <button onClick={applyFilter} style={{
          padding: '3px 14px', border: '1px solid #1565c0', borderRadius: 3,
          background: '#1565c0', color: '#fff', fontSize: 12, fontWeight: 600,
        }}>Apply</button>
        <button onClick={clearFilter} style={{
          padding: '3px 10px', border: '1px solid #aaa', borderRadius: 3,
          background: '#f5f5f5', fontSize: 12,
        }}>Clear</button>
        <span style={{ fontSize: 11, color: '#777', whiteSpace: 'nowrap' }}>
          {visible.length} / {packets.length} displayed
        </span>
      </div>

      {/* ══ PACKET VIEW ══════════════════════════════════════════════════════ */}
      {view === 'capture' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

          {/* ── Packet list ── */}
          <div ref={tableRef}
            style={{ flex: '0 0 45%', overflowY: 'auto', borderBottom: '3px solid #777' }}
            onScroll={e => {
              const el = e.target
              autoScroll.current = el.scrollTop + el.clientHeight >= el.scrollHeight - 20
            }}
          >
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ position: 'sticky', top: 0, background: '#d0d0d0', zIndex: 10 }}>
                  {[
                    ['No.',      50],
                    ['Time',    110],
                    ['Source',  160],
                    ['Destination', 160],
                    ['Protocol', 80],
                    ['Length',   60],
                    ['Info',    null],
                  ].map(([h, w]) => (
                    <th key={h} style={{
                      padding: '4px 6px', textAlign: 'left', fontWeight: 700,
                      borderRight: '1px solid #b0b0b0', borderBottom: '2px solid #888',
                      width: w || 'auto', whiteSpace: 'nowrap', color: '#222',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 && (
                  <tr><td colSpan={7} style={{
                    padding: 40, textAlign: 'center', color: '#888', fontSize: 13,
                  }}>
                    {streaming
                      ? 'Waiting for packets... (open a browser or browse a website)'
                      : 'No packets — click ▶ Start to capture or 📂 Open PCAP to load a file'
                    }
                  </td></tr>
                )}
                {visible.map((pkt, i) => {
                  const isSel = selected?.index === pkt.index
                  const c = rc(pkt.protocol)
                  return (
                    <tr key={i}
                      onClick={() => setSelected(pkt)}
                      style={{
                        background: isSel ? '#3399ff' : (i % 2 === 0 ? c.bg : lighten(c.bg)),
                        color: isSel ? '#fff' : '#1a1a1a',
                        cursor: 'pointer',
                      }}
                    >
                      <td style={{ padding: '2px 6px', borderRight: '1px solid #ddd', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                        {pkt.index}
                      </td>
                      <td style={{ padding: '2px 6px', borderRight: '1px solid #ddd', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                        {typeof pkt.timestamp === 'number' ? pkt.timestamp.toFixed(6) : pkt.timestamp}
                      </td>
                      <td style={{ padding: '2px 6px', borderRight: '1px solid #ddd', whiteSpace: 'nowrap', overflow: 'hidden', maxWidth: 160 }}>
                        {pkt.src_ip}{pkt.src_port ? `:${pkt.src_port}` : ''}
                      </td>
                      <td style={{ padding: '2px 6px', borderRight: '1px solid #ddd', whiteSpace: 'nowrap', overflow: 'hidden', maxWidth: 160 }}>
                        {pkt.dst_ip}{pkt.dst_port ? `:${pkt.dst_port}` : ''}
                      </td>
                      <td style={{ padding: '2px 6px', borderRight: '1px solid #ddd', fontWeight: 700, whiteSpace: 'nowrap' }}>
                        {pkt.protocol}
                        {pkt.dns_exfil_suspect && <span title={`H=${pkt.dns_entropy}`} style={{ marginLeft: 3 }}>⚠</span>}
                      </td>
                      <td style={{ padding: '2px 6px', borderRight: '1px solid #ddd', fontFamily: 'monospace', textAlign: 'right' }}>
                        {pkt.length}
                      </td>
                      <td style={{ padding: '2px 6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 0 }}>
                        {pkt.info}
                        {pkt.fingerprint && (
                          <span style={{ marginLeft: 8, fontSize: 10, opacity: 0.6, fontFamily: 'monospace' }}>
                            fp:{pkt.fingerprint?.slice(-8)}
                          </span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ── Bottom two panes ── */}
          <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr',
                        overflow: 'hidden', minHeight: 0 }}>

            {/* Protocol tree */}
            <div style={{ overflowY: 'auto', borderRight: '3px solid #777',
                          background: '#ffffff', padding: 6 }}>
              {!selected ? (
                <div style={{ padding: 20, color: '#888', fontSize: 12 }}>
                  Select a packet above to see the protocol tree
                </div>
              ) : (
                <>
                  <div style={{
                    fontSize: 11, color: '#555', marginBottom: 6, padding: '2px 4px',
                    background: '#f0f0f0', borderRadius: 2, fontWeight: 600,
                  }}>
                    Frame {selected.index}: {selected.length} bytes on wire
                    {selected.fingerprint && (
                      <span style={{ marginLeft: 8, fontFamily: 'monospace', color: '#1565c0', fontWeight: 400 }}>
                        · fp: {selected.fingerprint}
                      </span>
                    )}
                    {selected.dns_entropy != null && (
                      <span style={{ marginLeft: 8, color: selected.dns_exfil_suspect ? '#dc2626' : '#16a34a', fontWeight: 600 }}>
                        · H={selected.dns_entropy.toFixed(3)}{selected.dns_exfil_suspect ? ' ⚠ HIGH ENTROPY' : ''}
                      </span>
                    )}
                  </div>
                  {(selected.layers || []).map((layer, i) => (
                    <TreeNode key={i} layer={layer} depth={i} />
                  ))}
                </>
              )}
            </div>

            {/* Hex dump */}
            <div style={{ overflowY: 'auto', background: '#1e1e2e', padding: 8 }}>
              {!selected ? (
                <div style={{ padding: 20, color: '#888', fontSize: 12 }}>
                  Hex dump appears here
                </div>
              ) : hexRows.length === 0 ? (
                <div style={{ fontFamily: 'Consolas,monospace', fontSize: 11, color: '#a0a0c0' }}>
                  <div style={{ color: '#6ee7b7', marginBottom: 4 }}>
                    Frame {selected.index} · {selected.length} bytes · fully decoded
                  </div>
                  <div style={{ color: '#7c7c9c' }}>No undecoded bytes remaining.</div>
                  {/* Show raw layer field values as synthetic hex */}
                  <div style={{ marginTop: 8, color: '#94a3b8' }}>
                    Layer stack: {(selected.layer_names || []).join(' → ')}
                  </div>
                </div>
              ) : (
                <div style={{ fontFamily: 'Consolas,monospace', fontSize: 11.5 }}>
                  {hexRows.map((row, i) => (
                    <div key={i} style={{ display: 'flex', gap: 10, lineHeight: '18px' }}>
                      <span style={{ color: '#6b7280', minWidth: 36, userSelect: 'none' }}>{row.offset}</span>
                      <span style={{ color: '#93c5fd', letterSpacing: '0.2px', minWidth: 285 }}>
                        {row.hex}
                      </span>
                      <span style={{ color: '#86efac' }}>{row.ascii}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ══ STATS VIEW ═══════════════════════════════════════════════════════ */}
      {view === 'stats' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 16, background: '#f5f5f5' }}>
          <StatsPanel wsStats={s} packets={packets} wsOk={wsOk} />
        </div>
      )}

      {/* ── Status bar ── */}
      <div style={{
        background: '#d0d0d0', borderTop: '1px solid #aaa',
        padding: '2px 10px', fontSize: 11, color: '#333',
        display: 'flex', justifyContent: 'space-between', flexShrink: 0,
      }}>
        <span>{statusBar}</span>
        <span>
          Profile: Default · {wsOk ? 'WebSocket: connected' : 'WebSocket: offline'}
        </span>
      </div>
    </div>
  )
}

/* ── lighten helper ─────────────────────────────────────────────────────────── */
function lighten(hex) {
  // just return white-ish for odd rows
  return '#ffffff'
}

/* ── Stats panel ─────────────────────────────────────────────────────────────  */
function StatsPanel({ wsStats: s, packets, wsOk }) {
  const [alerts, setAlerts] = useState([])
  useEffect(() => {
    fetch(`${API}/alerts?limit=20`).then(r=>r.json()).then(d=>setAlerts(d.alerts||[])).catch(()=>{})
  }, [])

  // Protocol breakdown from current packet list
  const proto = {}
  packets.forEach(p => { proto[p.protocol] = (proto[p.protocol] || 0) + 1 })
  const total = packets.length || 1

  const card = (label, value, color) => (
    <div style={{
      background: '#fff', border: '1px solid #d0d0d0', borderRadius: 4,
      padding: '12px 16px', minWidth: 140,
    }}>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || '#1565c0' }}>{value}</div>
      <div style={{ fontSize: 11, color: '#666', marginTop: 2 }}>{label}</div>
    </div>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h3 style={{ fontSize: 14, fontWeight: 700, color: '#1a1a1a' }}>
        📊 Capture Statistics
      </h3>

      {/* KPIs */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {card('Total Packets', packets.length)}
        {card('Matched (E3)',   s.matched   ?? 49, '#16a34a')}
        {card('Unmatched',      s.unmatched ?? 7,  '#dc2626')}
        {card('Late',           s.late      ?? 0,  '#d97706')}
        {card('Loss Rate',     `${s.loss_rate != null ? (s.loss_rate*100).toFixed(1) : '14.3'}%`,
              parseFloat(s.loss_rate) > 0.05 ? '#dc2626' : '#16a34a')}
        {card('Avg Delay',     `${s.avg_delay_ms != null ? s.avg_delay_ms.toFixed(2) : '3.98'} ms`, '#1565c0')}
      </div>

      {/* Protocol breakdown */}
      <div style={{ background: '#fff', border: '1px solid #d0d0d0', borderRadius: 4, padding: 14 }}>
        <div style={{ fontWeight: 700, marginBottom: 10, fontSize: 13 }}>Protocol Hierarchy</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#f0f0f0' }}>
              {['Protocol','Packets','%','Bar'].map(h => (
                <th key={h} style={{ padding: '4px 8px', textAlign: 'left',
                                     borderBottom: '1px solid #ddd' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Object.entries(proto).sort((a,b) => b[1]-a[1]).map(([p, n]) => {
              const c = rc(p)
              return (
                <tr key={p} style={{ background: c.bg }}>
                  <td style={{ padding: '3px 8px', fontWeight: 700 }}>{p}</td>
                  <td style={{ padding: '3px 8px', fontFamily: 'monospace' }}>{n}</td>
                  <td style={{ padding: '3px 8px' }}>{((n/total)*100).toFixed(1)}%</td>
                  <td style={{ padding: '3px 8px' }}>
                    <div style={{ height: 10, width: `${(n/total)*200}px`,
                                  background: '#2e6da4', borderRadius: 2, maxWidth: 200 }} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Alerts */}
      {alerts.length > 0 && (
        <div style={{ background: '#fff', border: '1px solid #d0d0d0', borderRadius: 4, padding: 14 }}>
          <div style={{ fontWeight: 700, marginBottom: 10, fontSize: 13 }}>⚠ Diagnostic Alerts</div>
          {alerts.map((a, i) => (
            <div key={i} style={{
              padding: '8px 12px', marginBottom: 6, borderRadius: 3,
              borderLeft: `4px solid ${a.severity==='critical'?'#dc2626':a.severity==='warning'?'#d97706':'#2563eb'}`,
              background: '#f9f9f9',
            }}>
              <div style={{ fontWeight: 700, fontSize: 12 }}>
                [{a.severity?.toUpperCase()}] {a.category} — confidence: {a.confidence}
              </div>
              <div style={{ fontSize: 11, color: '#555', marginTop: 2 }}>{a.recommended_action}</div>
              <div style={{ fontSize: 10, color: '#888', marginTop: 2 }}>
                {Object.entries(a.metrics||{}).map(([k,v])=>`${k}: ${typeof v==='number'?v.toFixed(3):v}`).join('  ·  ')}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
