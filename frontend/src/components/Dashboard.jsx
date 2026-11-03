import { useState, useEffect, useRef } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts'
import PacketInspector from './PacketInspector'
import { API, WS } from '../config.js'

const S = {
  page:    { maxWidth: 1280, margin: '0 auto', padding: '16px' },
  header:  { display:'flex', alignItems:'center', justifyContent:'space-between',
             marginBottom:20, borderBottom:'1px solid #30363d', paddingBottom:14 },
  title:   { fontSize:22, fontWeight:700, color:'#58a6ff' },
  badge:   (ok) => ({ padding:'3px 10px', borderRadius:20, fontSize:12, fontWeight:600,
                      background: ok?'#1a4731':'#4a1a1a', color: ok?'#3fb950':'#f85149' }),
  tabs:    { display:'flex', gap:2, marginBottom:16, borderBottom:'1px solid #30363d' },
  tab:     (a) => ({ padding:'8px 20px', cursor:'pointer', border:'none', borderRadius:'6px 6px 0 0',
                     fontWeight:600, fontSize:13,
                     background: a ? '#1f6feb' : 'transparent',
                     color: a ? '#fff' : '#8b949e',
                     borderBottom: a ? '2px solid #1f6feb' : '2px solid transparent' }),
  grid:    { display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))', gap:10, marginBottom:16 },
  card:    { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:'12px 14px' },
  kpi:     { fontSize:26, fontWeight:700, color:'#58a6ff' },
  kpiL:    { fontSize:11, color:'#8b949e', marginTop:2 },
  section: { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:14, marginBottom:14 },
  sTitle:  { fontSize:14, fontWeight:600, marginBottom:10, color:'#f0f6fc' },
  alert:   (sev) => ({ padding:'10px 14px', borderRadius:6, marginBottom:8,
                       borderLeft:'4px solid',
                       borderColor: sev==='critical'?'#f85149':sev==='warning'?'#d29922':'#388bfd',
                       background:  sev==='critical'?'#1a0a0a':sev==='warning'?'#1a1400':'#0d1a2d' }),
  table:   { width:'100%', borderCollapse:'collapse', fontSize:12 },
  th:      { textAlign:'left', padding:'5px 8px', borderBottom:'1px solid #30363d', color:'#8b949e', fontWeight:500 },
  td:      { padding:'5px 8px', borderBottom:'1px solid #21262d' },
  btn:     { padding:'7px 16px', borderRadius:6, border:'none', background:'#1f6feb',
             color:'#fff', cursor:'pointer', fontWeight:600, fontSize:13 },
  btnG:    { padding:'7px 16px', borderRadius:6, border:'none', background:'#21262d',
             color:'#e6edf3', cursor:'pointer', fontWeight:600, fontSize:13 },
  input:   { flex:1, padding:'7px 10px', borderRadius:6, border:'1px solid #30363d',
             background:'#0d1117', color:'#e6edf3', fontSize:13 },
  tag:     (c) => {
    const m = { tcp:'#0550ae', udp:'#116329', dns:'#7d4e00', http:'#6e1a0d',
                icmp:'#5a1a8a', arp:'#7d3c00' }
    const bg = { tcp:'#d0e8ff', udp:'#dafbe1', dns:'#fff3cd', http:'#ffd7d5',
                 icmp:'#e8d5ff', arp:'#ffe8cc' }
    const k = c?.toLowerCase()
    return { padding:'2px 8px', borderRadius:12, fontSize:11, fontWeight:600,
             background: bg[k]||'#e8e8e8', color: m[k]||'#333' }
  },
}

function KPI({ label, value, color }) {
  return (
    <div style={S.card}>
      <div style={{ ...S.kpi, color: color||'#58a6ff' }}>{value}</div>
      <div style={S.kpiL}>{label}</div>
    </div>
  )
}

function AlertCard({ alert }) {
  return (
    <div style={S.alert(alert.severity)}>
      <div style={{ fontWeight:600, fontSize:13 }}>
        {alert.category} · {alert.severity?.toUpperCase()} · confidence: {alert.confidence}
      </div>
      <div style={{ fontSize:12, color:'#8b949e', marginTop:4 }}>{alert.recommended_action}</div>
      {alert.metrics && (
        <div style={{ fontSize:11, color:'#6e7681', marginTop:3 }}>
          {Object.entries(alert.metrics).map(([k,v])=>`${k}: ${typeof v==='number'?v.toFixed(4):v}`).join('  ·  ')}
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const [tab,     setTab]     = useState('overview')   // 'overview' | 'inspector' | 'alerts'
  const [wsOk,    setWsOk]    = useState(false)
  const [stats,   setStats]   = useState(null)
  const [alerts,  setAlerts]  = useState([])
  const [latency, setLatency] = useState([])
  const [captures,setCaps]    = useState([])
  const [flows,   setFlows]   = useState([])
  const [selCap,  setSelCap]  = useState(null)
  const [filter,  setFilter]  = useState('')
  const [uploading,  setUploading]   = useState(false)
  const [liveCapturing, setLiveCapturing] = useState(false)
  const [liveResult, setLiveResult]  = useState(null)
  const wsRef  = useRef(null)
  const tickRef = useRef(0)

  // ── WebSocket ──────────────────────────────────────────────────────────────
  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS)
      wsRef.current = ws
      ws.onopen  = () => setWsOk(true)
      ws.onclose = () => { setWsOk(false); setTimeout(connect, 2000) }
      ws.onerror = () => ws.close()
      ws.onmessage = ({ data }) => {
        try {
          const msg = JSON.parse(data)
          if (msg.type === 'metrics') {
            setStats(msg.stats)
            setAlerts(msg.recent_alerts || [])
          }
          if (msg.type === 'correlation' && msg.delay_ms != null) {
            tickRef.current += 1
            setLatency(prev => [...prev, { t: tickRef.current, delay_ms: msg.delay_ms }].slice(-60))
          }
        } catch {}
      }
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  // ── load captures ──────────────────────────────────────────────────────────
  const loadCaptures = () =>
    fetch(`${API}/captures`).then(r=>r.json()).then(setCaps).catch(()=>{})

  useEffect(() => { loadCaptures() }, [])

  // ── load flows ─────────────────────────────────────────────────────────────
  const loadFlows = (cid, filt) => {
    const body = { capture_id: cid, filter: filt || '' }
    fetch(`${API}/query`, { method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) })
      .then(r=>r.json()).then(d=>setFlows(d.flows||[])).catch(()=>{})
  }

  // ── upload PCAP ────────────────────────────────────────────────────────────
  const handleUpload = async (e) => {
    const file = e.target.files[0]; if (!file) return
    setUploading(true)
    const fd = new FormData(); fd.append('file', file)
    try {
      const res  = await fetch(`${API}/captures`, { method:'POST', body:fd })
      const data = await res.json()
      loadCaptures()
      setSelCap(data.capture_id)
      loadFlows(data.capture_id, '')
      if (data.alerts?.length) setAlerts(prev => [...data.alerts, ...prev])
      setTab('inspector')   // jump straight to inspector after upload
    } catch {}
    setUploading(false)
  }

  // ── live capture ───────────────────────────────────────────────────────────
  const handleLiveCapture = async () => {
    setLiveCapturing(true); setLiveResult(null)
    try {
      const res  = await fetch(`${API}/captures/live?timeout=20&persist=true`)
      const data = await res.json()
      setLiveResult(data)
      loadCaptures()
      if (data.capture_id) {
        setSelCap(data.capture_id)
        loadFlows(data.capture_id, '')
        setTab('inspector')   // jump to inspector after live capture
      }
      if (data.alerts?.length) setAlerts(prev => [...data.alerts, ...prev])
    } catch (e) { setLiveResult({ error: String(e) }) }
    setLiveCapturing(false)
  }

  const s = stats || {}
  const lossRate = s.loss_rate != null ? (s.loss_rate * 100).toFixed(1) : '—'
  const avgDelay = s.avg_delay_ms != null ? s.avg_delay_ms.toFixed(2) : '—'
  const networkStatus = s.loss_rate > 0.2 ? 'CRITICAL' : s.loss_rate > 0.05 ? 'WARNING' : 'NORMAL'
  const statusColor = networkStatus==='CRITICAL'?'#f85149':networkStatus==='WARNING'?'#e3b341':'#3fb950'

  return (
    <div style={{ background:'#0d1117', minHeight:'100vh', color:'#e6edf3' }}>
      <div style={S.page}>

        {/* ── Header ── */}
        <div style={S.header}>
          <div>
            <div style={S.title}>🦈 Mini-Shark</div>
            <div style={{ fontSize:11, color:'#8b949e', marginTop:2 }}>
              Distributed Multi-Point Latency &amp; Packet Loss Tracing · Team 07
            </div>
          </div>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <span style={S.badge(wsOk)}>{wsOk ? '● LIVE' : '○ OFFLINE'}</span>
            <span style={{ padding:'3px 10px', borderRadius:20, fontSize:12, fontWeight:600,
                           background:'#161b22', color: statusColor, border:`1px solid ${statusColor}` }}>
              {networkStatus}
            </span>
          </div>
        </div>

        {/* ── Capture controls (always visible) ── */}
        <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:16, flexWrap:'wrap' }}>
          <label style={{ ...S.btn, display:'inline-block' }}>
            {uploading ? 'Uploading...' : '📁 Upload PCAP'}
            <input type="file" accept=".pcap,.pcapng" onChange={handleUpload}
                   style={{ display:'none' }} disabled={uploading} />
          </label>
          <button style={S.btn} onClick={handleLiveCapture} disabled={liveCapturing}>
            {liveCapturing ? '🔴 Capturing...' : '📡 Quick Capture (20s)'}
          </button>
          {liveResult && !liveResult.error && (
            <span style={{ fontSize:12, color:'#3fb950' }}>
              ✓ {liveResult.packets_captured} packets · {liveResult.flows} flows
              {liveResult.alerts?.length > 0 && ` · ${liveResult.alerts.length} alerts`}
            </span>
          )}
          {liveResult?.error && (
            <span style={{ fontSize:12, color:'#f85149' }}>Error: {liveResult.error}</span>
          )}
          {/* Capture selector */}
          {captures.length > 0 && (
            <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginLeft:8 }}>
              {captures.map(c => (
                <button key={c.id}
                  onClick={() => { setSelCap(c.id); loadFlows(c.id,'') }}
                  style={{ ...S.btnG,
                    border:`1px solid ${selCap===c.id?'#58a6ff':'#30363d'}`,
                    color: selCap===c.id?'#58a6ff':'#8b949e', fontSize:12, padding:'5px 12px' }}>
                  #{c.id} {c.name} ({c.packet_count})
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Tabs ── */}
        <div style={S.tabs}>
          {[['overview','📊 Overview'],['inspector','🔬 Packet Inspector'],['alerts','⚠ Alerts']].map(([id,label])=>(
            <button key={id} style={S.tab(tab===id)} onClick={()=>setTab(id)}>{label}</button>
          ))}
        </div>

        {/* ══════════════ OVERVIEW TAB ══════════════ */}
        {tab === 'overview' && (
          <>
            {/* KPIs */}
            <div style={S.grid}>
              <KPI label="Total Records"  value={s.total_records??0} />
              <KPI label="Matched"        value={s.matched??0}        color="#3fb950" />
              <KPI label="Unmatched"      value={s.unmatched??0}      color="#f85149" />
              <KPI label="Late"           value={s.late??0}           color="#e3b341" />
              <KPI label="Loss Rate"      value={`${lossRate}%`}      color={parseFloat(lossRate)>5?'#f85149':'#3fb950'} />
              <KPI label="Avg Delay"      value={`${avgDelay} ms`}    color="#79c0ff" />
            </div>

            {/* Charts */}
            <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:12, marginBottom:14 }}>
              <div style={S.section}>
                <div style={S.sTitle}>Live Latency — ΔT = T₂ − T₁</div>
                {latency.length === 0
                  ? <div style={{ color:'#8b949e', fontSize:13 }}>No matched packets yet...</div>
                  : <ResponsiveContainer width="100%" height={180}>
                      <LineChart data={latency}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                        <XAxis dataKey="t" hide />
                        <YAxis stroke="#8b949e" fontSize={10} unit=" ms" />
                        <Tooltip contentStyle={{ background:'#161b22', border:'1px solid #30363d', fontSize:11 }}
                                 formatter={v=>[`${v.toFixed(2)} ms`,'Delay']} />
                        <Line type="monotone" dataKey="delay_ms" stroke="#58a6ff" dot={false} strokeWidth={2} />
                      </LineChart>
                    </ResponsiveContainer>
                }
              </div>
              <div style={S.section}>
                <div style={S.sTitle}>Packet States</div>
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={[{ name:'', Matched:s.matched??0, Unmatched:s.unmatched??0, Late:s.late??0 }]}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                    <YAxis stroke="#8b949e" fontSize={10} />
                    <Tooltip contentStyle={{ background:'#161b22', border:'1px solid #30363d', fontSize:11 }} />
                    <Legend wrapperStyle={{ fontSize:11 }} />
                    <Bar dataKey="Matched"   fill="#3fb950" radius={[3,3,0,0]} />
                    <Bar dataKey="Unmatched" fill="#f85149" radius={[3,3,0,0]} />
                    <Bar dataKey="Late"      fill="#e3b341" radius={[3,3,0,0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Flow table */}
            {selCap && (
              <div style={S.section}>
                <div style={S.sTitle}>Flow Explorer — Capture #{selCap}</div>
                <div style={{ display:'flex', gap:8, marginBottom:10 }}>
                  <input style={S.input}
                    placeholder='Filter: protocol == "TCP"  or  tcp.port == 443'
                    value={filter} onChange={e=>setFilter(e.target.value)}
                    onKeyDown={e=>e.key==='Enter'&&loadFlows(selCap,filter)} />
                  <button style={S.btn} onClick={()=>loadFlows(selCap,filter)}>Search</button>
                  <button style={S.btnG} onClick={()=>{setFilter('');loadFlows(selCap,'')}}>Clear</button>
                </div>
                <table style={S.table}>
                  <thead>
                    <tr>{['Flow','Protocol','Source IP:Port','Dest IP:Port','Packets','Bytes','Duration'].map(h=>(
                      <th key={h} style={S.th}>{h}</th>))}
                    </tr>
                  </thead>
                  <tbody>
                    {flows.slice(0,100).map(f=>(
                      <tr key={f.flow_id}
                        style={{ cursor:'pointer' }}
                        onClick={()=>setTab('inspector')}>
                        <td style={S.td}>#{f.flow_id}</td>
                        <td style={S.td}><span style={S.tag(f.five_tuple.protocol)}>{f.five_tuple.protocol}</span></td>
                        <td style={S.td}>{f.five_tuple.src_ip}:{f.five_tuple.src_port}</td>
                        <td style={S.td}>{f.five_tuple.dst_ip}:{f.five_tuple.dst_port}</td>
                        <td style={S.td}>{f.packet_count}</td>
                        <td style={S.td}>{f.byte_count}</td>
                        <td style={S.td}>{f.duration?.toFixed(3)}s</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {flows.length===0 && <div style={{color:'#8b949e',fontSize:12,marginTop:8}}>No flows</div>}
              </div>
            )}
          </>
        )}

        {/* ══════════════ PACKET INSPECTOR TAB ══════════════ */}
        {tab === 'inspector' && (
          <div style={S.section}>
            <div style={S.sTitle}>
              🔬 Packet Inspector
              {selCap && <span style={{ fontWeight:400, color:'#8b949e', fontSize:12, marginLeft:8 }}>
                — Capture #{selCap}
              </span>}
            </div>
            <PacketInspector captureId={selCap} />
          </div>
        )}

        {/* ══════════════ ALERTS TAB ══════════════ */}
        {tab === 'alerts' && (
          <div style={S.section}>
            <div style={S.sTitle}>⚠ Diagnostic Alerts</div>
            {alerts.length === 0
              ? <div style={{ color:'#8b949e', fontSize:13 }}>No alerts yet</div>
              : alerts.map((a,i) => <AlertCard key={i} alert={a} />)
            }
            {/* load all stored alerts */}
            <StoredAlerts />
          </div>
        )}

        <div style={{ fontSize:10, color:'#6e7681', textAlign:'center', marginTop:12 }}>
          Mini-Shark v0.4 · Team 07 · KLE Technological University
        </div>
      </div>
    </div>
  )
}

// ── stored alerts from DB ─────────────────────────────────────────────────────
function StoredAlerts() {
  const [stored, setStored] = useState([])
  useEffect(() => {
    fetch(`${API}/alerts?limit=20`)
      .then(r=>r.json()).then(d=>setStored(d.alerts||[])).catch(()=>{})
  }, [])

  if (stored.length === 0) return null
  return (
    <>
      <div style={{ fontSize:13, fontWeight:600, color:'#8b949e', marginTop:16, marginBottom:8 }}>
        Stored in database ({stored.length}):
      </div>
      {stored.map((a,i) => (
        <div key={i} style={{
          padding:'10px 14px', borderRadius:6, marginBottom:8,
          borderLeft:`4px solid ${a.severity==='critical'?'#f85149':a.severity==='warning'?'#d29922':'#388bfd'}`,
          background:'#161b22'
        }}>
          <div style={{ fontWeight:600, fontSize:13 }}>
            {a.category} · {a.severity?.toUpperCase()} · confidence: {a.confidence}
          </div>
          <div style={{ fontSize:12, color:'#8b949e', marginTop:4 }}>{a.recommended_action}</div>
          <div style={{ fontSize:11, color:'#6e7681', marginTop:3 }}>
            {Object.entries(a.metrics||{}).map(([k,v])=>`${k}: ${typeof v==='number'?v.toFixed(4):v}`).join('  ·  ')}
          </div>
        </div>
      ))}
    </>
  )
}
