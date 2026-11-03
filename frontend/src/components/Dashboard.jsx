import { useState, useEffect, useRef } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts'

const API = 'http://127.0.0.1:3000'
const WS  = 'ws://127.0.0.1:3000/ws/live'

const S = {
  page:  { maxWidth: 1200, margin: '0 auto', padding: '20px 16px' },
  header:{ display:'flex', alignItems:'center', justifyContent:'space-between',
           marginBottom: 24, borderBottom:'1px solid #30363d', paddingBottom:16 },
  title: { fontSize: 22, fontWeight: 700, color:'#58a6ff' },
  badge: (ok) => ({ padding:'3px 10px', borderRadius:20, fontSize:12, fontWeight:600,
                    background: ok ? '#1a4731':'#4a1a1a', color: ok ? '#3fb950':'#f85149' }),
  grid:  { display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))', gap:12, marginBottom:20 },
  card:  { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px' },
  kpi:   { fontSize:28, fontWeight:700, color:'#58a6ff' },
  kpiL:  { fontSize:12, color:'#8b949e', marginTop:2 },
  section:{ background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:16, marginBottom:16 },
  sTitle:{ fontSize:15, fontWeight:600, marginBottom:12, color:'#f0f6fc' },
  alert: (sev) => ({ padding:'10px 14px', borderRadius:6, marginBottom:8,
                     borderLeft:'4px solid',
                     borderColor: sev==='critical'?'#f85149': sev==='warning'?'#d29922':'#388bfd',
                     background: sev==='critical'?'#1a0a0a': sev==='warning'?'#1a1400':'#0d1a2d' }),
  alertTitle: { fontWeight:600, fontSize:13 },
  alertBody:  { fontSize:12, color:'#8b949e', marginTop:4 },
  table: { width:'100%', borderCollapse:'collapse', fontSize:13 },
  th:    { textAlign:'left', padding:'6px 8px', borderBottom:'1px solid #30363d', color:'#8b949e', fontWeight:500 },
  td:    { padding:'6px 8px', borderBottom:'1px solid #21262d' },
  upload:{ display:'flex', gap:10, alignItems:'center', marginBottom:16 },
  btn:   { padding:'7px 16px', borderRadius:6, border:'none', background:'#1f6feb',
           color:'#fff', cursor:'pointer', fontWeight:600, fontSize:13 },
  btnG:  { padding:'7px 16px', borderRadius:6, border:'none', background:'#21262d',
           color:'#e6edf3', cursor:'pointer', fontWeight:600, fontSize:13 },
  input: { flex:1, padding:'7px 10px', borderRadius:6, border:'1px solid #30363d',
           background:'#0d1117', color:'#e6edf3', fontSize:13 },
  tag:   (c) => ({ padding:'2px 8px', borderRadius:12, fontSize:11, fontWeight:600,
                   background: c==='matched'?'#1a4731': c==='unmatched'?'#4a1a1a': c==='late'?'#3a2a00':'#1a1a3a',
                   color: c==='matched'?'#3fb950': c==='unmatched'?'#f85149': c==='late'?'#e3b341':'#79c0ff' }),
}

// ── helpers ──────────────────────────────────────────────────────────────────

const fmt_ts = ns => ns ? new Date(ns / 1e6).toLocaleTimeString() : '—'
const fmt_ms = ns => ns != null ? (ns / 1e6).toFixed(2) + ' ms' : '—'

// ── sub-components ────────────────────────────────────────────────────────────

function KPI({ label, value, color }) {
  return (
    <div style={S.card}>
      <div style={{ ...S.kpi, color: color || '#58a6ff' }}>{value}</div>
      <div style={S.kpiL}>{label}</div>
    </div>
  )
}

function AlertCard({ alert }) {
  return (
    <div style={S.alert(alert.severity)}>
      <div style={S.alertTitle}>{alert.category} · {alert.severity.toUpperCase()} · confidence: {alert.confidence}</div>
      <div style={S.alertBody}>{alert.recommended_action}</div>
      {alert.metrics && (
        <div style={{ fontSize:11, color:'#6e7681', marginTop:4 }}>
          {Object.entries(alert.metrics).map(([k,v]) => `${k}: ${typeof v==='number'?v.toFixed(4):v}`).join('  ·  ')}
        </div>
      )}
    </div>
  )
}

// ── main dashboard ────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [wsOk,    setWsOk]    = useState(false)
  const [stats,   setStats]   = useState(null)
  const [alerts,  setAlerts]  = useState([])
  const [latency, setLatency] = useState([])   // [{t, delay_ms}]
  const [correlations, setCorr] = useState([])
  const [captures, setCaps]   = useState([])
  const [flows,    setFlows]  = useState([])
  const [selCap,   setSelCap] = useState(null)
  const [filter,   setFilter] = useState('')
  const [uploading,setUploading]=useState(false)
  const [liveCapturing,setLiveCapturing]=useState(false)
  const [liveResult, setLiveResult]=useState(null)
  const wsRef = useRef(null)
  const tickRef = useRef(0)

  // ── WebSocket ──────────────────────────────────────────────────────────
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
            setLatency(prev => {
              const next = [...prev, { t: tickRef.current, delay_ms: msg.delay_ms }]
              return next.slice(-60)   // keep last 60 points
            })
          }
          if (msg.type === 'correlation') {
            setCorr(prev => [msg, ...prev].slice(0,50))
          }
        } catch {}
      }
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  // ── load captures list ─────────────────────────────────────────────────
  const loadCaptures = () =>
    fetch(`${API}/captures`).then(r=>r.json()).then(setCaps).catch(()=>{})

  useEffect(() => { loadCaptures() }, [])

  // ── upload PCAP ────────────────────────────────────────────────────────
  const handleUpload = async (e) => {
    const file = e.target.files[0]; if (!file) return
    setUploading(true)
    const fd = new FormData(); fd.append('file', file)
    try {
      const res = await fetch(`${API}/captures`, { method:'POST', body:fd })
      const data = await res.json()
      loadCaptures()
      setSelCap(data.capture_id)
      loadFlows(data.capture_id, filter)
      if (data.alerts?.length) setAlerts(prev => [...data.alerts, ...prev])
    } catch {}
    setUploading(false)
  }

  // ── load flows ─────────────────────────────────────────────────────────
  const loadFlows = (cid, filt) => {
    const body = { capture_id: cid, filter: filt || '' }
    fetch(`${API}/query`, { method:'POST', headers:{'Content-Type':'application/json'},
                             body: JSON.stringify(body) })
      .then(r=>r.json()).then(d=>setFlows(d.flows||[])).catch(()=>{})
  }

  // ── live capture ───────────────────────────────────────────────────────
  const handleLiveCapture = async () => {
    setLiveCapturing(true); setLiveResult(null)
    try {
      const res = await fetch(`${API}/captures/live?count=30&timeout=20&persist=true`)
      const data = await res.json()
      setLiveResult(data)
      loadCaptures()
      if (data.capture_id) { setSelCap(data.capture_id); loadFlows(data.capture_id,'') }
      if (data.alerts?.length) setAlerts(prev => [...data.alerts, ...prev])
    } catch (e) { setLiveResult({ error: String(e) }) }
    setLiveCapturing(false)
  }

  const s = stats || {}
  const lossRate = s.loss_rate != null ? (s.loss_rate * 100).toFixed(1) : '—'
  const avgDelay = s.avg_delay_ms != null ? s.avg_delay_ms.toFixed(2) : '—'
  const networkStatus = s.loss_rate > 0.2 ? 'CRITICAL' : s.loss_rate > 0.05 ? 'WARNING' : 'NORMAL'

  return (
    <div style={S.page}>
      {/* ── Header ── */}
      <div style={S.header}>
        <div>
          <div style={S.title}>🦈 Mini-Shark</div>
          <div style={{ fontSize:12, color:'#8b949e', marginTop:2 }}>
            Distributed Multi-Point Latency &amp; Packet Loss Tracing
          </div>
        </div>
        <div style={{ display:'flex', gap:10, alignItems:'center' }}>
          <span style={S.badge(wsOk)}>{wsOk ? '● LIVE' : '○ OFFLINE'}</span>
          <span style={{ ...S.badge(networkStatus==='NORMAL'), fontSize:11 }}>
            Network: {networkStatus}
          </span>
        </div>
      </div>

      {/* ── KPI row ── */}
      <div style={S.grid}>
        <KPI label="Total Packets" value={s.total_records ?? 0} />
        <KPI label="Matched"       value={s.matched ?? 0}       color="#3fb950" />
        <KPI label="Unmatched"     value={s.unmatched ?? 0}     color="#f85149" />
        <KPI label="Late"          value={s.late ?? 0}          color="#e3b341" />
        <KPI label="Loss Rate"     value={`${lossRate}%`}       color={parseFloat(lossRate)>5?'#f85149':'#3fb950'} />
        <KPI label="Avg Delay"     value={`${avgDelay} ms`}     color="#79c0ff" />
      </div>

      {/* ── Latency chart + Protocol bar ── */}
      <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:12, marginBottom:16 }}>
        <div style={S.section}>
          <div style={S.sTitle}>Live Latency — ΔT = T₂ − T₁ (ms)</div>
          {latency.length === 0
            ? <div style={{ color:'#8b949e', fontSize:13 }}>Waiting for matched packets...</div>
            : <ResponsiveContainer width="100%" height={200}>
                <LineChart data={latency}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                  <XAxis dataKey="t" hide />
                  <YAxis stroke="#8b949e" fontSize={11} unit=" ms" />
                  <Tooltip
                    contentStyle={{ background:'#161b22', border:'1px solid #30363d', fontSize:12 }}
                    formatter={v => [`${v.toFixed(2)} ms`, 'Delay']} />
                  <Line type="monotone" dataKey="delay_ms" stroke="#58a6ff"
                        dot={false} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
          }
        </div>

        <div style={S.section}>
          <div style={S.sTitle}>Packet States</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[{
              name:'Status',
              Matched:  s.matched   ?? 0,
              Unmatched:s.unmatched ?? 0,
              Late:     s.late      ?? 0,
            }]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis dataKey="name" stroke="#8b949e" fontSize={11} />
              <YAxis stroke="#8b949e" fontSize={11} />
              <Tooltip contentStyle={{ background:'#161b22', border:'1px solid #30363d', fontSize:12 }} />
              <Legend wrapperStyle={{ fontSize:12 }} />
              <Bar dataKey="Matched"   fill="#3fb950" radius={[3,3,0,0]} />
              <Bar dataKey="Unmatched" fill="#f85149" radius={[3,3,0,0]} />
              <Bar dataKey="Late"      fill="#e3b341" radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Alerts ── */}
      {alerts.length > 0 && (
        <div style={S.section}>
          <div style={S.sTitle}>⚠ Diagnostic Alerts</div>
          {alerts.slice(0,5).map((a,i) => <AlertCard key={i} alert={a} />)}
        </div>
      )}

      {/* ── Upload + Live Capture controls ── */}
      <div style={S.section}>
        <div style={S.sTitle}>Packet Capture</div>
        <div style={S.upload}>
          <label style={{ ...S.btn, display:'inline-block' }}>
            {uploading ? 'Uploading...' : '📁 Upload PCAP'}
            <input type="file" accept=".pcap,.pcapng" onChange={handleUpload}
                   style={{ display:'none' }} disabled={uploading} />
          </label>
          <button style={S.btn} onClick={handleLiveCapture} disabled={liveCapturing}>
            {liveCapturing ? '🔴 Capturing...' : '📡 Live Capture (30 pkts)'}
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
        </div>

        {/* Captures list */}
        {captures.length > 0 && (
          <div>
            <div style={{ fontSize:13, color:'#8b949e', marginBottom:6 }}>Stored captures:</div>
            <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
              {captures.map(c => (
                <button key={c.id}
                  style={{ ...S.btnG, borderColor: selCap===c.id?'#58a6ff':'transparent',
                           border:`1px solid ${selCap===c.id?'#58a6ff':'#30363d'}` }}
                  onClick={() => { setSelCap(c.id); loadFlows(c.id, filter) }}>
                  #{c.id} {c.name} ({c.packet_count} pkts)
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Flow query ── */}
      {selCap && (
        <div style={S.section}>
          <div style={S.sTitle}>Flow Explorer — Capture #{selCap}</div>
          <div style={{ display:'flex', gap:8, marginBottom:12 }}>
            <input style={S.input} placeholder='Filter: protocol == "TCP"  or  tcp.port == 443'
                   value={filter} onChange={e=>setFilter(e.target.value)}
                   onKeyDown={e=>e.key==='Enter'&&loadFlows(selCap,filter)} />
            <button style={S.btn} onClick={()=>loadFlows(selCap,filter)}>Search</button>
            <button style={S.btnG} onClick={()=>{setFilter('');loadFlows(selCap,'')}}>Clear</button>
          </div>
          <table style={S.table}>
            <thead>
              <tr>{['Flow','Protocol','Src IP:Port','Dst IP:Port','Packets','Bytes','Duration'].map(h=>(
                <th key={h} style={S.th}>{h}</th>))}
              </tr>
            </thead>
            <tbody>
              {flows.slice(0,100).map(f=>(
                <tr key={f.flow_id}>
                  <td style={S.td}>#{f.flow_id}</td>
                  <td style={S.td}><span style={S.tag(f.five_tuple.protocol.toLowerCase())}>{f.five_tuple.protocol}</span></td>
                  <td style={S.td}>{f.five_tuple.src_ip}:{f.five_tuple.src_port}</td>
                  <td style={S.td}>{f.five_tuple.dst_ip}:{f.five_tuple.dst_port}</td>
                  <td style={S.td}>{f.packet_count}</td>
                  <td style={S.td}>{f.byte_count}</td>
                  <td style={S.td}>{f.duration?.toFixed(3)}s</td>
                </tr>
              ))}
            </tbody>
          </table>
          {flows.length === 0 && <div style={{color:'#8b949e',fontSize:13,marginTop:8}}>No flows found</div>}
        </div>
      )}

      {/* ── Recent correlations ── */}
      {correlations.length > 0 && (
        <div style={S.section}>
          <div style={S.sTitle}>Recent Correlations (live)</div>
          <table style={S.table}>
            <thead>
              <tr>{['Fingerprint','State','Delay'].map(h=><th key={h} style={S.th}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {correlations.slice(0,20).map((r,i)=>(
                <tr key={i}>
                  <td style={{...S.td,fontFamily:'monospace',fontSize:12}}>{r.fingerprint}</td>
                  <td style={S.td}><span style={S.tag(r.match_state)}>{r.match_state}</span></td>
                  <td style={S.td}>{r.delay_ms!=null ? `${r.delay_ms.toFixed(2)} ms` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ fontSize:11, color:'#6e7681', textAlign:'center', marginTop:16 }}>
        Mini-Shark v0.4 · Team 07 · KLE Technological University · API: {API}
      </div>
    </div>
  )
}
