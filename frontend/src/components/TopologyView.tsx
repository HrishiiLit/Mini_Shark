import { Canvas, useFrame } from '@react-three/fiber'
import { ContactShadows, Environment, Grid, Html, OrbitControls, useCursor } from '@react-three/drei'
import { useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import type { Flight } from '../types'
import { curveOut, getClientCurve, getClientPosition, pathPoint, ROUTER_POS, SERVER_POS } from '../lib/topology'
import { useCaptureStore } from '../store/useCaptureStore'
import { SimulationBar } from './SimulationBar'

export function TopologyView() {
  return (
    <div className="relative h-full min-h-0 overflow-hidden bg-[#F8FAFC]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-white to-transparent" />
      <SimulationBar />
      <ClientsHUD />
      <Canvas className="h-full w-full" camera={{ position: [0.4, 2.7, 7.2], fov: 38 }} dpr={[1, 1.75]} gl={{ antialias: true }}>
        <color attach="background" args={['#F8FAFC']} />
        <fog attach="fog" args={['#F8FAFC', 14, 28]} />
        <hemisphereLight args={['#ffffff', '#e2e8f0', 0.85]} />
        <directionalLight position={[7, 10, 6]} intensity={1.45} color="#ffffff" />
        <directionalLight position={[-8, 3, -5]} intensity={0.35} color="#38BDF8" />
        <Environment preset="studio" />
        <Scene />
        <ContactShadows position={[0, -0.01, 0]} opacity={0.16} scale={20} blur={2.4} far={5} />
        <Grid
          position={[0, 0, 0]}
          args={[24, 24]}
          cellSize={0.55}
          cellThickness={0.55}
          cellColor="#D8E0EA"
          sectionSize={2.75}
          sectionThickness={1.15}
          sectionColor="#94A3B8"
          fadeDistance={16}
          fadeStrength={1.35}
        />
        <OrbitControls
          enablePan={false}
          minDistance={4.2}
          maxDistance={12}
          maxPolarAngle={Math.PI / 2.12}
          target={[0, 0.42, 0]}
          makeDefault
        />
        <FpsMeter />
      </Canvas>
      <Legend />
    </div>
  )
}

function Scene() {
  const flights = useCaptureStore((s) => s.flights)
  const running = useCaptureStore((s) => s.running)
  const serverRipple = useCaptureStore((s) => s.serverRipple)
  const clientCount = useCaptureStore((s) => s.clientCount)
  const clients = useCaptureStore((s) => s.clients)
  const setFilter = useCaptureStore((s) => s.setFilter)
  const probes = useCaptureStore((s) => s.probesStatus)
  const demoMode = useCaptureStore((s) => s.demoMode)

  const p1Connected = probes.probe1_connected || demoMode
  const p2Connected = probes.probe2_connected || demoMode

  const activeClients = useMemo(() => {
    if (demoMode || probes.probe1_connected) {
      return clients.slice(0, Math.max(1, clientCount))
    }
    return []
  }, [demoMode, clientCount, clients, probes.probe1_connected])

  const effectiveClientCount = Math.max(1, activeClients.length)
  const clientCurves = useMemo(
    () => activeClients.map((_, i) => getClientCurve(i, effectiveClientCount)),
    [activeClients, effectiveClientCount],
  )

  const standbyClientCurve = useMemo(() => getClientCurve(0, 1), [])

  return (
    <group>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.012, 0]} receiveShadow>
        <circleGeometry args={[7.8, 64]} />
        <meshStandardMaterial color="#ffffff" roughness={0.92} metalness={0.04} />
      </mesh>

      {/* Ingress Cables */}
      {p1OnlineCables(p1Connected, clientCurves, standbyClientCurve)}

      {/* Egress Cable to Server */}
      <Cable curve={curveOut} color={p2Connected ? '#059669' : '#CBD5E1'} standby={!p2Connected} />

      {/* Idle pulses for each active client link */}
      {p1Connected &&
        activeClients.map((_, i) => (
          <IdlePulses
            key={`pulse-${i}-${effectiveClientCount}`}
            active={running}
            clientIndex={i}
            totalClients={effectiveClientCount}
          />
        ))}

      {/* Client Nodes: either active live/demo clients OR standby waiting placeholder */}
      {p1Connected ? (
        activeClients.map((c, i) => (
          <ProbeNode
            key={`client-node-${c.id}-${effectiveClientCount}`}
            position={getClientPosition(i, effectiveClientCount)}
            color="#2563EB"
            title={c.name}
            subtitle={c.ip}
            badge={`${c.vm} · Ingress`}
            tone="blue"
            onClick={() => setFilter(`ip.src == ${c.ip}`)}
          />
        ))
      ) : (
        <ProbeNode
          position={getClientPosition(0, 1)}
          color="#94A3B8"
          title="Awaiting Linux Probe"
          subtitle="Disconnected · Waiting on :9000"
          badge="Probe 1 · Standby (VM2)"
          tone="slate"
          onClick={() => setFilter('')}
        />
      )}

      {/* Central Correlation Router Node (always online in hub process) */}
      <RouterNode onResetFilter={() => setFilter('')} />

      {/* Egress Server Node: active or standby */}
      {p2Connected ? (
        <ProbeNode
          position={SERVER_POS}
          color="#059669"
          title="Server Node (VM1)"
          subtitle={probes.probe2_ip && probes.probe2_ip !== '127.0.0.1' ? probes.probe2_ip : '192.168.130.129'}
          badge="Probe 2 · Egress · LIVE"
          tone="green"
          rippleKey={serverRipple}
          onClick={() => setFilter(`ip.dst == ${probes.probe2_ip && probes.probe2_ip !== '127.0.0.1' ? probes.probe2_ip : '192.168.130.129'}`)}
        />
      ) : (
        <ProbeNode
          position={SERVER_POS}
          color="#94A3B8"
          title="Awaiting Server Probe"
          subtitle="Disconnected · Waiting on :9000"
          badge="Probe 2 · Standby (VM1)"
          tone="slate"
          onClick={() => setFilter('')}
        />
      )}

      {/* Animated Packet Particle Flights */}
      {flights.map((f) => (
        <PacketParticle key={f.id} flight={f} totalClients={effectiveClientCount} />
      ))}
    </group>
  )
}

function p1OnlineCables(
  p1Connected: boolean,
  clientCurves: THREE.QuadraticBezierCurve3[],
  standbyCurve: THREE.QuadraticBezierCurve3,
) {
  if (p1Connected && clientCurves.length > 0) {
    return clientCurves.map((curve, i) => <Cable key={`cable-in-${i}`} curve={curve} color="#2563EB" />)
  }
  return <Cable curve={standbyCurve} color="#CBD5E1" standby />
}

function Cable({
  curve,
  color,
  standby = false,
}: {
  curve: THREE.QuadraticBezierCurve3
  color: string
  standby?: boolean
}) {
  const core = useMemo(() => new THREE.TubeGeometry(curve, 96, standby ? 0.024 : 0.046, 18, false), [curve, standby])
  const glow = useMemo(() => new THREE.TubeGeometry(curve, 96, standby ? 0.04 : 0.11, 18, false), [curve, standby])
  return (
    <group>
      <mesh geometry={core}>
        <meshStandardMaterial
          color={color}
          metalness={standby ? 0.05 : 0.42}
          roughness={standby ? 0.8 : 0.18}
          transparent={standby}
          opacity={standby ? 0.45 : 1}
        />
      </mesh>
      {!standby && (
        <mesh geometry={glow}>
          <meshBasicMaterial color={color} transparent opacity={0.16} />
        </mesh>
      )}
    </group>
  )
}

function IdlePulses({
  active,
  clientIndex = 0,
  totalClients = 1,
}: {
  active: boolean
  clientIndex?: number
  totalClients?: number
}) {
  const refs = useRef<THREE.Mesh[]>([])
  const tmp = useRef(new THREE.Vector3())
  useFrame((state) => {
    refs.current.forEach((mesh, i) => {
      if (!mesh) return
      const t = (state.clock.elapsedTime * 0.16 + i / 4) % 1
      pathPoint(t, tmp.current, clientIndex, totalClients)
      mesh.position.copy(tmp.current)
      mesh.visible = active
    })
  })
  return (
    <>
      {Array.from({ length: 4 }, (_, i) => (
        <mesh
          key={i}
          ref={(el) => {
            if (el) refs.current[i] = el
          }}
        >
          <sphereGeometry args={[0.034, 12, 12]} />
          <meshBasicMaterial color="#38BDF8" transparent opacity={0.4} toneMapped={false} />
        </mesh>
      ))}
    </>
  )
}

function ProbeNode({
  position,
  color,
  title,
  subtitle,
  badge,
  tone,
  rippleKey,
  onClick,
}: {
  position: THREE.Vector3
  color: string
  title: string
  subtitle: string
  badge: string
  tone: 'blue' | 'green' | 'slate'
  rippleKey?: number
  onClick?: () => void
}) {
  const [hovered, setHovered] = useState(false)
  const isStandby = tone === 'slate'
  const ring = useRef<THREE.Mesh>(null)
  useCursor(hovered)
  useFrame(() => {
    if (!ring.current || !rippleKey || isStandby) return
    const age = (performance.now() - rippleKey) / 720
    if (age > 1) {
      ring.current.visible = false
      return
    }
    ring.current.visible = true
    ring.current.scale.setScalar(1 + age * 4.4)
    const mat = ring.current.material as THREE.MeshBasicMaterial
    mat.opacity = 0.72 * (1 - age)
  })

  return (
    <group
      position={position}
      scale={hovered ? 1.07 : 1}
      onPointerOver={() => setHovered(true)}
      onPointerOut={() => setHovered(false)}
      onClick={(e) => {
        e.stopPropagation()
        onClick?.()
      }}
    >
      <mesh position={[0, -0.2, 0]}>
        <cylinderGeometry args={[0.78, 0.88, 0.14, 40]} />
        <meshStandardMaterial color={isStandby ? '#f1f5f9' : '#ffffff'} metalness={0.18} roughness={0.24} />
      </mesh>
      <mesh>
        <sphereGeometry args={[0.42, 48, 48]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={isStandby ? 0.05 : hovered ? 1.05 : 0.48}
          roughness={isStandby ? 0.8 : 0.2}
          metalness={isStandby ? 0.05 : 0.12}
          transparent={isStandby}
          opacity={isStandby ? 0.65 : 1}
        />
      </mesh>
      {!isStandby && (
        <mesh ref={ring} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.02, 0]} visible={false}>
          <ringGeometry args={[0.44, 0.62, 56]} />
          <meshBasicMaterial color="#059669" transparent opacity={0.7} side={THREE.DoubleSide} />
        </mesh>
      )}
      <Html position={[0, 0.78, 0]} center distanceFactor={10} zIndexRange={[5, 0]} occlude={false} pointerEvents="none">
        <div className={`ms-node ${tone}`}>
          <div className="ms-pill">{badge}</div>
          <strong>{title}</strong>
          <span>{subtitle}</span>
        </div>
      </Html>
    </group>
  )
}

function RouterNode({ onResetFilter }: { onResetFilter?: () => void }) {
  const [hovered, setHovered] = useState(false)
  useCursor(hovered)
  const spin = useRef<THREE.Mesh>(null)
  useFrame((_, dt) => {
    if (spin.current) spin.current.rotation.z += dt * 0.55
  })
  return (
    <group
      position={ROUTER_POS}
      scale={hovered ? 1.05 : 1}
      onPointerOver={() => setHovered(true)}
      onPointerOut={() => setHovered(false)}
      onClick={(e) => {
        e.stopPropagation()
        onResetFilter?.()
      }}
    >
      <mesh>
        <boxGeometry args={[0.98, 0.5, 0.98]} />
        <meshStandardMaterial color="#ffffff" metalness={0.34} roughness={0.18} />
      </mesh>
      <mesh position={[0, 0.32, 0.42]}>
        <boxGeometry args={[0.62, 0.06, 0.08]} />
        <meshStandardMaterial color="#008DDA" emissive="#38BDF8" emissiveIntensity={0.9} />
      </mesh>
      <mesh ref={spin} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[0.6, 0.04, 14, 56]} />
        <meshStandardMaterial color="#008DDA" emissive="#38BDF8" emissiveIntensity={0.7} />
      </mesh>
      <Html position={[0, 0.86, 0]} center distanceFactor={10} zIndexRange={[5, 0]} occlude={false} pointerEvents="none">
        <div className="ms-node cyan">
          <div className="ms-pill">MiniShark-Host · E3</div>
          <strong>Router Node (Hub)</strong>
          <span>TCP :9000 Hub Listening</span>
        </div>
      </Html>
    </group>
  )
}

function PacketParticle({ flight, totalClients }: { flight: Flight; totalClients: number }) {
  const group = useRef<THREE.Group>(null)
  const mesh = useRef<THREE.Mesh>(null)
  const shock = useRef<THREE.Mesh>(null)
  const sparks = useRef<THREE.Group>(null)
  const t = useRef(0)
  const done = useRef(false)
  const pos = useRef(new THREE.Vector3())
  const [dropping, setDropping] = useState(false)
  const frozenFlightId = useCaptureStore((s) => s.frozenFlightId)
  const selectPacket = useCaptureStore((s) => s.selectPacket)
  const completeFlight = useCaptureStore((s) => s.completeFlight)
  const frozen = frozenFlightId === flight.id
  const color = flight.kind === 'drop' ? '#DC2626' : flight.kind === 'slow' ? '#D97706' : '#38BDF8'
  const clientIdx = Math.min(flight.clientId ?? 0, Math.max(0, totalClients - 1))

  useFrame((_, dt) => {
    if (done.current || !group.current || !mesh.current) return
    if (!frozen) t.current += dt / flight.duration

    if (flight.kind === 'drop') {
      const travel = Math.min(t.current / 0.5, 1) * 0.5
      pathPoint(travel, pos.current, clientIdx, totalClients)
      group.current.position.copy(pos.current)
      if (t.current > 0.5) {
        if (!dropping) setDropping(true)
        mesh.current.scale.setScalar(Math.max(0, 1 - (t.current - 0.5) * 3.6))
        const k = (t.current - 0.5) * 2.2
        if (shock.current) {
          shock.current.visible = true
          shock.current.scale.setScalar(1 + k * 3.2)
          const mat = shock.current.material as THREE.MeshBasicMaterial
          mat.opacity = Math.max(0, 0.9 - k)
        }
        if (sparks.current) {
          sparks.current.visible = true
          sparks.current.children.forEach((child, i) => {
            const a = (i / sparks.current!.children.length) * Math.PI * 2
            child.position.set(Math.cos(a) * k * 0.55, 0.08 + k * 0.2, Math.sin(a) * k * 0.55)
          })
        }
      }
      if (t.current > 1.18 && !done.current) {
        done.current = true
        queueMicrotask(() => completeFlight(flight.id, flight.packetId, 'drop'))
      }
      return
    }

    const p = Math.min(t.current, 1)
    pathPoint(p, pos.current, clientIdx, totalClients)
    group.current.position.copy(pos.current)
    mesh.current.scale.setScalar(frozen ? 1.4 : 1)
    if (t.current >= 1 && !done.current) {
      done.current = true
      queueMicrotask(() => completeFlight(flight.id, flight.packetId, flight.kind))
    }
  })

  return (
    <group ref={group}>
      <mesh
        ref={mesh}
        onClick={(e) => {
          e.stopPropagation()
          selectPacket(flight.packetId, flight.id)
        }}
        onPointerOver={(e) => {
          e.stopPropagation()
          document.body.style.cursor = 'pointer'
        }}
        onPointerOut={() => {
          document.body.style.cursor = 'auto'
        }}
      >
        <sphereGeometry args={[0.125, 24, 24]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={1.55} toneMapped={false} />
        <pointLight color={color} intensity={frozen ? 3.4 : 1.8} distance={2.2} />
      </mesh>
      <mesh ref={shock} visible={false} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.08, 0.22, 56]} />
        <meshBasicMaterial color="#DC2626" transparent opacity={0.85} side={THREE.DoubleSide} />
      </mesh>
      <group ref={sparks} visible={false}>
        {Array.from({ length: 8 }, (_, i) => (
          <mesh key={i}>
            <sphereGeometry args={[0.03, 8, 8]} />
            <meshBasicMaterial color="#DC2626" toneMapped={false} />
          </mesh>
        ))}
      </group>
      {dropping && (
        <Html center distanceFactor={8} zIndexRange={[8, 0]} occlude={false} pointerEvents="none" position={[0, 0.32, 0]}>
          <div className="ms-drop">[SILENT DROP: Hash {flight.hash64.slice(0, 8)}… — Link Loss: Client {clientIdx + 1} → Hub]</div>
        </Html>
      )}
      {frozen && flight.kind !== 'drop' && (
        <Html center occlude={false} pointerEvents="none" position={[0, 0.28, 0]}>
          <div className="ms-frozen">Frozen · Frame {flight.packetId}</div>
        </Html>
      )}
    </group>
  )
}

function FpsMeter() {
  const n = useRef(0)
  const acc = useRef(0)
  const setFps = useCaptureStore((s) => s.setFps)
  useFrame((_, dt) => {
    n.current += 1
    acc.current += dt
    if (acc.current > 0.5) {
      setFps(n.current / acc.current)
      n.current = 0
      acc.current = 0
    }
  })
  return null
}

function ClientsHUD() {
  const clientCount = useCaptureStore((s) => s.clientCount)
  const clients = useCaptureStore((s) => s.clients)
  const probes = useCaptureStore((s) => s.probesStatus)
  const demoMode = useCaptureStore((s) => s.demoMode)
  const filter = useCaptureStore((s) => s.filter)
  const setFilter = useCaptureStore((s) => s.setFilter)

  const clientProbes = (probes.active_clients || []).filter((p) => p.probe_id !== 2)
  const uniqueProbeIds = Array.from(new Set(clientProbes.map((p) => p.probe_id)))
  const ingressCount = uniqueProbeIds.length
  const activeClients = clients.slice(0, Math.max(1, clientCount))

  return (
    <div className="pointer-events-auto absolute top-16 left-3 z-30 flex flex-col gap-1.5 rounded-2xl border border-white/80 bg-white/92 p-2.5 shadow-[0_8px_24px_rgba(15,23,42,0.06)] backdrop-blur-md">
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-1.5">
        <span className="font-display text-[10px] font-semibold uppercase tracking-wider text-slate-400">
          Traffic Sources
        </span>
        <span className="flex items-center gap-1 text-[10px] font-medium text-emerald-600">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
          {demoMode
            ? 'Simulated'
            : ingressCount > 1
              ? `${ingressCount} Ingress Probes`
              : probes.probe1_connected
                ? 'Probe Ingress Active'
                : 'Standby'}
        </span>
      </div>

      <div className="flex flex-col gap-1">
        {activeClients.map((c, i) => {
          const isSelected = filter.includes(c.ip)
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => setFilter(isSelected ? '' : `ip.src == ${c.ip}`)}
              className={`flex items-center justify-between gap-3 rounded-xl px-2.5 py-1.5 text-left transition ${
                isSelected
                  ? 'border border-blue-400 bg-blue-50 text-blue-900 shadow-xs'
                  : 'bg-slate-50/80 hover:bg-slate-100/90 text-slate-700'
              }`}
              title={`Click to filter packets for ${c.name} (${c.ip})`}
            >
              <div className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-lg bg-blue-600 font-mono text-[9px] font-bold text-white shadow-xs">
                  C{i + 1}
                </span>
                <div>
                  <div className="font-semibold text-[11px] leading-tight text-slate-800">{c.name}</div>
                  <div className="font-mono text-[10px] text-slate-400">{c.ip}</div>
                </div>
              </div>
              <span className="rounded bg-white px-1.5 py-0.5 font-mono text-[9.5px] font-medium text-slate-500 border border-slate-200/60 shadow-xs">
                {c.vm}
              </span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function Legend() {
  const demoMode = useCaptureStore((s) => s.demoMode)
  const probes = useCaptureStore((s) => s.probesStatus)

  return (
    <div className="absolute bottom-3 left-3 flex items-center gap-3 rounded-2xl border border-slate-200 bg-white/90 px-3 py-2 text-[11px] text-slate-600 shadow-sm backdrop-blur">
      <span className="font-display text-[10px] uppercase tracking-[0.14em] text-slate-400">Observatory</span>
      <span className="flex items-center gap-1.5 font-semibold text-slate-800">
        <span
          className={`h-2 w-2 rounded-full ${
            demoMode ? 'bg-blue-600' : probes.total_connected > 0 ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'
          }`}
        />
        {demoMode
          ? 'Simulation Active'
          : probes.total_connected > 0
            ? `${probes.total_connected} Probe(s) Live`
            : 'Standby: Probes Disconnected'}
      </span>
      <span className="flex items-center gap-1.5">
        <i className="h-2 w-2 rounded-full bg-[#38BDF8]" /> Cyan ΔT
      </span>
      <span className="flex items-center gap-1.5">
        <i className="h-2 w-2 rounded-full bg-[#D97706]" /> Latency
      </span>
      <span className="flex items-center gap-1.5">
        <i className="h-2 w-2 rounded-full bg-[#DC2626]" /> Silent drop
      </span>
    </div>
  )
}
