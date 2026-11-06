import * as THREE from 'three'
import type { ClientNodeInfo } from '../types'

export const ROUTER_POS = new THREE.Vector3(0, 0.72, 0)
export const SERVER_POS = new THREE.Vector3(4.6, 0.35, 0)

export const DEFAULT_CLIENTS: ClientNodeInfo[] = [
  {
    id: 0,
    name: 'Arch Linux (Host)',
    ip: '10.108.157.186',
    probeBadge: 'Probe 1 · Client 1',
    os: 'Arch Linux',
    vm: 'Laptop 2 Host',
  },
  {
    id: 1,
    name: 'Ubuntu (VMware)',
    ip: '172.16.253.128',
    probeBadge: 'Probe 1 · Client 2',
    os: 'Ubuntu 22.04 LTS',
    vm: 'Laptop 2 Guest VM',
  },
  {
    id: 2,
    name: 'Client 3',
    ip: '10.108.157.187',
    probeBadge: 'Probe 1 · Ingress',
    os: 'Linux',
    vm: 'Client 3',
  },
  {
    id: 3,
    name: 'Client 4',
    ip: '10.108.157.188',
    probeBadge: 'Probe 1 · Ingress',
    os: 'Linux',
    vm: 'Client 4',
  },
]

export function getClientPosition(index: number, total: number): THREE.Vector3 {
  if (total <= 1) return new THREE.Vector3(-4.6, 0.35, 0)
  const spreadZ = Math.min(5.4, (total - 1) * 1.6)
  const z = -spreadZ / 2 + (index / Math.max(1, total - 1)) * spreadZ
  const x = -4.6 - Math.abs(z) * 0.12
  return new THREE.Vector3(x, 0.35, z)
}

// Memoized curve map to prevent per-frame re-allocations
const curveCache = new Map<string, THREE.QuadraticBezierCurve3>()

export function getClientCurve(index: number, total: number): THREE.QuadraticBezierCurve3 {
  const key = `${index}:${total}`
  const cached = curveCache.get(key)
  if (cached) return cached

  const p = getClientPosition(index, total)
  const start = new THREE.Vector3(p.x, 0.12, p.z)
  const midX = p.x * 0.48
  const midZ = p.z * 0.5 + (p.z >= 0 ? 0.35 : -0.35)
  const midY = 1.55 + Math.abs(p.z) * 0.08
  const control = new THREE.Vector3(midX, midY, midZ)
  const end = new THREE.Vector3(0, 0.3, 0)

  const curve = new THREE.QuadraticBezierCurve3(start, control, end)
  curveCache.set(key, curve)
  return curve
}

export const curveOut = new THREE.QuadraticBezierCurve3(
  new THREE.Vector3(0, 0.3, 0),
  new THREE.Vector3(2.25, 1.6, -0.6),
  new THREE.Vector3(4.6, 0.12, 0),
)

export function pathPoint(t: number, target: THREE.Vector3, clientIndex = 0, totalClients = 1) {
  const x = Math.min(Math.max(t, 0), 1)
  if (x < 0.5) {
    const c = getClientCurve(clientIndex, totalClients)
    return c.getPointAt(x * 2, target)
  }
  return curveOut.getPointAt((x - 0.5) * 2, target)
}

export function pathTangent(t: number, target: THREE.Vector3, clientIndex = 0, totalClients = 1) {
  const x = Math.min(Math.max(t, 0), 1)
  if (x < 0.5) {
    const c = getClientCurve(clientIndex, totalClients)
    return c.getTangentAt(x * 2, target)
  }
  return curveOut.getTangentAt((x - 0.5) * 2, target)
}
