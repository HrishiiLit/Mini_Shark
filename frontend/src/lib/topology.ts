import * as THREE from 'three'

export const CLIENT_POS = new THREE.Vector3(-4.6, 0.35, 0)
export const ROUTER_POS = new THREE.Vector3(0, 0.72, 0)
export const SERVER_POS = new THREE.Vector3(4.6, 0.35, 0)

export const curveIn = new THREE.QuadraticBezierCurve3(
  new THREE.Vector3(-4.6, 0.12, 0),
  new THREE.Vector3(-2.25, 1.6, 1.15),
  new THREE.Vector3(0, 0.3, 0),
)

export const curveOut = new THREE.QuadraticBezierCurve3(
  new THREE.Vector3(0, 0.3, 0),
  new THREE.Vector3(2.25, 1.6, -1.15),
  new THREE.Vector3(4.6, 0.12, 0),
)

export function pathPoint(t: number, target: THREE.Vector3) {
  const x = Math.min(Math.max(t, 0), 1)
  if (x < 0.5) return curveIn.getPointAt(x * 2, target)
  return curveOut.getPointAt((x - 0.5) * 2, target)
}

export function pathTangent(t: number, target: THREE.Vector3) {
  const x = Math.min(Math.max(t, 0), 1)
  if (x < 0.5) return curveIn.getTangentAt(x * 2, target)
  return curveOut.getTangentAt((x - 0.5) * 2, target)
}
