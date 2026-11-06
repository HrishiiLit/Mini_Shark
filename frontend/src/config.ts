// Dynamically resolve backend API and WebSocket endpoints based on the browser's hostname.
// This allows the same frontend build to connect seamlessly whether running locally on 127.0.0.1,
// on localhost, or across physical/virtual testbed machines (e.g. 10.108.157.2).

const envHost = import.meta.env.VITE_API_HOST
const host =
  envHost ||
  (typeof window !== 'undefined' && window.location.hostname
    ? `http://${window.location.hostname}:8001`
    : 'http://127.0.0.1:8001')

const wsHost = host.replace(/^http/, 'ws')

export const API = host
export const WS = `${wsHost}/ws/live`
