// Dynamically resolve backend API and WebSocket endpoints based on the browser's hostname.
// This allows the same frontend build to connect seamlessly whether running locally on 127.0.0.1
// or across physical/virtual testbed machines.

const envHost = import.meta.env.VITE_API_HOST
const host =
  envHost ||
  (typeof window !== 'undefined'
    ? `http://192.168.130.129:8001`
    : 'http://192.168.130.129:8001')

const wsHost = host.replace(/^http/, 'ws')

export const API = host
export const WS = `${wsHost}/ws/live`
