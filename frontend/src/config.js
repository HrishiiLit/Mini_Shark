/**
 * Mini-Shark — Dynamic API / WebSocket URL configuration.
 *
 * In a multi-VM deployment the browser may be running on a different machine
 * than the one that served the page (e.g. a student's laptop browsing
 * http://192.168.10.1:8001). Hardcoding 127.0.0.1 would break every fetch
 * and WebSocket in that scenario.
 *
 * Using window.location.hostname means:
 *   - Dev (Vite on localhost)   → API = http://localhost:8001
 *   - Hub VM (192.168.10.1)     → API = http://192.168.10.1:8001
 *   - Any other host            → API = http://<that-host>:8001
 *
 * Override at build-time via VITE_API_HOST env variable if needed:
 *   VITE_API_HOST=http://192.168.10.1:8001 npm run build
 */

const _host = import.meta.env.VITE_API_HOST
  ? import.meta.env.VITE_API_HOST.replace(/\/$/, '')   // strip trailing slash
  : `http://${window.location.hostname}:8001`

const _ws = _host.replace(/^http/, 'ws')

/** Base URL for all REST API calls, e.g. http://192.168.10.1:8001 */
export const API = _host

/** WebSocket endpoint for live packet streaming */
export const WS = `${_ws}/ws/live`
