import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// VITE_API_HOST lets you point the dev-server proxy at a remote hub, e.g.:
//   VITE_API_HOST=http://192.168.10.1:8001 npm run dev
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backendTarget = env.VITE_API_HOST || 'http://127.0.0.1:8001'

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        // REST API calls: /api/* → backend (strip /api prefix)
        '/api': {
          target: backendTarget,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, ''),
        },
        // WebSocket live feed
        '/ws': {
          target: backendTarget,
          changeOrigin: true,
          ws: true,
        },
      },
    },
  }
})
