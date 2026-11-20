/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  // In development the API is proxied so the refresh cookie stays first-party (SameSite=Lax).
  const apiTarget = env.VITE_DEV_API_PROXY ?? 'http://127.0.0.1:8000'
  const apiProxy = {
    target: apiTarget,
    changeOrigin: false,
    ws: true,
    // A browser closing its WebSocket (navigation, reload) resets the upstream socket: not an error.
    configure: (proxy: { on: (event: 'error', cb: (err: NodeJS.ErrnoException) => void) => void }) => {
      proxy.on('error', (err) => {
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') console.error('[api proxy]', err.message)
      })
    },
  }
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
    },
    server: {
      port: 5173,
      proxy: {
        '/api': apiProxy,
        '/health': { target: apiTarget, changeOrigin: false },
      },
    },
    preview: {
      port: 4173,
      proxy: { '/api': apiProxy },
    },
    build: {
      sourcemap: false,
      chunkSizeWarningLimit: 900,
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/test/setup.ts'],
      include: ['src/**/*.test.{ts,tsx}'],
      css: false,
    },
  }
})
