import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:9315',
      '/v1': 'http://localhost:9315',
      '/ws': { target: 'ws://localhost:9315', ws: true },
      '/sys': 'http://localhost:9315',
      '/mcp': 'http://localhost:9315',
      '/flows': 'http://localhost:9315',
    },
  },
  build: {
    outDir: '../navra-server/ui-dist',
    emptyOutDir: true,
  },
})
