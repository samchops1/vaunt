import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5000,
    strictPort: true,
    hmr: false,
    watch: {
      usePolling: true,
      interval: 1000
    },
    cors: true,
    headers: {
      'Access-Control-Allow-Origin': '*'
    }
  }
})
