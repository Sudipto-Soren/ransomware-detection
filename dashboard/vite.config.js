import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Any request to /api/... is forwarded to the FastAPI backend.
      // This means the React app never does cross-origin requests in dev —
      // no CORS issues, no need to remember the backend port in every fetch().
      '/api': {
        target:       'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
