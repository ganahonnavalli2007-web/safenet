import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Build output goes directly into the FastAPI backend's static folder
  build: {
    outDir: path.resolve(__dirname, '../safenet-backend/static'),
    emptyOutDir: true,
  },
  // During dev, proxy API calls to FastAPI so no CORS issues
  server: {
    port: 5173,
    proxy: {
      '/analyze': 'http://localhost:8000',
      '/threats': 'http://localhost:8000',
      '/dashboard': 'http://localhost:8000',
      '/report': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    }
  }
})
