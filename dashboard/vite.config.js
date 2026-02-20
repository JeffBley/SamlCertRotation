import { defineConfig } from 'vite';

export default defineConfig({
  // Build static artifacts into dist/ for SWA CLI deployment.
  build: {
    outDir: 'dist',
    sourcemap: true
  },
  // Local dev proxy so /api calls hit the Functions host without CORS changes.
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:7071',
        changeOrigin: true
      }
    }
  }
});
