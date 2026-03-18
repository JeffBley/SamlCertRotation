import { defineConfig } from 'vite';
import { copyFileSync } from 'fs';

export default defineConfig({
  // Build static artifacts into dist/ for SWA CLI deployment.
  build: {
    outDir: 'dist',
    sourcemap: true
  },
  plugins: [
    {
      // app.js is a non-module script so Vite won't bundle it automatically.
      // Copy it verbatim into dist/ so it is included in every deployment.
      name: 'copy-app-js',
      closeBundle() {
        copyFileSync('app.js', 'dist/app.js');
      }
    }
  ],
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
