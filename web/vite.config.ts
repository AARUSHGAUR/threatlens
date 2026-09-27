import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

/**
 * Vite configuration for the ThreatLens analyst client.
 *
 * Security notes:
 *  - No API provider keys are ever referenced here or in client code. The browser
 *    only talks to our own backend (`/api/*`), which holds the credentials.
 *  - The dev server proxies `/api` to the Express API so cookies stay first-party.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, path.resolve(process.cwd(), '..'), '');
  const apiTarget = env.API_INTERNAL_URL || 'http://localhost:4000';

  return {
    plugins: [react()],
    resolve: {
      alias: { '@': path.resolve(process.cwd(), 'src') },
    },
    server: {
      port: 5173,
      strictPort: false,
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: false,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
      chunkSizeWarningLimit: 1200,
    },
  };
});
