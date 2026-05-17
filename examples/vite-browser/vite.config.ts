import { defineConfig } from 'vite';

// Pin a non-default port so this example never clashes with whatever the
// host machine has on 5173. Playwright's webServer config below points at
// the same port — keep them in sync.
export default defineConfig({
  server: {
    port: 5174,
    strictPort: true,
  },
  // Tells Vite to surface a clear error if we accidentally import a
  // Node-builtin from the browser entry — this whole example exists to
  // prove the browser bundle has zero Node deps. (Vite would normally
  // try to polyfill some of them silently.)
  optimizeDeps: {
    include: ['node-rsa'],
  },
});
