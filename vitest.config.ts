import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const root = dirname(fileURLToPath(import.meta.url));
const nodeBackend = resolve(root, 'src/crypto/backend.node.ts');
const webBackend = resolve(root, 'src/crypto/backend.web.ts');

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'node',
          include: ['test/**/*.spec.ts'],
          environment: 'node',
        },
      },
      {
        resolve: {
          alias: {
            [nodeBackend]: webBackend,
          },
        },
        define: {
          'process.env.NODE_RSA_FORCE_BACKEND': JSON.stringify('web'),
        },
        test: {
          name: 'browser-emulated',
          include: ['test/**/*.spec.ts'],
          exclude: ['test/**/*.node-only.spec.ts'],
          environment: 'node',
        },
      },
    ],
  },
});
