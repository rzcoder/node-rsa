import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineWorkspace } from 'vitest/config';

const root = dirname(fileURLToPath(import.meta.url));
const nodeBackend = resolve(root, 'src/crypto/backend.node.ts');
const webBackend = resolve(root, 'src/crypto/backend.web.ts');

export default defineWorkspace([
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
      environment: 'node',
    },
  },
]);
