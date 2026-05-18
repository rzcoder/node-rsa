import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const root = dirname(fileURLToPath(import.meta.url));
const nodeEntry = resolve(root, 'src/index.node.ts');

// The bench imports the public API via the virtual `node-rsa-bench-entry`
// specifier, which resolves to the node bundle. The three modes (`node`,
// `js-jsbn`, `js-native`) are selected per-bench via constructor options —
// no separate project per bundle is needed, since the digest/RNG backend
// is always native to the runtime.
export default defineConfig({
  resolve: {
    alias: { 'node-rsa-bench-entry': nodeEntry },
  },
  test: {
    name: 'bench',
    environment: 'node',
    env: { NODE_RSA_BENCH_MODES: 'node,js-jsbn,js-native' },
    benchmark: {
      include: ['bench/**/*.bench.ts'],
    },
  },
});
