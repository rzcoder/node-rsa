import { defineConfig } from 'tsup';

const shared = {
  sourcemap: true,
  treeshake: true,
  splitting: false,
  clean: true,
  outDir: 'dist',
} as const;

export default defineConfig([
  {
    ...shared,
    entry: { 'index.node': 'src/index.node.ts' },
    format: ['esm', 'cjs'],
    platform: 'node',
    target: 'node20',
    dts: true,
  },
  {
    ...shared,
    entry: { 'index.browser': 'src/index.browser.ts' },
    format: ['esm'],
    platform: 'browser',
    target: 'es2022',
    dts: true,
    clean: false,
  },
]);
