#!/usr/bin/env node
import { statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const BUDGETS = {
  'dist/index.browser.js': { raw: 100_000, gz: 30_000 },
  'dist/index.node.js': { raw: 120_000, gz: 35_000 },
  'dist/index.node.cjs': { raw: 120_000, gz: 35_000 },
};

let failed = false;
for (const [rel, budget] of Object.entries(BUDGETS)) {
  const path = resolve(root, rel);
  const raw = statSync(path).size;
  const gz = gzipSync(readFileSync(path)).length;
  const rawOk = raw <= budget.raw;
  const gzOk = gz <= budget.gz;
  const mark = (ok) => (ok ? '✓' : '✗');
  console.log(
    `${mark(rawOk && gzOk)} ${rel.padEnd(28)} raw=${kb(raw)} (${mark(rawOk)} ≤${kb(budget.raw)})  gz=${kb(gz)} (${mark(gzOk)} ≤${kb(budget.gz)})`,
  );
  if (!rawOk || !gzOk) failed = true;
}

if (failed) {
  console.error('\nBundle size budget exceeded. Update the budget in scripts/check-bundle-size.mjs or trim the build.');
  process.exit(1);
}

function kb(n) {
  return `${(n / 1024).toFixed(1)} KB`;
}
