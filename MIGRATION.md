# Migrating from node-rsa v1 to v2

## TL;DR

For most Node.js consumers, **change nothing**. The public API is the same.
Make sure your Node runtime is ≥ 20 and rebuild.

For browser bundlers (Vite, Webpack 5, Rollup, esbuild, Parcel), **delete
any Buffer/crypto/process shims** you set up for v1 — they're no longer
needed and may interfere.

## Step 1: bump Node

```jsonc
// package.json (yours)
"engines": { "node": ">=20" }
```

v2 uses `node:crypto`, `globalThis.crypto`, ESM `import.meta`, and a strict
TypeScript configuration that targets ES2022. Node 18 reached end-of-life on
2025-04-30; v2 drops it.

## Step 2: update the import

```ts
// v1 (CommonJS)
const NodeRSA = require('node-rsa');

// v2 ESM
import NodeRSA from 'node-rsa';

// v2 CJS still works
const NodeRSA = require('node-rsa').default;
```

The CJS `.default` is the standard ESM-to-CJS interop shape.

## Step 3: review return types

If you call `.toString(...)` on the result of `encrypt`/`decrypt`/`sign`,
keep going — `Buffer` is still returned on Node. For browser bundles, the
return type is `Uint8Array`, which does not have `.toString('base64')`.
Replace with explicit encoding:

```ts
// v1 (browser, with polyfill)
const b64 = key.encrypt('hi').toString('base64');

// v2 (browser, no polyfill)
const b64 = key.encrypt('hi', 'base64');
// or
const bytes = key.encrypt('hi');
const b64 = btoa(String.fromCharCode(...bytes));
```

The encoding parameter has always existed on v1 too — using it now is
forward-compatible with both.

## Step 4: remove Buffer / crypto shims from your bundler

For Vite:

```diff
// vite.config.ts
- import { nodePolyfills } from 'vite-plugin-node-polyfills';
  export default defineConfig({
-   plugins: [nodePolyfills({ include: ['buffer', 'crypto'] })],
+   plugins: [],
  });
```

For Webpack:

```diff
// webpack.config.js
  resolve: {
-   fallback: { buffer: require.resolve('buffer/'), crypto: require.resolve('crypto-browserify') },
+   fallback: { buffer: false, crypto: false },
  },
```

The browser entry of `node-rsa@2` has no Node-builtin imports — CI greps the
bundle to keep it that way.

## Step 5: drop the `environment` option (optional)

`setOptions({ environment: 'browser' })` still works as a force-JS-engine
hint, but it logs a one-time deprecation warning. If you only need that
because you used to run `environment: 'browser'` in a Node test for cross-
compat checks, the new vitest workspace pattern is a better fit.

If you genuinely relied on `'iojs'` as an environment value, switch to
`'node'`. v2 has no third platform.

## Step 6: re-check your hash algorithm selection

* **MD4 in browser**: was never supported in v1's browser whitelist either
  — no change.
* **MD4 on Node**: v2 probes for OpenSSL legacy-provider availability at
  module load. If your Node runtime doesn't load it, MD4 throws. Switch to
  SHA-256 for any signing scheme that's not pinned by a wire-protocol
  requirement.

## Step 7: re-run your tests

The 61-case mocha suite from v1 is ported 1-to-1 in v2's
`test/node-rsa.spec.ts` (run on both Node and browser-emulated workspaces)
and is green. If your tests still pass, you're done.

## Things that did NOT change

- Constructor overloads — `new NodeRSA(pem)`, `new NodeRSA({b:2048})`,
  `new NodeRSA(pem, 'pkcs1-private-pem')`, `new NodeRSA(pem, options)`.
- Format strings — every `'pkcs1-private-pem'` / `'pkcs8-public-der'` /
  `'openssh-private'` / `'components'` / etc. still resolves the same.
- Combined scheme strings — `'pss-sha512'`, `'pkcs1-md5'`, etc.
- The `$$encryptKey` / `$$decryptKey` / `$getDataForEncrypt` /
  `$getDecryptedData` "internal" methods are still present on the class for
  the (unusual) callers that depend on them.
- `key.keyPair.{n,e,d,p,q,dmp1,dmq1,coeff}` field access — works the same;
  the fields are `BigInteger | null`.

## When to keep using v1

- You depend on `node-rsa` working under Node ≤ 18.
- You import from `node-rsa/src/...` deep-paths. v2 doesn't expose that
  layout.
- You patched the v1 source for a private fix. The v2 file structure is
  different; reapply against v2 or wait for the v2.x port of your patch.

`npm install node-rsa@^1.1` continues to work for those cases.
