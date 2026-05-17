# Migrating from node-rsa v1 / v2.0 to v2.1+

## TL;DR

* **v1 → v2.0**: bump Node to ≥ 20; everything else below in Steps 1–7.
* **v2.0 → v2.1**: one source-level change — the default signing scheme
  switched from PKCS#1 v1.5 to RSASSA-PSS. If you rely on the default
  (i.e. call `key.sign(...)` without an explicit `signingScheme`),
  either accept the switch (recommended — PSS is modern best practice)
  or pin to v1.5 explicitly. See [v2.0 → v2.1](#v20--v21-default-signing-scheme).

For browser bundlers (Vite, Webpack 5, Rollup, esbuild, Parcel), **delete
any Buffer/crypto/process shims** you set up for v1 — they're no longer
needed and may interfere.

## v2.0 → v2.1: node bundle uses `node:crypto` natively

Starting in 2.1, the node bundle routes RSA keygen, sign, and verify
through `node:crypto.{generateKeyPairSync, sign, verify}` whenever
possible — order-of-magnitude faster than the pure-JS path for keys ≥ 2048
bits. The browser bundle is unchanged (no `node:crypto`).

In normal use you don't need to do anything. Two configurations now
throw where 2.0 silently fell back to JS:

1. **Custom MGF for PSS.** `node:crypto` supports only MGF1 with hash =
   signing hash. If you pass `signingScheme: { scheme: 'pss', mgf: ... }`
   on Node, scheme construction throws. To keep a custom MGF, opt back
   into the pure-JS path:

   ```ts
   key.setOptions({ environment: 'browser' });   // forces JsEngine + JS schemes
   ```

2. **Hash algorithms not supported by your local OpenSSL build.** Most
   commonly this affects `md4` (and sometimes `ripemd160`) when the
   OpenSSL 3 legacy provider isn't loaded. Both `nodeBackend.digest` and
   `crypto.sign` reject the hash; sign/verify throw with a clear error.
   The previous behaviour was identical (the JS scheme delegated to
   `nodeBackend.digest` which also threw) — only the error wording and
   call-site differ.

If you forced `environment: 'browser'` at runtime, sign/verify revert to
the pure-JS schemes alongside the engine — that path is unchanged.

## v2.0 → v2.1: default signing scheme

`DEFAULT_SIGNING_SCHEME` changed from `'pkcs1'` to `'pss'` in 2.1. This
matters in two cases:

1. **You call `key.sign()` without an explicit scheme and someone else
   verifies the signature.** They'll be expecting PSS, not PKCS#1 v1.5.
   Either coordinate the switch or pin explicitly:

   ```ts
   const key = new NodeRSA(pem, { signingScheme: 'pkcs1' });
   //                              ^^^^^^^^^^^^^^^^^^^^^^^^
   //         keeps v2.0 default; remove this line to accept the v2.1 default
   ```

2. **You used the bare-hash shorthand** `signingScheme: 'sha256'`. The
   shorthand maps to "default scheme + that hash", so before 2.1 it meant
   `pkcs1-sha256`; now it means `pss-sha256`. Spell out the scheme
   to keep behaviour:

   ```ts
   new NodeRSA(null, { signingScheme: 'pkcs1-sha256' });
   ```

Round-trip in-process (`key.sign()` then `key.verify()` on the same
`NodeRSA` instance, no `setOptions` between them) is unaffected — both
sides see the same default and round-trip cleanly. Cross-version
verification (sign in 2.0, verify in 2.1, or vice versa) requires an
explicit scheme on at least one side.

There are no other source-level changes between 2.0 and 2.1. The rest of
this document is the original v1 → v2.0 migration.

---

# Migrating from node-rsa v1 to v2.0

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
