# Migrating from node-rsa v1 to v2.0

## TL;DR

Bump Node to ≥ 20; follow Steps 1–10 below. The biggest behavioural change
to watch for is the **default signing scheme switch from PKCS#1 v1.5 to
RSASSA-PSS**. If you rely on the default (i.e. call `key.sign(...)` without
an explicit `signingScheme`), either accept the switch (recommended — PSS
is modern best practice) or pin to v1.5 explicitly. See
[Step 7](#step-7-adjust-to-the-new-default-signing-scheme).

For browser bundlers (Vite, Webpack 5, Rollup, esbuild, Parcel), **delete
any Buffer/crypto/process shims** you set up for v1 — they're no longer
needed and may interfere.

## Behaviour changes at a glance

| Concern | v1 | v2 |
|---|---|---|
| Return types on Node | `Buffer` | `Buffer` (unchanged; `Buffer` extends `Uint8Array`) |
| Return types on browser | needed Buffer polyfill | `Uint8Array` |
| Module system | CJS | ESM + CJS dual |
| Min Node version | 8.11 | 20 |
| Browser crypto | `crypto-browserify` shim required | Built-in: `@noble/hashes` + `globalThis.crypto.getRandomValues` |
| `setOptions({environment})` | controls runtime branching | Deprecated no-op (still forces JS engine when set to `'browser'`) |
| MD4 in browser | available via shim | not available (Web Crypto subset) |
| `asn1` npm dependency | required | replaced with in-tree DER reader/writer |
| Default signing scheme | `pkcs1` (PKCS#1 v1.5) | `pss` (RSASSA-PSS) |
| Custom MGF for PSS on Node | accepted (pure-JS path) | throws — force JS path via `setOptions({environment:'browser'})` |

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

The node bundle additionally routes sign/verify through
`node:crypto.{sign,verify}`, which **throws synchronously** for any hash
the local OpenSSL build doesn't support (most commonly `md4`, sometimes
`ripemd160`). v1 and v2's pure-JS schemes already threw at digest time —
only the error wording and call-site differ. If you need a hash OpenSSL
doesn't support but `@noble/hashes` does, force the JS path with
`setOptions({ environment: 'browser' })`.

## Step 7: adjust to the new default signing scheme

`DEFAULT_SIGNING_SCHEME` is `'pss'` in v2 (was `'pkcs1'` in v1). This
matters in two cases:

1. **You call `key.sign()` without an explicit scheme and someone else
   verifies the signature.** They'll be expecting PSS, not PKCS#1 v1.5.
   Either coordinate the switch or pin explicitly:

   ```ts
   const key = new NodeRSA(pem, { signingScheme: 'pkcs1' });
   //                              ^^^^^^^^^^^^^^^^^^^^^^^^
   //         keeps v1's PKCS#1 v1.5 default; remove this line to accept the v2 default
   ```

2. **You used the bare-hash shorthand** `signingScheme: 'sha256'`. The
   shorthand maps to "default scheme + that hash", so in v1 it meant
   `pkcs1-sha256`; in v2 it means `pss-sha256`. Spell out the scheme to
   keep behaviour:

   ```ts
   new NodeRSA(null, { signingScheme: 'pkcs1-sha256' });
   ```

Round-trip in-process (`key.sign()` then `key.verify()` on the same
`NodeRSA` instance, no `setOptions` between them) is unaffected — both
sides see the same default and round-trip cleanly. Cross-version
verification (sign in v1, verify in v2, or vice versa) requires an
explicit scheme on at least one side.

## Step 8: if you used a custom MGF for PSS

The node bundle calls `node:crypto.sign` / `verify` for PSS, and
`node:crypto` only supports MGF1 with hash equal to the signing hash.
Passing `signingScheme: { scheme: 'pss', mgf: ... }` on Node throws at
scheme construction. To keep a custom MGF, opt back into the pure-JS path:

```ts
key.setOptions({ environment: 'browser' });   // forces JsEngine + JS schemes
```

If you forced `environment: 'browser'` at runtime, sign/verify revert to
the pure-JS schemes alongside the engine — that path is unchanged.

## Step 9: re-run your tests

The 61-case mocha suite from v1 is ported 1-to-1 in v2's
`test/node-rsa.spec.ts` (run on both Node and browser-emulated workspaces)
and is green. If your tests still pass, you're done.

## Step 10: TypeScript types — drop `@types/node-rsa`

v2 ships native TypeScript types. **Uninstall `@types/node-rsa`** — keeping
it shadows the bundled `.d.ts` and produces stale errors:

```sh
npm uninstall @types/node-rsa
```

The runtime and value-level API is unchanged, but the type surface differs
from `@types/node-rsa@1.1.4` in a few places. The fixes are mechanical.

### Module shape

DT used `export = NodeRSA`, which carried a namespace alongside the class.
v2 uses `export default NodeRSA` plus named type exports.

```ts
// v1 + @types/node-rsa
import NodeRSA = require('node-rsa');
const opts: NodeRSA.Options = { signingScheme: 'pkcs1-sha256' };
const key: NodeRSA.Key = pemString;

// v2
import NodeRSA, { type NodeRSAOptions, type Key } from 'node-rsa';
const opts: NodeRSAOptions = { signingScheme: 'pkcs1-sha256' };
const key: Key = pemString;
```

The `NodeRSA.<TypeName>` namespace pattern no longer resolves — every type
must be imported by name.

### One renamed type

Only the `Options` interface is renamed — DT scoped it under the namespace
(`NodeRSA.Options`), v2 exports it flat with the class-prefix:

| `@types/node-rsa@1.1.4` | v2 |
|---|---|
| `NodeRSA.Options` | `NodeRSAOptions` |

Every other DT type name is preserved as-is: `Key`, `Data`, `KeyBits`,
`KeyComponentsPrivate`, `KeyComponentsPublic`, `Format`, `FormatPem`,
`FormatDer`, `FormatComponentsPrivate`, `FormatComponentsPublic`, `Encoding`,
`EncryptionScheme`, `SigningScheme`, `SigningSchemeHash`, `HashingAlgorithm`,
`AdvancedSigningScheme`, `AdvancedSigningSchemePSS`, `AdvancedSigningSchemePKCS1`,
`AdvancedEncryptionScheme`, `AdvancedEncryptionSchemePKCS1`,
`AdvancedEncryptionSchemePKCS1OAEP`. Import them by name.

### `Encoding` is narrower

DT declared `Encoding = "ascii" | "utf8" | "utf16le" | "ucs2" | "latin1" |
"base64" | "hex" | "binary" | "buffer"`. v2 declares `Encoding = 'buffer'
| 'binary' | 'latin1' | 'hex' | 'base64' | 'utf8'`.

The dropped values (`ascii`, `utf16le`, `ucs2`) were not actually wired
end-to-end in v1 — passing them ran the data through a base64 fallback that
mangled non-ASCII input. v2 removes the type so the silent fallback can't
be reached. If you were genuinely using `'utf16le'` and getting expected
results, you weren't; switch to `'utf8'` or pre-encode the buffer yourself.

`'binary'` and `'latin1'` are interchangeable in v2 and map to the same
runtime path.

### Return types

`Buffer` on Node, `Uint8Array` on browser — already covered in
[Step 3](#step-3-review-return-types). DT always returned `Buffer`; if you
relied on Buffer-only methods (`.toString('base64')`, `.write`, etc.) on a
browser build, switch to the explicit-encoding overloads or polyfill `Buffer`.

## When to keep using v1

- You depend on `node-rsa` working under Node ≤ 18.
- You import from `node-rsa/src/...` deep-paths. v2 doesn't expose that
  layout.
- You patched the v1 source for a private fix. The v2 file structure is
  different; reapply against v2 or wait for the v2.x port of your patch.

`npm install node-rsa@^1.1` continues to work for those cases.
