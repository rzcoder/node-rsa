# Changelog

## 2.0.0 — TypeScript rewrite

Full rewrite of the v1 library in TypeScript with the same public API.

### Breaking changes

- **Min Node.js is now 20**. v1 worked back to Node 8.11; v2 requires Node 20+
  for `node:crypto`, `globalThis.crypto`, and modern ESM features.
- **Module shape**: ESM-first. `package.json#exports` provides a dual ESM/CJS
  layout — `import NodeRSA from 'node-rsa'` for ESM,
  `require('node-rsa').default` for CommonJS.
- **Browser default return type is `Uint8Array`** (was `Buffer` via polyfill).
  Node return type stays `Buffer` (which extends `Uint8Array`, so most
  existing consumers continue to work). Internal byte handling is `Uint8Array`
  end-to-end; the Node entry wraps results as `Buffer` at the API boundary.
- **No more `Buffer` or `crypto` shims for browsers**. The browser bundle
  contains zero Node-builtin imports — verified in CI by a `grep` over
  `dist/index.browser.js`. Bundlers (Vite, Webpack 5, Rollup, esbuild, Parcel)
  resolve the browser entry via package.json conditional exports.
- **`setOptions({environment})` is a deprecated no-op**. Build-time platform
  conditions decide the runtime now. The option still forces the pure-JS
  engine path when set to `'browser'`, preserving the v1 semantic that the
  61-case test suite relies on. A one-time `console.warn` is emitted on use.
- **MD4 is Node-only and provider-gated**. OpenSSL 3 (Node 17+) doesn't load
  the legacy provider by default, so `crypto.createHash('md4')` throws. v2
  probes at module load and reports md4 as unsupported when the provider is
  absent. The browser bundle never supports MD4.
- **`asn1` npm dependency removed**. PKCS#1, PKCS#8, and OpenSSH formats now
  use a small in-tree DER reader/writer (~150 lines, under
  [`src/asn1/`](src/asn1)). Byte-identical to v1 output for every fixture key.
- **Native PKCS#1 v1.5 `privateDecrypt` is routed through the JS engine on
  modern Node**. Node has security-deprecated raw PKCS#1 v1.5 decryption (CVE
  response); v2 transparently falls back to the pure-JS implementation so the
  call still succeeds. The byte-for-byte plaintext is identical.

### Added

- TypeScript types for every public surface (`NodeRSAOptions`,
  `EncryptionSchemeOptions`, `SigningSchemeOptions`, `HashAlg`, format
  string union types).
- `@noble/hashes` runtime dependency for synchronous SHA/MD/RIPEMD digests
  in the browser bundle. ~6 KB gzipped, audited, zero-dep.
- Bundle size budget (CI-enforced):
  - `dist/index.browser.js`: <100 KB raw / <30 KB gzipped (currently 90/21)
  - `dist/index.node.{js,cjs}`: <120 KB raw / <35 KB gzipped (currently 94/22)

### Internal

- Modern tooling: `tsup` for build (esbuild), `vitest` for tests (with a
  workspace running every spec in two projects — `node` and
  `browser-emulated`), `biome` for lint+format, strict TypeScript with
  `noUncheckedIndexedAccess` / `exactOptionalPropertyTypes` /
  `noImplicitOverride` etc.
- 1006 test cases across 27 files. The v1 mocha suite of 61 `it()` blocks is
  ported verbatim and runs in both vitest projects.
- The legacy v1 source is preserved in `src.legacy/` during the port and
  deleted on the v2.0.0 release commit.

### Deferred to v2.1

Tracked in [`TODO.md`](TODO.md): native-BigInt backend (replaces the jsbn
port for a ~10× keygen speedup), `generateKeyPairAsync` (browser-friendly,
non-blocking), async `sign`/`verify`/`encrypt`/`decrypt` variants for Web
Crypto integration, full Vite+Playwright browser example.

## 1.1.1 and earlier

See git history.
