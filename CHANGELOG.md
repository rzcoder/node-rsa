# Changelog

## 2.1.0 — Security audit fixes

A multi-agent security audit (cryptography, exploitability, RFC/FIPS
compliance) was run against v2.0.0 and produced a list of findings; this
release closes all Tier 0 (critical / high) and Tier 1 (defence-in-depth)
items. No public-API breakage other than the default-signing-scheme
switch noted below.

### Breaking change

- **Default signing scheme switched from `pkcs1` (PKCS#1 v1.5) to `pss`
  (RSASSA-PSS).** PSS is the modern best-practice signing scheme — it
  has a tighter security reduction and is preferred by RFC 8017 / NIST
  for new code. Existing signatures produced under the v1.5 default
  remain verifiable by passing `signingScheme: 'pkcs1'` explicitly.

  ```ts
  // v2.0 behaviour (sign with PKCS#1 v1.5 by default):
  const key = new NodeRSA();        // default = pkcs1
  const sig = key.sign('msg');

  // v2.1 reproduction:
  const key = new NodeRSA(null, { signingScheme: 'pkcs1' });
  const sig = key.sign('msg');
  ```

  The bare-hash shorthand `setOptions({ signingScheme: 'sha256' })`
  also now resolves to `pss-sha256` (was `pkcs1-sha256`). Set
  `signingScheme: 'pkcs1-sha256'` explicitly to keep v2.0 behaviour.

### Security fixes (no API change)

- **OAEP decode is now constant-time** (RFC 8017 §7.1.2). Closes a Manger-
  style padding-oracle (~10⁵ queries to recover plaintext given a timing
  oracle). Includes a missing `Y == 0x00` check on the leading byte and a
  post-decode message-length bound.
- **PKCS#1 v1.5 decode is now constant-time** internally (RFC 8017 §7.2.2,
  Bleichenbacher / ROBOT). Closes the internal differential timing oracle;
  the valid/invalid binary oracle inherent to PKCS#1 v1.5 remains — use
  OAEP for untrusted ciphertexts (the README has a security note).
- **PSS verify is now constant-time** (RFC 8017 §9.1.2 step 11).
- **Private-key operations are blinded** (Kocher 1996 / Brumley-Boneh
  2003 defence). Fresh `r ← random coprime to n` masks the variable-time
  `modPow` from any timing leak on `d`, `dmp1`, or `dmq1`.
- **Miller-Rabin uses CSPRNG witnesses** in [2, n-2] (was `Math.random()`
  over a 168-element fixed table — adversarial-pseudoprime risk) and now
  honours the caller's full round count (was silently halved). Keygen
  picks adaptive rounds by bit length per FIPS 186-4 Table C.3.
- **Public exponent validated on import**: `1 < e` with e odd
  (RFC 8017 §3.1).
- **RSA primitive bounds-check**: `0 ≤ x < n` enforced in both
  `$doPrivate` and `$doPublic` (RFC 8017 §3.2). `verify()` translates
  the resulting out-of-range error to "invalid signature" per §8.x.
- **Imported private keys are CRT-consistency-checked**: `n = p·q`,
  `dp ≡ d mod (p−1)`, `dq ≡ d mod (q−1)`, `q·coeff ≡ 1 mod p`,
  `e·dp ≡ 1 mod (p−1)`, `e·dq ≡ 1 mod (q−1)`. Closes a Boneh-DeMillo-
  Lipton fault-injection vector on crafted PEM/PKCS#8/OpenSSH files.
- **`generate(B)` refuses `B < 512`** (cryptographically broken) and
  emits a one-shot `console.warn` for `B < 2048` (below NIST SP 800-56B
  §6.1.6.2 minimum).
- **Fermat-distance defence**: keygen rejects p, q pairs with
  `|p − q| < 2^(B/2 − 100)` (FIPS 186-4 §B.3.6).
- **CRT recombination is branch-free**: removed the data-dependent
  `while (xp < xq) xp += p` loop.
- **OpenSSH parser hardening**: `SshReader.readString` bounds-checks
  before `subarray`; the two private-section checkints (`checkint1`,
  `checkint2`) are now validated for equality.
- **PKCS#8 parser hardening**: outer version validated against
  {0, 1} (RFC 5958 §2); inner PKCS#1 version restricted to two-prime
  (RFC 8017 §A.1.2); algorithm OID whitelist with clear diagnostics for
  PSS-only (1.2.840.113549.1.1.10) and OAEP-only (.1.1.7) misuse.

### Audit document

The full audit, peer review, and remediation plan live at
[`docs/security-audit-v2.1.md`](docs/security-audit-v2.1.md) (TBD —
to be moved into the repo before tagging).

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
