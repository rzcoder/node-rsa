# node-rsa

RSA library for Node.js and modern browsers. Originally based on Tom Wu's [jsbn](http://www-cs-students.stanford.edu/~tjw/jsbn/).

* TypeScript + ESM-first, dual ESM/CJS package
* Same public API as v1 — drop-in upgrade for most consumers
* Works in browsers with **no** Node-builtin shims (no Buffer, no crypto, no fs)
* Node bundle uses `node:crypto` for hashing, RNG, and public-key fast path
* Generate / import / export PKCS#1, PKCS#8, OpenSSH; raw component access
* PKCS#1 v1.5, OAEP, and PSS schemes; long-message chunked encryption
* Sign and verify with MD5/SHA-1/224/256/384/512/RIPEMD-160

> **Looking for v1?** Install `node-rsa@^1.1` — v1 docs are in the `v1` branch.

## Install

```bash
npm install node-rsa
```

> Requires **Node.js ≥ 20**. For modern browsers, any bundler with conditional-exports support (Vite, Webpack 5, Rollup, esbuild, Parcel) will pick up the browser entry automatically.

## Quick start

```ts
import NodeRSA from 'node-rsa';

const key = new NodeRSA({ b: 2048 });

const ciphertext = key.encrypt('Hello, RSA!', 'base64');
const plaintext = key.decrypt(ciphertext, 'utf8');     // 'Hello, RSA!'

const signature = key.sign('payload');
const valid = key.verify('payload', signature);        // true
```

Browser (any modern bundler):

```ts
import NodeRSA from 'node-rsa';

const key = new NodeRSA(pemString);
const ct = key.encrypt('secret');   // Uint8Array
```

## API

The full v1 surface is preserved. See the in-package types or the
[v1 docs](https://github.com/rzcoder/node-rsa/blob/v1/README.md) for method
references — every method, format string, and option keeps the same name and
semantics.

Key methods on `NodeRSA`:

| Method | Description |
|---|---|
| `new NodeRSA(key?, format?, options?)` | Construct from PEM/DER/components, or `{b:bits, e:exp}` to generate |
| `generateKeyPair(bits, exp)` | Generate a fresh key pair |
| `importKey(data, format)` | Import (auto-detects format if omitted) |
| `exportKey(format)` | Export — `'pkcs1-private-pem'`, `'pkcs8-public-der'`, `'openssh-private'`, `'components'`, etc. |
| `setOptions({ signingScheme, encryptionScheme, ... })` | Update scheme/hash/padding |
| `encrypt`, `decrypt`, `encryptPrivate`, `decryptPublic` | With optional `encoding`/`source_encoding` for `'hex'`/`'base64'`/`'utf8'`/`'json'`/`'buffer'` |
| `sign`, `verify` | Same encoding params as encrypt; verify returns boolean |
| `isPrivate`, `isPublic(strict?)`, `isEmpty` | Predicates |
| `getKeySize`, `getMaxMessageSize` | Key metrics |

## Behaviour changes from v1

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

A migration walkthrough is in [`MIGRATION.md`](MIGRATION.md).

## Browser compatibility

The browser bundle (`dist/index.browser.js`) is published as ESM only and
contains no Node-builtin imports. Bundlers that honour the `"browser"` export
condition (Vite, Webpack 5, Rollup, esbuild, Parcel) will pick it up
automatically. The bundle currently weighs **~90 KB** raw / **~21 KB**
gzipped.

If you target older bundlers that don't resolve conditional exports, you can
import the browser entry directly:

```ts
import NodeRSA from 'node-rsa/dist/index.browser.js';
```

## Schemes & hash algorithms

* **Encryption**: `pkcs1` (v1.5 — see security note below), `pkcs1_oaep`
  (default), or `pkcs1` with `padding: 3` for RSA_NO_PADDING.
* **Signing**: `pss` (default, hash sha256), `pkcs1` (PKCS#1 v1.5, hash
  sha256). The default was `pkcs1` in v1 and v2.0; v2.1 switched it to
  `pss` — see CHANGELOG and MIGRATION for details.
* **Hashes (Node)**: md5, ripemd160, sha1, sha224, sha256, sha384, sha512.
  MD4 is supported only if OpenSSL's legacy provider is loaded
  (`node --openssl-legacy-provider`) and is unavailable in the browser
  bundle entirely.
* **Hashes (browser)**: md5, ripemd160, sha1, sha256, sha384, sha512.

## Security notes

* **PKCS#1 v1.5 encryption** (`encryptionScheme: 'pkcs1'`) is vulnerable to
  Bleichenbacher-style padding-oracle attacks if used to decrypt untrusted
  ciphertexts. The library closes the internal differential timing leak but
  cannot eliminate the binary valid/invalid oracle inherent to the scheme.
  Use `pkcs1_oaep` (the default) for new code and any path that handles
  attacker-controlled ciphertexts.
* **Private operations are blinded** (Kocher 1996 defence) to mask the
  variable-time `modPow` from timing attackers. In Node, the native engine
  also routes through OpenSSL's constant-time path where available. In the
  browser, the pure-JS `modPow` is not strictly constant-time even with
  blinding — avoid this library for long-lived server keys exposed to
  shared-CPU attackers.

## Versioning

Semantic versioning. v2.0.0 is a major release with the breaking changes
listed above; subsequent minor releases will be backwards-compatible within
the v2 API.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgements

* Tom Wu — original [jsbn](http://www-cs-students.stanford.edu/~tjw/jsbn/) BigInteger and RSA implementations
* [@noble/hashes](https://github.com/paulmillr/noble-hashes) — synchronous browser-side hash functions
