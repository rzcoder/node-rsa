# Node-RSA

[![npm version](https://img.shields.io/npm/v/node-rsa.svg)](https://www.npmjs.com/package/node-rsa)
[![CI](https://github.com/rzcoder/node-rsa/actions/workflows/ci.yml/badge.svg)](https://github.com/rzcoder/node-rsa/actions/workflows/ci.yml)
[![npm downloads](https://img.shields.io/npm/dm/node-rsa.svg)](https://www.npmjs.com/package/node-rsa)
[![license](https://img.shields.io/npm/l/node-rsa.svg)](https://github.com/rzcoder/node-rsa/blob/master/LICENSE)

RSA library for Node.js and browsers.

* Pure TypeScript
* Works in Node.js and modern browsers (no Buffer/crypto polyfills needed)
* Generating keys
* Encrypting and decrypting, with long-message support
* Signing and verifying

## Table of contents

* [Example](#example)
* [Installing](#installing)
* [Usage](#usage)
  * [Create instance](#create-instance)
  * [Import/Export keys](#importexport-keys)
  * [Properties](#properties)
  * [Encrypting/Decrypting](#encryptingdecrypting)
  * [Signing/Verifying](#signingverifying)
* [Browser usage](#browser-usage)
* [Security notes](#security-notes)
* [Migrating](#migrating)
* [Changelog](#changelog)
* [License](#license)
* [Acknowledgements](#acknowledgements)

## Example

```ts
import NodeRSA from 'node-rsa';

const key = new NodeRSA({ b: 2048 });

const text = 'Hello RSA!';
const encrypted = key.encrypt(text, 'base64');
console.log('encrypted:', encrypted);
const decrypted = key.decrypt(encrypted, 'utf8');
console.log('decrypted:', decrypted);
```

## Installing

```shell
npm install node-rsa
```
> <sub>Requires Node.js >= 20. For browsers, any bundler with conditional-exports support (Vite, Webpack 5, Rollup, esbuild, Parcel) picks the browser entry automatically.</sub>

### Testing

```shell
npm test
```

## Usage

### Create instance

```ts
import NodeRSA from 'node-rsa';

const key = new NodeRSA([keyData, [format]], [options]);
```

* `keyData` — `string | Uint8Array | object` — key data in one of the supported formats, or a generation spec.
* `format` — `string` — format id for importing the key. See [Import/Export](#importexport-keys).
* `options` — `object` — additional settings (below).

#### Options

You can pass options as the second/third constructor argument, or later via `key.setOptions()`.

* `environment` — `'node'` or `'browser'`. Auto-detected from the loaded bundle; the option mainly exists to force the pure-JS engine on Node (`setOptions({ environment: 'browser' })`), bypassing the `node:crypto` fast path — useful if you need PSS with a custom MGF.
* `bigIntImpl` — `'native'` or `'jsbn'`. The browser bundle defaults to native ES2020 `BigInt`; the Node bundle uses jsbn. Switch only **before** importing/generating a key; switching on a populated instance throws.
* `signingScheme` — scheme used for `sign` / `verify`. One of `'pss'` (default), `'pkcs1'`, or a `'scheme-hash'` shorthand (e.g. `'pkcs1-sha512'`). Object form is also accepted: `{ scheme: 'pss', hash: 'sha256', saltLength?: number, mgf?: MaskGenerationFunction }`. Default hash is `sha256`.
* `encryptionScheme` — padding scheme for `encrypt` / `decrypt`. One of `'pkcs1_oaep'` (default) or `'pkcs1'`. Object form: `{ scheme: 'pkcs1_oaep', hash: 'sha1', mgf?, label? }`. Default OAEP hash is `sha1`.

> *Note:* Supported hash algorithms are `'md5'`, `'ripemd160'`, `'sha1'`, `'sha256'`, `'sha512'` in both environments, plus `'md4'`, `'sha224'`, `'sha384'` on Node. `'md4'` additionally requires running Node with `--openssl-legacy-provider`.

#### Creating an "empty" key

```ts
const key = new NodeRSA();
```

#### Generate new 2048-bit key

```ts
const key = new NodeRSA({ b: 2048 });
```

Or:

```ts
key.generateKeyPair([bits], [exp]);
```

* `bits` — `number` — key size in bits. 2048 by default.
* `exp` — `number` — public exponent. 65537 by default.

#### Load key from PEM string

```ts
const key = new NodeRSA(
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIIBOQIBAAJAVY6quuzCwyOWzymJ7C4zXjeV/232wt2ZgJZ1kHzjI73wnhQ3WQcL\n' +
  'DFCSoi2lPUW8/zspk0qWvPdtp6Jg5Lu7hwIDAQABAkBEws9mQahZ6r1mq2zEm3D/\n' +
  'VM9BpV//xtd6p/G+eRCYBT2qshGx42ucdgZCYJptFoW+HEx/jtzWe74yK6jGIkWJ\n' +
  'AiEAoNAMsPqwWwTyjDZCo9iKvfIQvd3MWnmtFmjiHoPtjx0CIQCIMypAEEkZuQUi\n' +
  'pMoreJrOlLJWdc0bfhzNAJjxsTv/8wIgQG0ZqI3GubBxu9rBOAM5EoA4VNjXVigJ\n' +
  'QEEk1jTkp8ECIQCHhsoq90mWM/p9L5cQzLDWkTYoPI49Ji+Iemi2T5MRqwIgQl07\n' +
  'Es+KCn25OKXR/FJ5fu6A6A+MptABL3r8SEjlpLc=\n' +
  '-----END RSA PRIVATE KEY-----',
);
```

### Import/Export keys

```ts
key.importKey(keyData, [format]);
key.exportKey([format]);
```

* `keyData` — may be:
    * PEM string (or a `Uint8Array`/`Buffer` containing one)
    * `Uint8Array` containing raw DER
    * object with raw key components
* `format` — `string` — format id for import/export.

#### Format string syntax

`scheme-[key_type]-[output_type]`

**Scheme** — node-rsa supports several:

  * `'pkcs1'` — public PEM starts with `-----BEGIN RSA PUBLIC KEY-----`, private with `-----BEGIN RSA PRIVATE KEY-----`.
  * `'pkcs8'` — public PEM starts with `-----BEGIN PUBLIC KEY-----`, private with `-----BEGIN PRIVATE KEY-----`.
  * `'openssh'` — public starts with `ssh-rsa`, private with `-----BEGIN OPENSSH PRIVATE KEY-----`.
  * `'components'` — raw modulus/exponent and CRT params. For a private key all components must be present; for a public key only `n` and `e`. All components are `Uint8Array` except `e`, which may be `Uint8Array` or a plain `number`.

**Key type** — `'private'` (default) or `'public'`.

**Output type**:

 * `'pem'` — base64 PEM string with header/footer. Used by default.
 * `'der'` — `Uint8Array` of binary DER.

> *Note:* For import, if `keyData` is a PEM string (or a `Uint8Array` containing PEM), you can omit `format`. If it's raw DER, you must specify the format string.

**Shortcuts and examples**

 * `'private'` ≡ `'pkcs1'` ≡ `'pkcs1-private'` ≡ `'pkcs1-private-pem'` — private key, PKCS#1, PEM.
 * `'public'` ≡ `'pkcs8-public'` ≡ `'pkcs8-public-pem'` — public key, PKCS#8, PEM.
 * `'pkcs8'` ≡ `'pkcs8-private'` ≡ `'pkcs8-private-pem'` — private key, PKCS#8, PEM.
 * `'pkcs1-der'` ≡ `'pkcs1-private-der'` — private key, PKCS#1, binary DER.
 * `'pkcs8-public-der'` — public key, PKCS#8, binary DER.

**Code example**

```ts
const keyData = '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----';
key.importKey(keyData, 'pkcs8');
const publicDer = key.exportKey('pkcs8-public-der');
const privateDer = key.exportKey('pkcs1-der');
```

```ts
const hex = (s: string) =>
  Uint8Array.from(s.match(/.{2}/g)!.map((b) => parseInt(b, 16)));

key.importKey({
  n: hex('0086fa9ba066685845fc03833a9699c8baefb53cfbf19052a7f10f1eaa30488cec1ceb752bdff2df9fad6c64b3498956e7dbab4035b4823c99a44cc57088a23783'),
  e: 65537,
  d: hex('5d2f0dd982596ef781affb1cab73a77c46985c6da2aafc252cea3f4546e80f40c0e247d7d9467750ea1321cc5aa638871b3ed96d19dcc124916b0bcb296f35e1'),
  p: hex('00c59419db615e56b9805cc45673a32d278917534804171edcf925ab1df203927f'),
  q: hex('00aee3f86b66087abc069b8b1736e38ad6af624f7ea80e70b95f4ff2bf77cd90fd'),
  dmp1: hex('008112f5a969fcb56f4e3a4c51a60dcdebec157ee4a7376b843487b53844e8ac85'),
  dmq1: hex('1a7370470e0f8a4095df40922a430fe498720e03e1f70d257c3ce34202249d21'),
  coeff: hex('00b399675e5e81506b729a777cc03026f0b2119853dfc5eb124610c0ab82999e45'),
}, 'components');

const publicComponents = key.exportKey('components-public');
console.log(publicComponents);

/*
{ n: Uint8Array(65) [0, 134, 250, 155, 160, 102, 104, 88, 69, 252, 3, 131, 58, ... ],
  e: 65537 }
*/
```

To import only the public part use `'components-public'`:

```ts
key.importKey({
  n: hex('0086fa9ba066685845fc03833a9699c8baefb53cfbf19052a7f10f1eaa30488cec1ceb752bdff2df9fad6c64b3498956e7dbab4035b4823c99a44cc57088a23783'),
  e: 65537,
}, 'components-public');
```

> *Note:* `Buffer` is a `Uint8Array` subclass on Node, so any code that passes `Buffer.from(...)` still works — the types document the cross-platform shape.

### Properties

#### Key testing
```ts
key.isPrivate();
key.isPublic([strict]);
```
`strict` — `boolean` — if `true`, returns `false` when the key pair also contains a private exponent. Default `false`.

```ts
key.isEmpty();
```
Returns `true` if the instance has no key data.

#### Key info
```ts
key.getKeySize();
```
Returns key size in bits.

```ts
key.getMaxMessageSize();
```
Returns the max data size for a single encrypt operation, in bytes (scheme-dependent).

### Encrypting/Decrypting

```ts
key.encrypt(buffer, [encoding], [source_encoding]);
key.encryptPrivate(buffer, [encoding], [source_encoding]); // encrypt with private key
```
Returns the encrypted data.

* `buffer` — data to encrypt. May be `string`, `Uint8Array` (or `Buffer` on Node), `number`, plain object, or array. Objects and arrays are JSON-stringified first.
* `encoding` — output encoding: `'buffer'` (default — returns `Uint8Array`), `'binary'`, `'hex'`, or `'base64'`.
* `source_encoding` — only used when `buffer` is a string; how to interpret its bytes. Accepts `'utf8'` (default), `'hex'`, `'base64'`, `'binary'`.

```ts
key.decrypt(buffer, [encoding]);
key.decryptPublic(buffer, [encoding]); // decrypt with public key
```
Returns the decrypted data.

* `buffer` — `Uint8Array` or base64-encoded string.
* `encoding` — output: `'buffer'` (default, raw `Uint8Array`), `'utf8'`, `'hex'`, `'base64'`, `'binary'`, or `'json'` (UTF-8 decoded + `JSON.parse`).

> *Note:* `encryptPrivate` / `decryptPublic` always use PKCS#1 v1.5 type-1 padding (deterministic), regardless of the configured `encryptionScheme`.

### Signing/Verifying
```ts
key.sign(buffer, [encoding], [source_encoding]);
```
Returns the signature. All arguments behave like `encrypt`.

```ts
key.verify(buffer, signature, [source_encoding], [signature_encoding]);
```
Returns `true` / `false`.

* `buffer` — data that was signed; same shape as for `encrypt`.
* `signature` — `Uint8Array` or string, as produced by `sign`.
* `source_encoding` — encoding for `buffer` if it's a string. Default `'utf8'`.
* `signature_encoding` — encoding of `signature`. One of `'buffer'` (default), `'binary'`, `'hex'`, `'base64'`.

## Browser usage

The browser bundle (`dist/index.browser.js`) is published as ESM only and contains no Node-builtin imports — you don't need to polyfill Buffer, crypto, or process. Bundlers that honour the `"browser"` export condition (Vite, Webpack 5, Rollup, esbuild, Parcel) pick it up automatically. The bundle weighs ~114 KB raw / ~28 KB gzipped.

If your bundler doesn't resolve conditional exports, import the browser entry directly:

```ts
import NodeRSA from 'node-rsa/dist/index.browser.js';
```

## Security notes

* **PKCS#1 v1.5 encryption** (`encryptionScheme: 'pkcs1'`) is vulnerable to Bleichenbacher-style padding-oracle attacks when used to decrypt attacker-controlled ciphertexts. The library closes the internal differential timing channel but cannot eliminate the binary valid/invalid oracle inherent to the scheme. Use the default `'pkcs1_oaep'` for new code and for any path that touches attacker-controlled ciphertext.

## Migrating

Migrating from 1.x? See [MIGRATION.md](MIGRATION.md) for the behaviour-change summary and step-by-step walkthrough.

## Changelog

Release notes and per-version changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

Copyright (c) 2014 rzcoder

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Licensing for code used in rsa.ts and jsbn

Copyright (c) 2003-2005 Tom Wu
All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

In addition, the following condition applies:

All redistributions must retain an intact copy of this copyright notice
and disclaimer.

## Acknowledgements

* Tom Wu — original [jsbn](http://www-cs-students.stanford.edu/~tjw/jsbn/) BigInteger and RSA implementations
* Paul Miller — [@noble/hashes](https://github.com/paulmillr/noble-hashes) v2.x, audited synchronous hash functions (MD5, RIPEMD-160, SHA-1/2 family) used by the browser bundle
