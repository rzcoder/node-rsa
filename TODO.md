# TODO — post-v2.0

Tracked work that was scoped out of v2.0.0 to keep the rewrite focused.

## v2.1 candidates

- [x] **Native `BigInt` backend** _(shipped in v2.1)_. The audited jsbn
  implementation still ships as the default on Node; the browser bundle
  flips to native at module load. Selectable per-instance via
  `new NodeRSA(key, { bigIntImpl: 'jsbn' | 'native' })`. ~4× faster on the
  JS sign/verify path (the predicted 10× keygen speedup mostly landed via
  `crypto.generateKeyPairSync` instead — see CHANGELOG). Per-key BI
  pinning lets two NodeRSA instances with different impls coexist in one
  process.

- [ ] **`generateKeyPairAsync`**. On Node the urgency dropped — keygen now
  goes through `crypto.generateKeyPairSync` and returns in ~50 ms at
  2048-bit. The remaining motivation is the browser bundle, where keygen
  is still a multi-hundred-ms blocking loop. Add an async variant that
  cooperates via `setTimeout(0)` every N Miller-Rabin trials. Non-
  breaking; existing sync method stays.

- [ ] **Async `sign` / `verify` / `encrypt` / `decrypt`**. Lets browser
  consumers integrate with the async `SubtleCrypto.{sign,verify,encrypt,
  decrypt}` APIs for their native SHA-2/RSA implementations. Node's
  fast-path is already wired through synchronous `crypto.{sign,verify,
  publicEncrypt,privateDecrypt}` calls so the Node motivation is weaker.

- [x] **Vite + Playwright browser example** _(shipped in v2.1)_. Lives at
  [`examples/vite-browser/`](examples/vite-browser/). Vite serves a page
  that runs keygen + OAEP encrypt/decrypt + PSS sign/verify + PEM round-
  trip against the browser bundle; Playwright drives Chromium and asserts
  on both the DOM and a `window.__rsaResults` payload. Not wired into
  `npm run check` because it would pull a ~100 MB Chromium download into
  CI; opt-in via `cd examples/vite-browser && npm test`.

- [ ] **Stream encryption / decryption**. Some v1 issues request stream-
  shaped APIs for large files. Would benefit from chunked engine work.

## v2.x housekeeping

- [x] ~~Drop the temporary `asn1` devDep used by the `legacy-parity` test
  files once the legacy parity tests are removed~~ — completed in v2.0.0
  (the `src.legacy/` tree was deleted on the release commit; the `asn1`
  devDep is no longer in `package.json`).

- [ ] Consider re-enabling MD4 support on Node by attempting
  `setProvider('legacy')` once at module load behind an opt-in flag.

- [x] **Audit the `pkcs8` BIT STRING export** _(shipped in v2.1)_. Pinned
  in [`test/formats/pkcs8-bitstring.spec.ts`](test/formats/pkcs8-bitstring.spec.ts):
  the in-tree writer always emits an unused-bits byte of `0x00` (no
  caller-tunable parameter), the reader strict-rejects non-zero unused-
  bits with a clear diagnostic (rather than silently masking as the
  legacy `asn1` package did), and SPKI round-trip is byte-identical to
  OpenSSL's `pkey -pubout` output for every fixture.
