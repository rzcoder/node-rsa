# TODO — post-v2.0

Tracked work that was scoped out of v2.0.0 to keep the rewrite focused.

## v2.1 candidates

- [ ] **Native `BigInt` backend**. Currently the BigInteger implementation
  is a faithful port of Tom Wu's jsbn (digit base 2^28, ~1500 LOC). A native-
  `BigInt`-backed implementation would be ~10× faster on keygen and shrink
  the bundle by ~30 KB. Risk: Miller-Rabin's RNG ordering on a different
  representation can diverge from v1; needs deterministic-seed parity tests
  before swap.

- [ ] **`generateKeyPairAsync`**. The synchronous `generateKeyPair` blocks
  the event loop for several seconds at 2048 bits — fine on Node, lethal in
  the browser. Add an async variant that cooperates via `setTimeout(0)`
  every N Miller-Rabin trials. Non-breaking; existing sync method stays.

- [ ] **Async `sign` / `verify` / `encrypt` / `decrypt`**. Lets Node
  consumers opt into the native fast-path even for schemes that currently
  fall back to JS, and lets browser consumers integrate with the async
  `SubtleCrypto.digest` API (using its native SHA-2 implementations).

- [ ] **Vite + Playwright browser example**. v2 has Node CJS/ESM example
  consumers and a CI bundle-hygiene grep; adding a real browser end-to-end
  test would close the loop. Stub directory: `examples/vite-browser/`.

- [ ] **Stream encryption / decryption**. Some v1 issues request stream-
  shaped APIs for large files. Would benefit from chunked engine work.

## v2.x housekeeping

- [ ] Drop the temporary `asn1` devDep used by the `legacy-parity` test
  files once the legacy parity tests are removed (they only run while v1's
  source lives at `src.legacy/`, and Chapter 11 of the rewrite deletes that
  tree).

- [ ] Consider re-enabling MD4 support on Node by attempting
  `setProvider('legacy')` once at module load behind an opt-in flag.

- [ ] Audit the `pkcs8` BIT STRING export — v1 produced byte-identical
  output for every fixture, but the legacy `asn1` package and our in-tree
  writer differ on one corner case (BIT STRING with non-zero unused bits)
  that no v1 caller exercised. Document the behaviour or add a guard.
