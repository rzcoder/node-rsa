import { generateKeyPairSync } from 'node:crypto';
import { fromBase64 } from '../crypto/bytes.js';
import type { RSAKey } from './key.js';

// One-shot guard mirroring RSAKey.generate's warning behaviour.
let warnedSmallKey = false;

function fromBase64Url(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (b64.length % 4)) % 4;
  return fromBase64(b64 + '='.repeat(pad));
}

/**
 * Populate `key` with a freshly-generated `bits`-bit RSA key whose public
 * exponent is `expHex` (hex string, e.g. `"010001"`). Uses
 * `node:crypto.generateKeyPairSync` — orders of magnitude faster than the
 * pure-JS Miller-Rabin path for keys ≥ 2048 bits (~50 ms vs ~2 s for
 * 2048-bit).
 *
 * Browser bundle has no equivalent; src/index.browser.ts doesn't wire this
 * factory and NodeRSA.generateKeyPair falls back to RSAKey.generate.
 */
export function nodeNativeKeygen(key: RSAKey, bits: number, expHex: string): void {
  if (bits < 512) {
    throw new Error(
      `Key size ${bits} bits is cryptographically broken (< 512); refusing to generate`,
    );
  }
  if (bits < 2048 && !warnedSmallKey) {
    warnedSmallKey = true;
    // eslint-disable-next-line no-console
    console.warn(
      `node-rsa: generating ${bits}-bit RSA key — below NIST SP 800-56B §6.1.6.2 minimum (2048 bits); not recommended for production`,
    );
  }

  const exp = Number.parseInt(expHex, 16);
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicExponent: exp,
  });
  const jwk = privateKey.export({ format: 'jwk' }) as {
    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qi: string;
  };

  key.setPrivate(
    fromBase64Url(jwk.n),
    exp,
    fromBase64Url(jwk.d),
    fromBase64Url(jwk.p),
    fromBase64Url(jwk.q),
    fromBase64Url(jwk.dp),
    fromBase64Url(jwk.dq),
    fromBase64Url(jwk.qi),
  );
}
