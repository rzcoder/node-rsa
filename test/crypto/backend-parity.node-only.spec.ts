import { describe, expect, it } from 'vitest';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { webBackend } from '../../src/crypto/backend.web.js';
import { toHex } from '../../src/crypto/bytes.js';
import type { HashAlg } from '../../src/crypto/types.js';

// Only runs in the 'node' workspace project. The 'browser-emulated' project
// excludes *.node-only.spec.ts because its alias substitutes backend.node
// with backend.web, which would make the comparison trivial.

const CROSS_PLATFORM_HASHES: HashAlg[] = [
  'md5',
  'ripemd160',
  'sha1',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
];

const CORPUS: Uint8Array[] = [
  new Uint8Array(0),
  new TextEncoder().encode('a'),
  new TextEncoder().encode('abc'),
  new TextEncoder().encode('The quick brown fox jumps over the lazy dog'),
  (() => {
    const big = new Uint8Array(10_000);
    for (let i = 0; i < big.length; i++) big[i] = (i * 7 + 3) & 0xff;
    return big;
  })(),
];

describe('node vs. web backend parity', () => {
  for (const alg of CROSS_PLATFORM_HASHES) {
    describe(alg, () => {
      CORPUS.forEach((data, i) => {
        it(`input #${i} (len=${data.length}) digests match`, () => {
          const a = toHex(nodeBackend.digest(alg, data));
          const b = toHex(webBackend.digest(alg, data));
          expect(a).toBe(b);
        });
      });
    });
  }

  it('md4 is never supported by the web backend', () => {
    // Node support is OpenSSL-config dependent (OpenSSL 3 needs the legacy
    // provider loaded). Web backend never supports MD4.
    expect(webBackend.supportsHash('md4')).toBe(false);
    expect(() => webBackend.digest('md4', new Uint8Array(0))).toThrow(/MD4/);
  });

  it('backends advertise their name', () => {
    expect(nodeBackend.name).toBe('node');
    expect(webBackend.name).toBe('web');
  });
});
