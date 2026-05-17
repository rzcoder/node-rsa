import { describe, expect, it } from 'vitest';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { webBackend } from '../../src/crypto/backend.web.js';
import { toHex } from '../../src/crypto/bytes.js';
import { DIGEST_LENGTH } from '../../src/crypto/digest-length.js';
import type { HashingAlgorithm } from '../../src/crypto/types.js';

// The vitest workspace aliases backend.node → backend.web in the
// browser-emulated project, so `nodeBackend` here resolves to whichever
// backend the project under test should exercise. Test vectors are universal.

const EMPTY = new Uint8Array(0);
const ABC = new TextEncoder().encode('abc');
const QUICK = new TextEncoder().encode('The quick brown fox jumps over the lazy dog');

// Known test vectors from RFCs / FIPS publications.
const VECTORS: Partial<Record<HashingAlgorithm, { empty: string; abc: string; quick: string }>> = {
  md5: {
    empty: 'd41d8cd98f00b204e9800998ecf8427e',
    abc: '900150983cd24fb0d6963f7d28e17f72',
    quick: '9e107d9d372bb6826bd81d3542a419d6',
  },
  sha1: {
    empty: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    abc: 'a9993e364706816aba3e25717850c26c9cd0d89d',
    quick: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
  },
  sha224: {
    empty: 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
    abc: '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
    quick: '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525',
  },
  sha256: {
    empty: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    abc: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    quick: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
  },
  sha384: {
    empty:
      '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
    abc: 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    quick:
      'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1',
  },
  sha512: {
    empty:
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
    abc: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    quick:
      '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6',
  },
  ripemd160: {
    empty: '9c1185a5c5e9fc54612808977ee8f548b2258d31',
    abc: '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc',
    quick: '37f332f68db77bd9d7edd4969571ad671cf9dd3b',
  },
};

describe('digest test vectors', () => {
  for (const [alg, vec] of Object.entries(VECTORS) as Array<
    [HashingAlgorithm, NonNullable<(typeof VECTORS)[HashingAlgorithm]>]
  >) {
    describe(alg, () => {
      it.skipIf(!nodeBackend.supportsHash(alg))(`empty: ${vec.empty.slice(0, 16)}…`, () => {
        const out = nodeBackend.digest(alg, EMPTY);
        expect(out.length).toBe(DIGEST_LENGTH[alg]);
        expect(toHex(out)).toBe(vec.empty);
      });

      it.skipIf(!nodeBackend.supportsHash(alg))(`"abc": ${vec.abc.slice(0, 16)}…`, () => {
        const out = nodeBackend.digest(alg, ABC);
        expect(toHex(out)).toBe(vec.abc);
      });

      it.skipIf(!nodeBackend.supportsHash(alg))(`fox: ${vec.quick.slice(0, 16)}…`, () => {
        const out = nodeBackend.digest(alg, QUICK);
        expect(toHex(out)).toBe(vec.quick);
      });
    });
  }
});

describe('digest output length', () => {
  for (const alg of Object.keys(DIGEST_LENGTH) as HashingAlgorithm[]) {
    it.skipIf(!nodeBackend.supportsHash(alg))(`${alg} → ${DIGEST_LENGTH[alg]} bytes`, () => {
      const out = nodeBackend.digest(alg, new Uint8Array([1, 2, 3, 4, 5]));
      expect(out.length).toBe(DIGEST_LENGTH[alg]);
    });
  }
});

describe('digest determinism', () => {
  it('same input → same output (sha256)', () => {
    const a = nodeBackend.digest('sha256', QUICK);
    const b = nodeBackend.digest('sha256', QUICK);
    expect(toHex(a)).toBe(toHex(b));
  });
});

describe('digest error cases', () => {
  it('rejects an unknown algorithm', () => {
    expect(() => nodeBackend.digest('sha999' as HashingAlgorithm, EMPTY)).toThrow();
  });
});

/**
 * Hash functions process data in fixed-size blocks (SHA-1/224/256 = 64 B,
 * SHA-384/512 = 128 B), buffering partial blocks internally. Bugs around
 * the "exactly one block", "one block plus one byte", and "block-aligned
 * across multiple blocks" cases are common when implementing or porting
 * a hash (e.g., an off-by-one in the length-encoded padding step).
 *
 * We don't have NIST vectors at these exact sizes, but we can use the
 * backend as its own oracle: the digest must equal a chunked re-hash
 * implementation only if the impl is correct. Since we don't expose an
 * update/finalize API, we just verify the digest is stable (same input
 * → same output) and length-correct across block boundaries — a
 * non-trivial assertion if a future refactor breaks the chunking.
 */
describe('digest block-boundary inputs', () => {
  const BLOCK: Partial<Record<HashingAlgorithm, number>> = {
    md5: 64,
    sha1: 64,
    sha224: 64,
    sha256: 64,
    sha384: 128,
    sha512: 128,
    ripemd160: 64,
  };

  function makeBuf(n: number, seed: number): Uint8Array {
    // Deterministic pseudo-random fill (LCG) so the test is reproducible.
    const out = new Uint8Array(n);
    let s = seed | 0;
    for (let i = 0; i < n; i++) {
      s = (s * 1103515245 + 12345) & 0x7fffffff;
      out[i] = s & 0xff;
    }
    return out;
  }

  for (const [alg, block] of Object.entries(BLOCK) as Array<[HashingAlgorithm, number]>) {
    it.skipIf(!nodeBackend.supportsHash(alg))(
      `${alg}: ${block - 1}/${block}/${block + 1}/${2 * block} bytes — stable and correct length`,
      () => {
        for (const n of [block - 1, block, block + 1, 2 * block - 1, 2 * block, 2 * block + 1]) {
          const data = makeBuf(n, n * 7);
          const a = nodeBackend.digest(alg, data);
          const b = nodeBackend.digest(alg, data);
          expect(a.length, `length for n=${n}`).toBe(DIGEST_LENGTH[alg]);
          expect(toHex(b)).toBe(toHex(a));
          // A truncated input must yield a different digest from the full
          // one — catches a regression that drops trailing bytes.
          if (n > 1) {
            const cut = nodeBackend.digest(alg, data.subarray(0, n - 1));
            expect(toHex(cut)).not.toBe(toHex(a));
          }
        }
      },
    );
  }

  it.skipIf(!nodeBackend.supportsHash('sha256'))(
    'sha256: 1-byte difference at the block boundary produces a different digest',
    () => {
      // Last byte before the 64-byte boundary mutated vs first byte of the
      // next block — both must produce digests distinct from the canonical.
      const base = makeBuf(64, 1);
      const ref = toHex(nodeBackend.digest('sha256', base));
      const a = new Uint8Array(base);
      a[63] = (a[63] as number) ^ 0x01;
      expect(toHex(nodeBackend.digest('sha256', a))).not.toBe(ref);
      const extra = new Uint8Array(65);
      extra.set(base);
      // Adding a single zero byte yields a different hash too.
      expect(toHex(nodeBackend.digest('sha256', extra))).not.toBe(ref);
    },
  );
});

/**
 * The vitest workspace alias maps src/crypto/backend.node.ts →
 * src/crypto/backend.web.ts in the `browser-emulated` project. A broken
 * alias would silently let the node backend serve `browser-emulated`,
 * defeating the dual-backend coverage. Detect the active workspace by
 * importing both backends explicitly: when the alias is live, the two
 * identifiers are the same reference; when it's not, they differ.
 */
describe('backend identity (workspace-alias smoke)', () => {
  const aliasActive = nodeBackend === webBackend;
  it('alias is active iff nodeBackend resolves to webBackend', () => {
    // Both states are legitimate (one per workspace); we just confirm the
    // identity matches the .name field — i.e. if alias is active, .name
    // says 'web'; otherwise 'node'.
    if (aliasActive) {
      expect(nodeBackend.name).toBe('web');
    } else {
      expect(nodeBackend.name).toBe('node');
    }
  });

  it('webBackend.name is always "web" (no aliasing in the other direction)', () => {
    expect(webBackend.name).toBe('web');
  });
});
