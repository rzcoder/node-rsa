import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import NodeRSA from '../../src/index.node.js';
import { RSAKey } from '../../src/rsa/key.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

/** Convert a BigInteger to its big-endian byte representation. */
function toBytes(b: BigInteger): Uint8Array {
  return b.toBuffer() as Uint8Array;
}

describe('H1 — public exponent validation on import', () => {
  // We reuse the valid n from a real fixture; only e varies.
  const validKey = (): NodeRSA => new NodeRSA(readStr('private_pkcs1.pem'));
  const validN = (): Uint8Array => toBytes(validKey().keyPair.n!);

  it('rejects e = 0', () => {
    const k = new RSAKey();
    expect(() => k.setPublic(validN(), 0)).toThrow(/e must be > 1/);
  });

  it('rejects e = 1 (ciphertext == plaintext)', () => {
    const k = new RSAKey();
    expect(() => k.setPublic(validN(), 1)).toThrow(/e must be > 1/);
  });

  it('rejects even e = 2 (breaks RSA invertibility)', () => {
    const k = new RSAKey();
    expect(() => k.setPublic(validN(), 2)).toThrow(/e must be odd/);
  });

  it('rejects even e = 4', () => {
    const k = new RSAKey();
    expect(() => k.setPublic(validN(), 4)).toThrow(/e must be odd/);
  });

  it('accepts canonical e = 65537', () => {
    const k = new RSAKey();
    expect(() => k.setPublic(validN(), 65537)).not.toThrow();
  });

  it('accepts e = 3 (uncommon but legal)', () => {
    const k = new RSAKey();
    expect(() => k.setPublic(validN(), 3)).not.toThrow();
  });
});

describe('H2 — RSA primitive input bounds', () => {
  it('$doPublic throws when x >= n', () => {
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    // x = n is the boundary; RFC requires 0 <= x < n.
    expect(() => k.keyPair.$doPublic(k.keyPair.n!)).toThrow(/out of range/);
  });

  it('$doPublic throws when x = n + 1', () => {
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    const nPlusOne = k.keyPair.n!.add(BigInteger.ONE);
    expect(() => k.keyPair.$doPublic(nPlusOne)).toThrow(/out of range/);
  });

  it('$doPrivate throws when x >= n', () => {
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    expect(() => k.keyPair.$doPrivate(k.keyPair.n!)).toThrow(/out of range/);
  });

  it('$doPublic accepts x in [0, n)', () => {
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    const small = new BigInteger(Uint8Array.of(0x42));
    expect(() => k.keyPair.$doPublic(small)).not.toThrow();
  });
});

describe('H3 — private key CRT consistency validation', () => {
  function loadComponents(): {
    n: Uint8Array;
    e: number;
    d: Uint8Array;
    p: Uint8Array;
    q: Uint8Array;
    dmp1: Uint8Array;
    dmq1: Uint8Array;
    coeff: Uint8Array;
  } {
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    const kp = k.keyPair;
    return {
      n: toBytes(kp.n!),
      e: kp.e,
      d: toBytes(kp.d!),
      p: toBytes(kp.p!),
      q: toBytes(kp.q!),
      dmp1: toBytes(kp.dmp1!),
      dmq1: toBytes(kp.dmq1!),
      coeff: toBytes(kp.coeff!),
    };
  }

  function flipLastByte(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(bytes);
    out[out.length - 1] ^= 0x01;
    return out;
  }

  it('rejects key where n != p × q', () => {
    const c = loadComponents();
    const k = new RSAKey();
    expect(() =>
      k.setPrivate(flipLastByte(c.n), c.e, c.d, c.p, c.q, c.dmp1, c.dmq1, c.coeff),
    ).toThrow(/n ≠ p × q/);
  });

  it('rejects key where dp != d mod (p − 1)', () => {
    const c = loadComponents();
    const k = new RSAKey();
    expect(() =>
      k.setPrivate(c.n, c.e, c.d, c.p, c.q, flipLastByte(c.dmp1), c.dmq1, c.coeff),
    ).toThrow(/dp ≠ d mod/);
  });

  it('rejects key where dq != d mod (q − 1)', () => {
    const c = loadComponents();
    const k = new RSAKey();
    expect(() =>
      k.setPrivate(c.n, c.e, c.d, c.p, c.q, c.dmp1, flipLastByte(c.dmq1), c.coeff),
    ).toThrow(/dq ≠ d mod/);
  });

  it('rejects key where q × coeff ≢ 1 (mod p)', () => {
    const c = loadComponents();
    const k = new RSAKey();
    expect(() =>
      k.setPrivate(c.n, c.e, c.d, c.p, c.q, c.dmp1, c.dmq1, flipLastByte(c.coeff)),
    ).toThrow(/q × coeff ≢ 1/);
  });

  it('accepts the unmodified valid key', () => {
    const c = loadComponents();
    const k = new RSAKey();
    expect(() => k.setPrivate(c.n, c.e, c.d, c.p, c.q, c.dmp1, c.dmq1, c.coeff)).not.toThrow();
  });

  it('skips CRT validation when CRT components are absent', () => {
    // Basic n, e, d key (no p, q, dp, dq, coeff). Validation should be
    // skipped since we can't cross-check without the primes.
    const c = loadComponents();
    const k = new RSAKey();
    expect(() => k.setPrivate(c.n, c.e, c.d)).not.toThrow();
  });
});

describe('H5 — minimum key size guard on generate', () => {
  it('refuses B = 256 (cryptographically broken)', () => {
    expect(() => new NodeRSA({ b: 256 })).toThrow(/cryptographically broken/);
  });

  it('refuses B = 128', () => {
    expect(() => new NodeRSA({ b: 128 })).toThrow(/cryptographically broken/);
  });

  it('refuses B = 504 (just below the 512 threshold, multiple of 8)', () => {
    expect(() => new NodeRSA({ b: 504 })).toThrow(/cryptographically broken/);
  });

  it('accepts B = 512 (legal but warned)', () => {
    // 512-bit keys emit a one-shot console.warn but are not rejected; the
    // legacy test suite uses them for speed.
    expect(() => new NodeRSA({ b: 512 })).not.toThrow();
  });
});
