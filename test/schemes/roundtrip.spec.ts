import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerReader } from '../../src/asn1/index.js';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { fromUtf8 } from '../../src/crypto/bytes.js';
import { RSAKey } from '../../src/rsa/key.js';
import { SCHEMES, oaepScheme, pkcs1Scheme, pssScheme } from '../../src/schemes/index.js';
import type { SchemeOptions } from '../../src/schemes/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../../test/keys');

function loadDer(name: string): Uint8Array {
  const buf = readFileSync(resolve(keysDir, name));
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function loadPrivateKey(): RSAKey {
  const seq = new DerReader(loadDer('private_pkcs1.der')).readSequence();
  seq.readSmallInteger(); // version
  const n = seq.readInteger();
  const e = seq.readSmallInteger();
  const d = seq.readInteger();
  const p = seq.readInteger();
  const q = seq.readInteger();
  const dmp1 = seq.readInteger();
  const dmq1 = seq.readInteger();
  const coeff = seq.readInteger();
  const key = new RSAKey();
  key.setPrivate(n, e, d, p, q, dmp1, dmq1, coeff);
  return key;
}

function makeOptions(
  encryptionScheme: 'pkcs1' | 'pkcs1_oaep',
  signingScheme: 'pkcs1' | 'pss' = 'pkcs1',
): SchemeOptions {
  return {
    signingScheme,
    encryptionScheme,
    signingSchemeOptions: {},
    encryptionSchemeOptions: {},
    environment: 'node',
    backend: nodeBackend,
  };
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

describe('RSAKey loaded from PKCS#1 private fixture', () => {
  it('has the expected metrics', () => {
    const key = loadPrivateKey();
    expect(key.isPrivate()).toBe(true);
    expect(key.isPublic()).toBe(true);
    expect(key.isPublic(true)).toBe(false);
    expect(key.keySize).toBe(1024);
    expect(key.encryptedDataLength).toBe(128);
    expect(key.e).toBe(65537);
  });
});

describe('PKCS#1 v1.5 encrypt → decrypt round-trip', () => {
  const messages = [
    'hello world',
    '', // empty
    'a',
    'τέστ unicode 🚀',
    'A'.repeat(50),
  ];

  for (const text of messages) {
    it(`message "${text.slice(0, 20)}${text.length > 20 ? '…' : ''}"`, () => {
      const key = loadPrivateKey();
      const options = makeOptions('pkcs1');
      key.setOptions(options, SCHEMES);

      const msg = fromUtf8(text);
      const padded = key.encryptionScheme.encPad(msg);
      expect(padded.length).toBe(key.encryptedDataLength);
      const ct = key.$doPublic(new BigInteger(padded)).toBuffer(key.encryptedDataLength);
      expect(ct).not.toBeNull();
      expect((ct as Uint8Array).length).toBe(key.encryptedDataLength);

      const dec = key
        .$doPrivate(new BigInteger(ct as Uint8Array))
        .toBuffer(key.encryptedDataLength);
      expect(dec).not.toBeNull();
      const unpadded = key.encryptionScheme.encUnPad(dec as Uint8Array);
      expect(unpadded).not.toBeNull();
      expect(unpadded as Uint8Array).toEqual(msg);
    });
  }
});

describe('OAEP encrypt → decrypt round-trip', () => {
  it('default SHA-1 OAEP', () => {
    const key = loadPrivateKey();
    const options = makeOptions('pkcs1_oaep');
    key.setOptions(options, SCHEMES);

    const msg = fromUtf8('hello OAEP');
    const padded = key.encryptionScheme.encPad(msg);
    expect(padded.length).toBe(key.encryptedDataLength);
    const ct = key.$doPublic(new BigInteger(padded)).toBuffer(key.encryptedDataLength);
    const dec = key.$doPrivate(new BigInteger(ct as Uint8Array)).toBuffer(key.encryptedDataLength);
    const unpadded = key.encryptionScheme.encUnPad(dec as Uint8Array);
    expect(unpadded as Uint8Array).toEqual(msg);
  });

  // 1024-bit key supports OAEP up to: k - 2*hLen - 2.
  //   sha1   → 86 bytes  ✓
  //   sha256 → 62 bytes  ✓
  //   sha384 → 30 bytes  ✓
  //   sha512 → −2 bytes  ✗ (key too small; verified via expect-throw below)
  it.each(['sha256', 'sha384'] as const)('OAEP hash=%s', (h) => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1_oaep'),
      encryptionSchemeOptions: { hash: h },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8(`OAEP-${h}`);
    const padded = key.encryptionScheme.encPad(msg);
    expect(padded.length).toBe(key.encryptedDataLength);
    const ct = key.$doPublic(new BigInteger(padded)).toBuffer(key.encryptedDataLength);
    const dec = key.$doPrivate(new BigInteger(ct as Uint8Array)).toBuffer(key.encryptedDataLength);
    const unpadded = key.encryptionScheme.encUnPad(dec as Uint8Array);
    expect(unpadded as Uint8Array).toEqual(msg);
  });

  it('OAEP/sha512 refuses to pad on 1024-bit key (k=128 < 2·64+2)', () => {
    // RFC 8017 §7.1.1: encoding requires k ≥ 2hLen + 2. With sha512/hLen=64
    // and a 1024-bit key (k=128) the minimum is 130, so any encPad call —
    // even on empty input — must throw. Exercises the upper geometry guard.
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1_oaep'),
      encryptionSchemeOptions: { hash: 'sha512' },
    };
    key.setOptions(options, SCHEMES);
    expect(() => key.encryptionScheme.encPad(fromUtf8(''))).toThrow();
  });

  it('OAEP with custom label', () => {
    const key = loadPrivateKey();
    const label = fromUtf8('my-label');
    const options: SchemeOptions = {
      ...makeOptions('pkcs1_oaep'),
      encryptionSchemeOptions: { label },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8('labeled');
    const padded = key.encryptionScheme.encPad(msg);
    const ct = key.$doPublic(new BigInteger(padded)).toBuffer(key.encryptedDataLength);
    const dec = key.$doPrivate(new BigInteger(ct as Uint8Array)).toBuffer(key.encryptedDataLength);
    const unpadded = key.encryptionScheme.encUnPad(dec as Uint8Array);
    expect(unpadded as Uint8Array).toEqual(msg);
  });
});

describe('PKCS#1 v1.5 sign → verify round-trip', () => {
  it.each(['sha1', 'sha256', 'sha384', 'sha512'] as const)('hash=%s', (h) => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pkcs1'),
      signingSchemeOptions: { hash: h },
    };
    key.setOptions(options, SCHEMES);

    const msg = fromUtf8('hello pkcs1 signing');
    const sig = key.signingScheme.sign(msg);
    expect(sig.length).toBe(key.encryptedDataLength);
    expect(key.signingScheme.verify(msg, sig)).toBe(true);
    expect(key.signingScheme.verify(fromUtf8('tampered'), sig)).toBe(false);
  });
});

describe('PSS sign → verify round-trip', () => {
  it.each(['sha1', 'sha256', 'sha512'] as const)('hash=%s', (h) => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: h },
    };
    key.setOptions(options, SCHEMES);

    const msg = fromUtf8('hello pss signing');
    const sig = key.signingScheme.sign(msg);
    expect(sig.length).toBe(key.encryptedDataLength);
    expect(key.signingScheme.verify(msg, sig)).toBe(true);
    expect(key.signingScheme.verify(fromUtf8('tampered'), sig)).toBe(false);
  });

  it('PSS with saltLength=0 is deterministic-ish', () => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: 'sha256', saltLength: 0 },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8('zero-salt');
    const sig1 = key.signingScheme.sign(msg);
    const sig2 = key.signingScheme.sign(msg);
    expect(sig1).toEqual(sig2);
    expect(key.signingScheme.verify(msg, sig1)).toBe(true);
  });

  it.each(
    // RFC 3447 §9.1: saltLength ∈ {0, hLen}. hLen depends on hash, so verify
    // each explicitly — each branch traverses a different EM geometry (PS
    // padding length, separator position) in emsaPssEncode / emsaPssVerify.
    // sha512+saltLen=64 won't fit on a 1024-bit key (emLen=128 < 64+64+2);
    // covered by the explicit-geometry-failure test below.
    [
      ['sha1', 20],
      ['sha256', 32],
      ['sha384', 48],
    ] as const,
  )('PSS hash=%s saltLength=hLen=%i', (h, sLen) => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: h, saltLength: sLen },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8(`pss-${h}-saltLen-${sLen}`);
    const sig = key.signingScheme.sign(msg);
    expect(sig.length).toBe(key.encryptedDataLength);
    expect(key.signingScheme.verify(msg, sig)).toBe(true);
  });

  it('rejects a PSS signature with a single-byte flip', () => {
    // Hardens against any future refactor that swaps emsaPssVerify's
    // accumulated `bad` flag for an early return — verify must still come
    // back false for tampered signatures.
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: 'sha256' },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8('pss-tamper');
    const sig = key.signingScheme.sign(msg);
    // Walk a few representative positions: start (masked-bits region),
    // middle (PS / separator), tail (salt and trailer).
    for (const pos of [0, sig.length >> 2, sig.length >> 1, sig.length - 2, sig.length - 1]) {
      const tampered = new Uint8Array(sig);
      tampered[pos] = (tampered[pos] as number) ^ 0x01;
      expect(key.signingScheme.verify(msg, tampered), `flip at ${pos} should be rejected`).toBe(
        false,
      );
    }
  });

  it('rejects a PSS signature whose message was modified', () => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: 'sha256' },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8('original');
    const sig = key.signingScheme.sign(msg);
    expect(key.signingScheme.verify(fromUtf8('original2'), sig)).toBe(false);
    expect(key.signingScheme.verify(fromUtf8(''), sig)).toBe(false);
  });

  it('sha512+saltLen=64 fails to encode on 1024-bit key (geometry guard)', () => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: 'sha512', saltLength: 64 },
    };
    key.setOptions(options, SCHEMES);
    expect(() => key.signingScheme.sign(fromUtf8('x'))).toThrow();
  });

  it('rejects a truncated PSS signature without throwing', () => {
    // RFC 8017 §8.1.2 step 2.b: representation-out-of-range yields
    // "invalid signature" (not an exception). emsaPssVerify additionally
    // checks EM.length === emLen and returns false.
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1', 'pss'),
      signingSchemeOptions: { hash: 'sha256' },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8('truncate-me');
    const sig = key.signingScheme.sign(msg);
    expect(() => key.signingScheme.verify(msg, sig.subarray(0, sig.length - 1))).not.toThrow();
    expect(key.signingScheme.verify(msg, sig.subarray(0, sig.length - 1))).toBe(false);
  });
});

describe('scheme registry', () => {
  it('isEncryption', () => {
    expect(SCHEMES.pkcs1?.isEncryption).toBe(true);
    expect(SCHEMES.pkcs1_oaep?.isEncryption).toBe(true);
    expect(SCHEMES.pss?.isEncryption).toBe(false);
  });

  it('isSignature', () => {
    expect(SCHEMES.pkcs1?.isSignature).toBe(true);
    expect(SCHEMES.pkcs1_oaep?.isSignature).toBe(false);
    expect(SCHEMES.pss?.isSignature).toBe(true);
  });

  it('exports the scheme implementations', () => {
    expect(SCHEMES.pkcs1).toBe(pkcs1Scheme);
    expect(SCHEMES.pkcs1_oaep).toBe(oaepScheme);
    expect(SCHEMES.pss).toBe(pssScheme);
  });
});

describe('RSAKey errors', () => {
  it('setPrivate rejects empty modulus', () => {
    const key = new RSAKey();
    expect(() => key.setPrivate(new Uint8Array(0), 65537, new Uint8Array([1]))).toThrow();
  });

  it('setPublic rejects empty modulus', () => {
    const key = new RSAKey();
    expect(() => key.setPublic(new Uint8Array(0), 65537)).toThrow();
  });
});
