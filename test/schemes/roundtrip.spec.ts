import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerReader } from '../../src/asn1/index.js';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { equals, fromUtf8 } from '../../src/crypto/bytes.js';
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
      expect(equals(unpadded as Uint8Array, msg)).toBe(true);
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
    expect(equals(unpadded as Uint8Array, msg)).toBe(true);
  });

  it('OAEP with sha256', () => {
    const key = loadPrivateKey();
    const options: SchemeOptions = {
      ...makeOptions('pkcs1_oaep'),
      encryptionSchemeOptions: { hash: 'sha256' },
    };
    key.setOptions(options, SCHEMES);
    const msg = fromUtf8('OAEP-SHA256');
    const padded = key.encryptionScheme.encPad(msg);
    const ct = key.$doPublic(new BigInteger(padded)).toBuffer(key.encryptedDataLength);
    const dec = key.$doPrivate(new BigInteger(ct as Uint8Array)).toBuffer(key.encryptedDataLength);
    const unpadded = key.encryptionScheme.encUnPad(dec as Uint8Array);
    expect(equals(unpadded as Uint8Array, msg)).toBe(true);
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
    expect(equals(unpadded as Uint8Array, msg)).toBe(true);
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
    expect(equals(sig1, sig2)).toBe(true);
    expect(key.signingScheme.verify(msg, sig1)).toBe(true);
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
