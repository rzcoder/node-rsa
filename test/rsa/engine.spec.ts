import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerReader } from '../../src/asn1/index.js';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { equals, fromUtf8 } from '../../src/crypto/bytes.js';
import { JsEngine } from '../../src/rsa/engine.js';
import { RSAKey } from '../../src/rsa/key.js';
import { SCHEMES } from '../../src/schemes/index.js';
import type { SchemeOptions } from '../../src/schemes/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../../test/keys');

function loadPrivateKey(): RSAKey {
  const buf = readFileSync(resolve(keysDir, 'private_pkcs1.der'));
  const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const seq = new DerReader(bytes).readSequence();
  seq.readSmallInteger();
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

function configure(key: RSAKey, encryptionScheme: 'pkcs1' | 'pkcs1_oaep' = 'pkcs1'): void {
  const options: SchemeOptions = {
    signingScheme: 'pkcs1',
    encryptionScheme,
    signingSchemeOptions: {},
    encryptionSchemeOptions: {},
    environment: 'node',
    backend: nodeBackend,
  };
  key.setOptions(options, SCHEMES);
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

describe('JsEngine encrypt → decrypt (PKCS#1 v1.5)', () => {
  it('round-trips short message', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    const msg = fromUtf8('hello engine');
    const ct = engine.encrypt(msg);
    expect(ct.length).toBe(key.encryptedDataLength);
    const dec = engine.decrypt(ct);
    expect(equals(dec, msg)).toBe(true);
  });

  it('chunks a long message across multiple blocks', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    // 1024-bit key → max plain = 117 bytes for PKCS#1 v1.5. Use 250 bytes.
    const msg = new Uint8Array(250).map((_, i) => (i * 3 + 1) & 0xff);
    const ct = engine.encrypt(msg);
    expect(ct.length % key.encryptedDataLength).toBe(0);
    expect(ct.length).toBeGreaterThan(key.encryptedDataLength); // at least 2 chunks
    const dec = engine.decrypt(ct);
    expect(equals(dec, msg)).toBe(true);
  });

  it('rejects ciphertext whose length is not a multiple of encryptedDataLength', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    expect(() => engine.decrypt(new Uint8Array(key.encryptedDataLength + 5))).toThrow(
      /Incorrect data or key/,
    );
  });

  it('encryptPrivate → decryptPublic (signature-shaped path)', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    const msg = fromUtf8('signed payload');
    const ct = engine.encrypt(msg, true);
    const dec = engine.decrypt(ct, true);
    expect(equals(dec, msg)).toBe(true);
  });
});

describe('JsEngine — CRT vs non-CRT $doPrivate parity', () => {
  // RSAKey.$doPrivate uses Garner CRT recombination when p/q/dmp1/dmq1/coeff
  // are present; otherwise it falls back to modPow(d, n). Both paths must
  // produce identical outputs for the same input — a CRT bug would only
  // surface as wrong ciphertext for keys with CRT components, which most
  // imported keys have.
  it('CRT and non-CRT decrypt produce byte-identical plaintext for a fixed message', () => {
    const fullKey = loadPrivateKey(); // has full CRT components
    const basicKey = new RSAKey();
    // Only n, e, d → engine takes the modPow(d, n) branch.
    basicKey.setPrivate(
      fullKey.n!.toBuffer() as Uint8Array,
      fullKey.e,
      fullKey.d!.toBuffer() as Uint8Array,
    );
    configure(fullKey);
    configure(basicKey);

    const fullEng = new JsEngine(fullKey);
    const basicEng = new JsEngine(basicKey);
    const msg = fromUtf8('crt-vs-direct parity check');

    // Encrypt with public (no CRT involvement) → both keys give same path.
    const ctFull = fullEng.encrypt(msg);
    // Decrypt with each key; the CRT branch (fullKey) and the non-CRT
    // branch (basicKey) must agree on the plaintext.
    const ptFull = fullEng.decrypt(ctFull);
    const ptBasic = basicEng.decrypt(ctFull);
    expect(equals(ptBasic, ptFull)).toBe(true);
    expect(equals(ptFull, msg)).toBe(true);
  });

  it('CRT and non-CRT produce identical raw $doPrivate result for a fixed input < n', () => {
    // Direct primitive-level parity check — bypasses padding so a CRT bug
    // becomes a single-block mismatch.
    const fullKey = loadPrivateKey();
    const basicKey = new RSAKey();
    basicKey.setPrivate(
      fullKey.n!.toBuffer() as Uint8Array,
      fullKey.e,
      fullKey.d!.toBuffer() as Uint8Array,
    );
    configure(fullKey);
    configure(basicKey);
    // Choose a small value (well under n) by building a BigInteger that
    // matches the active impl through the same selector the keys use.
    const seed = new Uint8Array(fullKey.encryptedDataLength);
    seed.fill(0x42);
    seed[0] = 0x00; // ensures value < n
    const x = new BigInteger(seed);
    const yFull = fullKey.$doPrivate(x).toString(16);
    const yBasic = basicKey.$doPrivate(x).toString(16);
    expect(yBasic).toBe(yFull);
  });
});

describe('JsEngine — message-size boundary handling (PKCS#1 v1.5)', () => {
  it('encrypts a message of exactly maxMessageLength bytes in one block', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    const max = key.maxMessageLength;
    expect(max).toBe(key.encryptedDataLength - 11); // 117 for 1024-bit PKCS#1 v1.5
    const msg = new Uint8Array(max).map((_, i) => (i * 7 + 5) & 0xff);
    const ct = engine.encrypt(msg);
    expect(ct.length).toBe(key.encryptedDataLength); // exactly one chunk
    const dec = engine.decrypt(ct);
    expect(equals(dec, msg)).toBe(true);
  });

  it('encrypts a message of maxMessageLength + 1 bytes in two blocks', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    const max = key.maxMessageLength;
    const msg = new Uint8Array(max + 1).map((_, i) => (i * 13) & 0xff);
    const ct = engine.encrypt(msg);
    expect(ct.length).toBe(key.encryptedDataLength * 2);
    const dec = engine.decrypt(ct);
    expect(equals(dec, msg)).toBe(true);
  });

  it('encrypts an empty message into a single full-size block', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    const ct = engine.encrypt(new Uint8Array(0));
    expect(ct.length).toBe(key.encryptedDataLength);
    const dec = engine.decrypt(ct);
    expect(dec.length).toBe(0);
  });

  it('encrypts a single-byte message', () => {
    const key = loadPrivateKey();
    configure(key);
    const engine = new JsEngine(key);
    const ct = engine.encrypt(new Uint8Array([0xff]));
    expect(ct.length).toBe(key.encryptedDataLength);
    const dec = engine.decrypt(ct);
    expect(Array.from(dec)).toEqual([0xff]);
  });
});

describe('JsEngine encrypt → decrypt (OAEP)', () => {
  it('round-trips with default SHA-1', () => {
    const key = loadPrivateKey();
    configure(key, 'pkcs1_oaep');
    const engine = new JsEngine(key);
    const msg = fromUtf8('oaep engine');
    const ct = engine.encrypt(msg);
    const dec = engine.decrypt(ct);
    expect(equals(dec, msg)).toBe(true);
  });

  it('chunks across multiple OAEP blocks', () => {
    const key = loadPrivateKey();
    configure(key, 'pkcs1_oaep');
    const engine = new JsEngine(key);
    // 1024-bit key with OAEP/SHA-1 → max plain = 86 bytes. Try 250.
    const msg = new Uint8Array(250).map((_, i) => i & 0xff);
    const ct = engine.encrypt(msg);
    expect(ct.length % key.encryptedDataLength).toBe(0);
    const dec = engine.decrypt(ct);
    expect(equals(dec, msg)).toBe(true);
  });
});
