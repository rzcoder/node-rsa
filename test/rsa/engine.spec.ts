import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerReader } from '../../src/asn1/index.js';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
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
