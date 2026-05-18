import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerReader } from '../../src/asn1/index.js';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { RSAKey } from '../../src/rsa/key.js';
import { SCHEMES } from '../../src/schemes/index.js';
import type { EncryptionScheme, SchemeOptions } from '../../src/schemes/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../../test/keys');

/**
 * EM-shape negative tests for PKCS#1 v1.5 decode (src/schemes/pkcs1.ts).
 * Goes one layer below cross-validation/js-engine-security: directly
 * crafts the *decoded* EM and calls `encryptionScheme.encUnPad`. That
 * isolates the constant-time `bad` flag from the surrounding RSA
 * primitive (no need to encrypt → tamper → decrypt; we synthesise the
 * post-RSA byte string the decoder sees).
 *
 * Lives in both vitest workspaces — the encUnPad code is pure-JS and
 * identical across `node` and `browser-emulated`.
 */

function loadDer(name: string): Uint8Array {
  const buf = readFileSync(resolve(keysDir, name));
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function makeKey(): RSAKey {
  const seq = new DerReader(loadDer('private_pkcs1.der')).readSequence();
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
  const options: SchemeOptions = {
    signingScheme: 'pkcs1',
    encryptionScheme: 'pkcs1',
    signingSchemeOptions: {},
    encryptionSchemeOptions: {},
    environment: 'node',
    backend: nodeBackend,
  };
  key.setOptions(options, SCHEMES);
  return key;
}

/**
 * Build a well-formed PKCS#1 v1.5 type-2 EM: `00 02 PS 00 MSG`, with
 * `PS` of arbitrary non-zero bytes long enough to satisfy the ≥ 8
 * minimum unless otherwise specified.
 */
function buildEm(
  emLen: number,
  msgLen: number,
  opts: { type?: number; psLen?: number; corrupt?: (em: Uint8Array) => void } = {},
): Uint8Array {
  const em = new Uint8Array(emLen);
  em[0] = 0x00;
  em[1] = opts.type ?? 0x02;
  const psLen = opts.psLen ?? emLen - msgLen - 3;
  // Fill PS with non-zero bytes (0x42), then the separator 0x00, then message.
  for (let i = 0; i < psLen; i++) em[2 + i] = 0x42;
  em[2 + psLen] = 0x00; // separator
  for (let i = 0; i < msgLen; i++) em[3 + psLen + i] = 0xa5;
  opts.corrupt?.(em);
  return em;
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

describe('PKCS#1 v1.5 encUnPad — direct EM negative tests (type=2)', () => {
  it('accepts a canonical EM', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const em = buildEm(key.encryptedDataLength, 10);
    const out = enc.encUnPad(em);
    expect(out).not.toBeNull();
    expect((out as Uint8Array).length).toBe(10);
  });

  it('rejects EM with leading byte ≠ 0x00', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const em = buildEm(key.encryptedDataLength, 10, {
      corrupt: (b) => {
        b[0] = 0x01;
      },
    });
    expect(enc.encUnPad(em)).toBeNull();
  });

  it('rejects EM with type byte ≠ 0x02 (e.g., 0x01, 0x03, 0xff)', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    for (const t of [0x00, 0x01, 0x03, 0xff]) {
      const em = buildEm(key.encryptedDataLength, 10, {
        corrupt: (b) => {
          b[1] = t;
        },
      });
      expect(enc.encUnPad(em), `type=0x${t.toString(16)}`).toBeNull();
    }
  });

  it('rejects EM with no 0x00 separator anywhere after byte 2', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const em = new Uint8Array(key.encryptedDataLength);
    em[0] = 0x00;
    em[1] = 0x02;
    em.fill(0x42, 2); // No 0x00 → no separator found
    expect(enc.encUnPad(em)).toBeNull();
  });

  it('rejects EM with PS shorter than 8 bytes (RFC §7.2.1)', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    for (const psLen of [0, 1, 7]) {
      const em = buildEm(key.encryptedDataLength, key.encryptedDataLength - psLen - 3, {
        psLen,
      });
      expect(enc.encUnPad(em), `PS=${psLen}`).toBeNull();
    }
  });

  it('accepts EM where PS is exactly 8 bytes (boundary)', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const em = buildEm(key.encryptedDataLength, key.encryptedDataLength - 11, { psLen: 8 });
    const out = enc.encUnPad(em);
    expect(out).not.toBeNull();
    expect((out as Uint8Array).length).toBe(key.encryptedDataLength - 11);
  });

  it('rejects EM whose buffer is shorter than 11 bytes (geometry)', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    for (const len of [0, 1, 10]) {
      const em = new Uint8Array(len);
      expect(enc.encUnPad(em), `len=${len}`).toBeNull();
    }
  });

  it('accepts EM with empty message (msg length = 0)', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    // PS = emLen - 3 (separator + leading 2 bytes; msg = 0)
    const em = buildEm(key.encryptedDataLength, 0);
    const out = enc.encUnPad(em);
    expect(out).not.toBeNull();
    expect((out as Uint8Array).length).toBe(0);
  });
});

describe('PKCS#1 v1.5 encUnPad — direct EM negative tests (type=1, signature path)', () => {
  it('accepts a canonical type-1 EM', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const emLen = key.encryptedDataLength;
    // type-1 EM: 0x00 0x01 0xff…0xff 0x00 MSG
    const em = new Uint8Array(emLen);
    em[0] = 0x00;
    em[1] = 0x01;
    const psLen = emLen - 10 - 3; // 10-byte message
    for (let i = 0; i < psLen; i++) em[2 + i] = 0xff;
    em[2 + psLen] = 0x00;
    for (let i = 0; i < 10; i++) em[3 + psLen + i] = 0x5a;
    const out = enc.encUnPad(em, { type: 1 });
    expect(out).not.toBeNull();
    expect((out as Uint8Array).length).toBe(10);
  });

  it('rejects type-1 EM where a PS byte is not 0xff and not the separator', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const emLen = key.encryptedDataLength;
    const em = new Uint8Array(emLen);
    em[0] = 0x00;
    em[1] = 0x01;
    const psLen = emLen - 10 - 3;
    for (let i = 0; i < psLen; i++) em[2 + i] = 0xff;
    em[2 + 5] = 0xfe; // PS byte ≠ 0xff and ≠ 0x00
    em[2 + psLen] = 0x00;
    for (let i = 0; i < 10; i++) em[3 + psLen + i] = 0x5a;
    expect(enc.encUnPad(em, { type: 1 })).toBeNull();
  });

  it('rejects type-1 EM with type byte ≠ 0x01', () => {
    const key = makeKey();
    const enc = key.encryptionScheme as EncryptionScheme;
    const emLen = key.encryptedDataLength;
    const em = new Uint8Array(emLen);
    em[0] = 0x00;
    em[1] = 0x02; // wrong type for sig path
    const psLen = emLen - 10 - 3;
    for (let i = 0; i < psLen; i++) em[2 + i] = 0xff;
    em[2 + psLen] = 0x00;
    expect(enc.encUnPad(em, { type: 1 })).toBeNull();
  });
});

describe('PKCS#1 v1.5 encUnPad — RSA_NO_PADDING raw mode', () => {
  it('strips leading zero pad', () => {
    const key = new RSAKey();
    const seq = new DerReader(loadDer('private_pkcs1.der')).readSequence();
    seq.readSmallInteger();
    const n = seq.readInteger();
    const e = seq.readSmallInteger();
    const d = seq.readInteger();
    const p = seq.readInteger();
    const q = seq.readInteger();
    const dmp1 = seq.readInteger();
    const dmq1 = seq.readInteger();
    const coeff = seq.readInteger();
    key.setPrivate(n, e, d, p, q, dmp1, dmq1, coeff);
    const options: SchemeOptions = {
      signingScheme: 'pkcs1',
      encryptionScheme: 'pkcs1',
      signingSchemeOptions: {},
      // RSA_NO_PADDING = 3 (matches src/schemes/pkcs1.ts).
      encryptionSchemeOptions: { padding: 3 },
      environment: 'node',
      backend: nodeBackend,
    };
    key.setOptions(options, SCHEMES);
    const enc = key.encryptionScheme as EncryptionScheme;
    const em = new Uint8Array(key.encryptedDataLength);
    // Zero-pad except for a small payload at the tail.
    em[em.length - 3] = 0x00; // last zero is the boundary
    em[em.length - 2] = 0x11;
    em[em.length - 1] = 0x22;
    const out = enc.encUnPad(em) as Uint8Array;
    expect(Array.from(out)).toEqual([0x11, 0x22]);
  });
});
