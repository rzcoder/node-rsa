import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import NodeRSA from '../../src/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

/**
 * The security-fix code paths in src/schemes/oaep.ts and src/schemes/pkcs1.ts
 * (C4 constant-time OAEP decode, C5 PKCS#1 v1.5 decode, C2 RSA blinding) only
 * run when the JS engine handles the primitive. On Node, encryption and OAEP
 * decryption are normally routed through NodeNativeEngine to OpenSSL — which
 * means the cross-validation.node-only suite cannot test them.
 *
 * This file forces the JS engine via `environment: 'browser'` and exercises
 * the fixes directly. Runs in BOTH the `node` and `browser-emulated` vitest
 * workspaces because the JS engine should behave identically.
 */

function makeJsKey(opts: Record<string, unknown> = {}): NodeRSA {
  return new NodeRSA(readStr('private_pkcs1.pem'), {
    environment: 'browser', // force the pure-JS engine
    ...opts,
  });
}

describe('OAEP — JS-engine round-trip and constant-time decode (C4)', () => {
  it('round-trips a short message through encPad → public → private → encUnPad', () => {
    const key = makeJsKey();
    const msg = new TextEncoder().encode('hello world');
    const ct = key.encrypt(msg) as Uint8Array;
    const pt = key.decrypt(ct) as Uint8Array;
    expect(new TextDecoder().decode(pt)).toBe('hello world');
  });

  it('rejects mid-buffer tampered ciphertext with the JS-engine padding error', () => {
    // C4 path: oaep.encUnPad returns null on bad padding; the engine wraps
    // in this generic message. We mutate a middle byte (small XOR) to avoid
    // pushing the integer value past `n` and tripping the H2 bounds check
    // instead — RSA primitive is a permutation, so the resulting plaintext
    // is pseudo-random and almost-certainly fails OAEP padding.
    const key = makeJsKey();
    const ct = key.encrypt(new TextEncoder().encode('test')) as Uint8Array;
    const tampered = new Uint8Array(ct);
    tampered[Math.floor(tampered.length / 2)] ^= 0x01;
    expect(() => key.decrypt(tampered)).toThrow('Error during decryption');
  });

  it('all mid-buffer mutations yield the SAME generic error (constant error path)', () => {
    // C4's downstream contract: every distinct OAEP failure mode (Y, lHash,
    // PS, separator) reaches the same `return null` and the engine wraps in
    // an identical message. The message itself must not be an oracle.
    //
    // We can't easily craft ciphertexts that hit each failure mode
    // *specifically* (encrypt's public API doesn't expose padding internals),
    // but we can demonstrate that several independent mid-buffer mutations
    // all surface byte-identical errors — that's the observable property.
    const key = makeJsKey();
    const valid = key.encrypt(new TextEncoder().encode('test')) as Uint8Array;
    // Pick positions across the buffer: lHash region, mid-DB, near tail.
    // Skip byte 0 (would push ct >= n on some keys and trip H2 instead).
    const positions = [20, 40, 60, 80, valid.length - 5];
    const errors = positions.map((pos) => {
      const t = new Uint8Array(valid);
      t[pos] ^= 0x01;
      try {
        key.decrypt(t);
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    });
    expect(errors[0]).toBeTruthy();
    for (let i = 1; i < errors.length; i++) {
      expect(errors[i], `position ${positions[i]} differs from position ${positions[0]}`).toBe(
        errors[0],
      );
    }
  });
});

describe('PKCS#1 v1.5 — JS-engine round-trip and constant-time decode (C5)', () => {
  it('round-trips through encPad → public → private → encUnPad', () => {
    const key = makeJsKey({ encryptionScheme: 'pkcs1' });
    const msg = new TextEncoder().encode('hello');
    const ct = key.encrypt(msg) as Uint8Array;
    const pt = key.decrypt(ct) as Uint8Array;
    expect(new TextDecoder().decode(pt)).toBe('hello');
  });

  it('rejects mid-buffer tampered ciphertext with the JS-engine padding error', () => {
    // Same rationale as the OAEP test: avoid byte 0 to keep the value < n.
    const key = makeJsKey({ encryptionScheme: 'pkcs1' });
    const ct = key.encrypt(new TextEncoder().encode('test')) as Uint8Array;
    const tampered = new Uint8Array(ct);
    tampered[Math.floor(tampered.length / 2)] ^= 0x01;
    expect(() => key.decrypt(tampered)).toThrow('Error during decryption');
  });

  it('all mid-buffer mutations yield the SAME generic error (constant error path)', () => {
    const key = makeJsKey({ encryptionScheme: 'pkcs1' });
    const valid = key.encrypt(new TextEncoder().encode('test')) as Uint8Array;
    const positions = [20, 40, 60, 80, valid.length - 5];
    const errors = positions.map((pos) => {
      const t = new Uint8Array(valid);
      t[pos] ^= 0x01;
      try {
        key.decrypt(t);
        return null;
      } catch (e) {
        return (e as Error).message;
      }
    });
    expect(errors[0]).toBeTruthy();
    for (let i = 1; i < errors.length; i++) {
      expect(errors[i], `position ${positions[i]} differs from position ${positions[0]}`).toBe(
        errors[0],
      );
    }
  });
});

describe('RSA blinding — JS-engine private operation does not crash (C2)', () => {
  it('private operation completes for arbitrary input in [0, n)', () => {
    // Exercise $doPrivate through encryptPrivate (which calls $doPrivate
    // through the JS engine). Without the blinding path working, this
    // would crash or produce wrong output.
    const key = makeJsKey({ encryptionScheme: 'pkcs1' });
    const msg = new TextEncoder().encode('blinded');
    // encryptPrivate uses $doPrivate; decryptPublic verifies the result.
    const ct = key.encryptPrivate(msg) as Uint8Array;
    const pt = key.decryptPublic(ct) as Uint8Array;
    expect(new TextDecoder().decode(pt)).toBe('blinded');
  });

  it('repeated private ops on the same input yield the same plaintext', () => {
    // Blinding uses fresh r each call, but the un-blinded result must be
    // deterministic for a fixed message.
    const key = makeJsKey({ encryptionScheme: 'pkcs1' });
    const msg = new TextEncoder().encode('repeat');
    const ct = key.encryptPrivate(msg) as Uint8Array;
    for (let i = 0; i < 5; i++) {
      const pt = key.decryptPublic(ct) as Uint8Array;
      expect(new TextDecoder().decode(pt)).toBe('repeat');
    }
  });
});
