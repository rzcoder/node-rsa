import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
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

/**
 * Regression suite for moduli whose bit length is 8k+1 (1025, 2049, …).
 *
 * The modulus length in octets is k = ⌈bits / 8⌉ (RFC 8017 §2). It used to
 * be computed as (bits + 6) >> 3, which is one byte short exactly when
 * bits ≡ 1 (mod 8). Every scheme sizes its encoded message, ciphertext and
 * signature from that value, so such keys produced 128-byte output for a
 * 129-byte modulus: results did not interoperate with OpenSSL, the node
 * engine could not decrypt at all, and whenever the RSA result needed the
 * top byte the pure-JS engine either threw (jsbn) or silently dropped that
 * byte (native BigInt).
 *
 * `generateKeyPair` only accepts sizes that are a multiple of 8, so these
 * keys only arrive through import — hence the fixtures.
 */

const FIXTURES = [
  { file: 'private_1025_pkcs1.pem', bits: 1025, trials: 24 },
  { file: 'private_2049_pkcs1.pem', bits: 2049, trials: 6 },
] as const;

const RUNTIMES: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
  ['pure-JS engine, jsbn', { environment: 'browser', bigIntImpl: 'jsbn' }],
  ['pure-JS engine, native BigInt', { environment: 'browser', bigIntImpl: 'native' }],
  ['default engine', { bigIntImpl: 'jsbn' }],
];

function message(i: number, length = 24): Uint8Array {
  const out = new Uint8Array(length);
  for (let j = 0; j < length; j++) out[j] = (i * 31 + j * 7 + 1) & 0xff;
  return out;
}

describe('modulus byte length is ⌈bits / 8⌉', () => {
  it('holds for every bit length across three byte boundaries', () => {
    for (let bits = 1017; bits <= 1040; bits++) {
      // Smallest odd integer with exactly `bits` bits: 2^(bits-1) + 1.
      const n = new Uint8Array(Math.ceil(bits / 8));
      n[0] = 1 << ((bits - 1) % 8);
      n[n.length - 1] = (n[n.length - 1] as number) | 1;

      const key = new RSAKey();
      key.setPublic(n, 65537);
      expect(key.keySize, `${bits} bits`).toBe(bits);
      expect(key.encryptedDataLength, `${bits} bits`).toBe(Math.ceil(bits / 8));
    }
  });
});

for (const { file, bits, trials } of FIXTURES) {
  const k = Math.ceil(bits / 8);

  for (const [runtime, runtimeOpts] of RUNTIMES) {
    describe(`${bits}-bit key — ${runtime}`, () => {
      const make = (opts: Record<string, unknown> = {}): NodeRSA =>
        new NodeRSA(readStr(file), { ...runtimeOpts, ...opts });

      it('reports the key size and per-scheme maximum message size', () => {
        expect(make().getKeySize()).toBe(bits);
        expect(make({ encryptionScheme: 'pkcs1' }).getMaxMessageSize()).toBe(k - 11);
        // OAEP with the default SHA-1: k − 2·hLen − 2.
        expect(make({ encryptionScheme: 'pkcs1_oaep' }).getMaxMessageSize()).toBe(k - 42);
      });

      for (const scheme of ['pkcs1', 'pkcs1_oaep'] as const) {
        it(`${scheme}: ciphertext is ${k} bytes and round-trips (${trials} trials)`, () => {
          const key = make({ encryptionScheme: scheme });
          for (let i = 0; i < trials; i++) {
            const msg = message(i);
            const ct = key.encrypt(msg) as Uint8Array;
            expect(ct.length).toBe(k);
            expect(Array.from(key.decrypt(ct) as Uint8Array)).toEqual(Array.from(msg));
          }
        });

        it(`${scheme}: multi-chunk message round-trips in ${k}-byte blocks`, () => {
          const key = make({ encryptionScheme: scheme });
          const msg = message(1, key.getMaxMessageSize() * 2 + 5);
          const ct = key.encrypt(msg) as Uint8Array;
          expect(ct.length).toBe(3 * k);
          expect(Array.from(key.decrypt(ct) as Uint8Array)).toEqual(Array.from(msg));
        });
      }

      it(`encryptPrivate / decryptPublic round-trips in ${k}-byte blocks`, () => {
        const key = make({ encryptionScheme: 'pkcs1' });
        for (let i = 0; i < trials; i++) {
          const msg = message(i);
          const ct = key.encryptPrivate(msg) as Uint8Array;
          expect(ct.length).toBe(k);
          expect(Array.from(key.decryptPublic(ct) as Uint8Array)).toEqual(Array.from(msg));
        }
      });

      for (const scheme of ['pkcs1-sha256', 'pss-sha256'] as const) {
        it(`${scheme}: signature is ${k} bytes and verifies (${trials} trials)`, () => {
          const key = make({ signingScheme: scheme });
          for (let i = 0; i < trials; i++) {
            const msg = message(i);
            const sig = key.sign(msg) as Uint8Array;
            expect(sig.length).toBe(k);
            expect(key.verify(msg, sig)).toBe(true);

            const tampered = sig.slice();
            tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 1;
            expect(key.verify(msg, tampered)).toBe(false);
          }
        });
      }
    });
  }
}
