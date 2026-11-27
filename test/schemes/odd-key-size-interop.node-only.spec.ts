import {
  createPrivateKey,
  createPublicKey,
  constants as cryptoConstants,
  sign as nodeSign,
  verify as nodeVerify,
  privateDecrypt,
  publicEncrypt,
} from 'node:crypto';
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
 * OpenSSL interop for moduli of 8k+1 bits (see test/rsa/odd-key-size.spec.ts
 * for the background). OpenSSL sizes everything from ⌈bits / 8⌉ octets, so
 * these directions only work when node-rsa uses the same modulus length.
 * `.node-only`: needs node:crypto as the reference implementation.
 */

const FIXTURES = [
  { file: 'private_1025_pkcs1.pem', bits: 1025, trials: 12 },
  { file: 'private_2049_pkcs1.pem', bits: 2049, trials: 4 },
] as const;

const RUNTIMES: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
  ['pure-JS engine, jsbn', { environment: 'browser', bigIntImpl: 'jsbn' }],
  ['pure-JS engine, native BigInt', { environment: 'browser', bigIntImpl: 'native' }],
  ['default engine', { bigIntImpl: 'jsbn' }],
];

const SIGNING = [
  ['pkcs1-sha256', { padding: cryptoConstants.RSA_PKCS1_PADDING }],
  ['pss-sha256', { padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 20 }],
] as const;

function message(i: number): Buffer {
  return Buffer.from(`odd key size interop ${i}`);
}

for (const { file, bits, trials } of FIXTURES) {
  const k = Math.ceil(bits / 8);
  const pem = readStr(file);
  const publicKey = createPublicKey(pem);
  const privateKey = createPrivateKey(pem);

  for (const [runtime, runtimeOpts] of RUNTIMES) {
    describe(`${bits}-bit key ↔ node:crypto — ${runtime}`, () => {
      const make = (opts: Record<string, unknown> = {}): NodeRSA =>
        new NodeRSA(pem, { ...runtimeOpts, ...opts });

      it('OAEP: node:crypto encrypts, node-rsa decrypts', () => {
        const key = make({ encryptionScheme: 'pkcs1_oaep' });
        for (let i = 0; i < trials; i++) {
          const ct = publicEncrypt(
            { key: publicKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING },
            message(i),
          );
          expect(ct.length).toBe(k);
          expect(Buffer.from(key.decrypt(ct) as Uint8Array).equals(message(i))).toBe(true);
        }
      });

      it('OAEP: node-rsa encrypts, node:crypto decrypts', () => {
        const key = make({ encryptionScheme: 'pkcs1_oaep' });
        for (let i = 0; i < trials; i++) {
          const ct = key.encrypt(message(i)) as Uint8Array;
          expect(ct.length).toBe(k);
          const pt = privateDecrypt(
            { key: privateKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING },
            Buffer.from(ct),
          );
          expect(pt.equals(message(i))).toBe(true);
        }
      });

      it('PKCS#1 v1.5: node:crypto encrypts, node-rsa decrypts', () => {
        const key = make({ encryptionScheme: 'pkcs1' });
        for (let i = 0; i < trials; i++) {
          const ct = publicEncrypt(
            { key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
            message(i),
          );
          expect(Buffer.from(key.decrypt(ct) as Uint8Array).equals(message(i))).toBe(true);
        }
      });

      for (const [scheme, nodeOpts] of SIGNING) {
        it(`${scheme}: node-rsa signs, node:crypto verifies`, () => {
          const key = make({ signingScheme: scheme });
          for (let i = 0; i < trials; i++) {
            const sig = key.sign(message(i)) as Uint8Array;
            expect(sig.length).toBe(k);
            const ok = nodeVerify(
              'sha256',
              message(i),
              { key: publicKey, ...nodeOpts },
              Buffer.from(sig),
            );
            expect(ok).toBe(true);
          }
        });

        it(`${scheme}: node:crypto signs, node-rsa verifies`, () => {
          const key = make({ signingScheme: scheme });
          for (let i = 0; i < trials; i++) {
            const sig = nodeSign('sha256', message(i), { key: privateKey, ...nodeOpts });
            expect(sig.length).toBe(k);
            expect(key.verify(message(i), sig)).toBe(true);
          }
        });
      }
    });
  }
}
