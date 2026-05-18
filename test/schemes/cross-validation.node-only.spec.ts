import {
  constants as cryptoConstants,
  sign as nodeSign,
  verify as nodeVerify,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
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
 * Cross-validation suite. node-rsa and OpenSSL (via node:crypto) must agree
 * for every supported scheme × hash combination. This file is .node-only:
 * the browser-emulated workspace doesn't have node:crypto.
 *
 * Engine routing caveat: on Node, encrypt/decrypt for OAEP and PKCS#1 v1.5
 * route through NodeNativeEngine (OpenSSL) — NOT through the JS engine
 * where the C4/C5/C2 constant-time fixes live. So the OAEP and PKCS#1
 * encrypt/decrypt cases below validate INTEROP (round-trip correctness),
 * not the JS-engine security paths. The dedicated JS-engine coverage lives
 * in test/schemes/js-engine-security.spec.ts (which forces JsEngine via
 * `environment: 'browser'` and runs in both workspaces).
 *
 * Sign/verify paths for both PKCS#1 v1.5 and PSS *do* run through the JS
 * engine on Node — no native-engine equivalent exists — so those tests
 * exercise pkcs1Scheme/pssScheme directly.
 *
 * Each describe block runs N random message trials; with the fixture
 * 1024-bit key the suite is fast enough to keep in CI.
 */

const ITERATIONS = 20;

function makeNodeRsa(scheme: string, hashOpt?: string): NodeRSA {
  const pem = readStr('private_pkcs1.pem');
  const opts: { signingScheme?: string; encryptionScheme?: string } = {};
  if (scheme.startsWith('pkcs1-') || scheme.startsWith('pss-')) {
    opts.signingScheme = scheme;
  } else {
    opts.encryptionScheme = scheme;
    if (hashOpt) opts.encryptionScheme = scheme;
  }
  return new NodeRSA(pem, opts);
}

const NODE_HASH: Record<string, string> = {
  sha1: 'sha1',
  sha256: 'sha256',
  sha384: 'sha384',
  sha512: 'sha512',
};

describe('PKCS#1 v1.5 sign / verify ↔ node:crypto', () => {
  for (const hash of ['sha1', 'sha256', 'sha384', 'sha512'] as const) {
    it(`bit-identical signatures: pkcs1-${hash} (${ITERATIONS} trials)`, () => {
      const key = makeNodeRsa(`pkcs1-${hash}`);
      const pem = readStr('private_pkcs1.pem');
      for (let i = 0; i < ITERATIONS; i++) {
        const msg = randomBytes(50 + Math.floor(Math.random() * 200));
        // node-rsa → node:crypto
        const sig = key.sign(msg) as Uint8Array;
        const ok = nodeVerify(NODE_HASH[hash], msg, pem, sig);
        expect(ok, `node:crypto failed to verify node-rsa signature #${i}`).toBe(true);
        // PKCS#1 v1.5 is deterministic — sign in node:crypto and compare bytes.
        const sigNode = nodeSign(NODE_HASH[hash], msg, pem);
        expect(Buffer.from(sig).equals(sigNode), `byte-equal signature #${i}`).toBe(true);
      }
    });

    it(`accepts node:crypto-produced signatures: pkcs1-${hash}`, () => {
      const key = makeNodeRsa(`pkcs1-${hash}`);
      const pem = readStr('private_pkcs1.pem');
      for (let i = 0; i < ITERATIONS; i++) {
        const msg = randomBytes(50 + Math.floor(Math.random() * 200));
        const sig = nodeSign(NODE_HASH[hash], msg, pem);
        expect(key.verify(msg, sig as unknown as Uint8Array)).toBe(true);
      }
    });
  }
});

describe('PSS sign / verify ↔ node:crypto', () => {
  for (const hash of ['sha1', 'sha256', 'sha384', 'sha512'] as const) {
    it(`node-rsa signs, node:crypto verifies: pss-${hash}`, () => {
      // PSS uses a random salt so signatures aren't bit-identical, but
      // they must verify in both directions.
      const key = makeNodeRsa(`pss-${hash}`);
      const pem = readStr('private_pkcs1.pem');
      for (let i = 0; i < ITERATIONS; i++) {
        const msg = randomBytes(50 + Math.floor(Math.random() * 200));
        const sig = key.sign(msg) as Uint8Array;
        const ok = nodeVerify(
          NODE_HASH[hash],
          msg,
          {
            key: pem,
            padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
            saltLength: 20, // matches DEFAULT_SALT_LENGTH in src/schemes/pss.ts
          },
          sig,
        );
        expect(ok, `node:crypto failed to verify PSS-${hash} signature #${i}`).toBe(true);
      }
    });

    it(`node:crypto signs, node-rsa verifies: pss-${hash}`, () => {
      const key = makeNodeRsa(`pss-${hash}`);
      const pem = readStr('private_pkcs1.pem');
      for (let i = 0; i < ITERATIONS; i++) {
        const msg = randomBytes(50 + Math.floor(Math.random() * 200));
        const sig = nodeSign(NODE_HASH[hash], msg, {
          key: pem,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: 20,
        });
        expect(key.verify(msg, sig as unknown as Uint8Array)).toBe(true);
      }
    });
  }
});

describe('OAEP encrypt / decrypt ↔ node:crypto', () => {
  // OAEP defaults to SHA-1 in src/schemes/oaep.ts; node:crypto defaults to
  // SHA-1 as well for RSA_PKCS1_OAEP_PADDING — they line up.
  it('node-rsa encrypts, node:crypto decrypts (default SHA-1)', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const pem = readStr('private_pkcs1.pem');
    const maxMsg = key.getMaxMessageSize();
    for (let i = 0; i < ITERATIONS; i++) {
      const msg = randomBytes(1 + Math.floor(Math.random() * maxMsg));
      const ct = key.encrypt(msg) as Uint8Array;
      const pt = privateDecrypt(
        { key: pem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(ct),
      );
      expect(Buffer.from(pt).equals(Buffer.from(msg)), `OAEP round-trip #${i}`).toBe(true);
    }
  });

  it('node:crypto encrypts, node-rsa decrypts (default SHA-1)', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const pem = readStr('private_pkcs1.pem');
    const maxMsg = key.getMaxMessageSize();
    for (let i = 0; i < ITERATIONS; i++) {
      const msg = randomBytes(1 + Math.floor(Math.random() * maxMsg));
      const ct = publicEncrypt(
        { key: pem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(msg),
      );
      const pt = key.decrypt(new Uint8Array(ct)) as Uint8Array;
      expect(Buffer.from(pt).equals(Buffer.from(msg)), `OAEP reverse round-trip #${i}`).toBe(true);
    }
  });
});

describe('OAEP cross-validation with non-default hash', () => {
  // OAEP with SHA-1 is the existing happy-path. node:crypto exposes oaepHash
  // to align with our encryptionSchemeOptions.hash. Skip sha512 — it doesn't
  // fit on a 1024-bit key (k=128 < 2·64+2). sha384 only just fits (max 30 B).
  for (const hash of ['sha256', 'sha384'] as const) {
    const maxByHash: Record<string, number> = { sha256: 62, sha384: 30 };
    it(`node-rsa encrypts, node:crypto decrypts: oaepHash=${hash}`, () => {
      const pem = readStr('private_pkcs1.pem');
      const key = new NodeRSA(pem, {
        encryptionScheme: { scheme: 'pkcs1_oaep', hash },
      });
      const limit = maxByHash[hash] as number;
      for (let i = 0; i < ITERATIONS; i++) {
        const msg = randomBytes(1 + Math.floor(Math.random() * limit));
        const ct = key.encrypt(msg) as Uint8Array;
        const pt = privateDecrypt(
          { key: pem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash },
          Buffer.from(ct),
        );
        expect(Buffer.from(pt).equals(Buffer.from(msg)), `${hash} round-trip #${i}`).toBe(true);
      }
    });

    it(`node:crypto encrypts, node-rsa decrypts: oaepHash=${hash}`, () => {
      const pem = readStr('private_pkcs1.pem');
      const key = new NodeRSA(pem, {
        encryptionScheme: { scheme: 'pkcs1_oaep', hash },
      });
      const limit = maxByHash[hash] as number;
      for (let i = 0; i < ITERATIONS; i++) {
        const msg = randomBytes(1 + Math.floor(Math.random() * limit));
        const ct = publicEncrypt(
          { key: pem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash },
          Buffer.from(msg),
        );
        const pt = key.decrypt(new Uint8Array(ct)) as Uint8Array;
        expect(Buffer.from(pt).equals(Buffer.from(msg)), `${hash} reverse #${i}`).toBe(true);
      }
    });
  }
});

describe('Negative interop: tampered ciphertext / signature is rejected', () => {
  it('node-rsa rejects a PKCS#1 v1.5 signature with a flipped bit', () => {
    const key = makeNodeRsa('pkcs1-sha256');
    const pem = readStr('private_pkcs1.pem');
    const msg = randomBytes(64);
    const sig = nodeSign('sha256', msg, pem);
    const tampered = new Uint8Array(sig);
    tampered[Math.floor(tampered.length / 2)] ^= 0x01;
    expect(key.verify(msg, tampered)).toBe(false);
  });

  it('node-rsa rejects an OAEP ciphertext with a flipped bit', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const pem = readStr('private_pkcs1.pem');
    const msg = randomBytes(32);
    const ct = publicEncrypt(
      { key: pem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(msg),
    );
    const tampered = new Uint8Array(ct);
    tampered[Math.floor(tampered.length / 2)] ^= 0x01;
    // The error message varies: native-engine path surfaces OpenSSL's
    // "oaep decoding error", JsEngine path surfaces our "invalid padding".
    // Either way, decrypt MUST throw — not return garbage plaintext.
    expect(() => key.decrypt(tampered)).toThrow();
  });
});
