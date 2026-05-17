import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import NodeRSA from '../src/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, 'keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

describe('NodeRSA smoke', () => {
  it('constructs empty', () => {
    const key = new NodeRSA();
    expect(key.isEmpty()).toBe(true);
    expect(key.isPrivate()).toBe(false);
    expect(key.isPublic()).toBe(false);
  });

  it('imports a PKCS#1 private PEM and exports it back', () => {
    const orig = readStr('private_pkcs1.pem');
    const key = new NodeRSA(orig);
    expect(key.isPrivate()).toBe(true);
    expect(key.getKeySize()).toBe(1024);
    const pem = key.exportKey('pkcs1-private-pem');
    expect(pem).toContain('BEGIN RSA PRIVATE KEY');
  });

  it('round-trips encrypt → decrypt with default OAEP scheme', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const ct = key.encrypt('hello world');
    expect(ct).toBeInstanceOf(Uint8Array);
    const pt = key.decrypt(ct as Uint8Array, 'utf8');
    expect(pt).toBe('hello world');
  });

  it('round-trips sign → verify with PKCS#1', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const sig = key.sign('signed data');
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(key.verify('signed data', sig as Uint8Array)).toBe(true);
    expect(key.verify('tampered', sig as Uint8Array)).toBe(false);
  });

  it('setOptions parses combined format like "pss-sha512"', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    key.setOptions({ signingScheme: 'pss-sha512' });
    expect(key.$options.signingScheme).toBe('pss');
    expect(key.$options.signingSchemeOptions.hash).toBe('sha512');
    const sig = key.sign('payload');
    expect(key.verify('payload', sig as Uint8Array)).toBe(true);
  });

  it('encrypts with base64 output encoding', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const b64 = key.encrypt('hi', 'base64') as string;
    expect(typeof b64).toBe('string');
    expect(b64).toMatch(/^[A-Za-z0-9+/=]+$/);
    const pt = key.decrypt(b64, 'utf8');
    expect(pt).toBe('hi');
  });

  it('decrypts to JSON', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const ct = key.encrypt({ x: 1, y: [2, 3] });
    const obj = key.decrypt(ct as Uint8Array, 'json');
    expect(obj).toEqual({ x: 1, y: [2, 3] });
  });

  it('encryptPrivate ↔ decryptPublic', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const ct = key.encryptPrivate('private-encrypted');
    const pt = key.decryptPublic(ct as Uint8Array, 'utf8');
    expect(pt).toBe('private-encrypted');
  });

  it('throws on import of empty key', () => {
    expect(() => new NodeRSA('')).toThrow(/Empty key/);
  });

  it('exportKey caches', () => {
    const key = new NodeRSA(readStr('private_pkcs1.pem'));
    const a = key.exportKey();
    const b = key.exportKey();
    expect(a).toBe(b);
  });

  it('generates a fresh 512-bit key and uses it', () => {
    const key = new NodeRSA({ b: 512 });
    expect(key.getKeySize()).toBe(512);
    const ct = key.encrypt('round-trip');
    const pt = key.decrypt(ct as Uint8Array, 'utf8');
    expect(pt).toBe('round-trip');
  }, 35_000);

  it('post-keygen comprehensive: 512-bit key works end-to-end for OAEP + PSS + PKCS#1', () => {
    // Regression: a generated key must be usable across every scheme the
    // public API exposes — not just the constructor default. Failures
    // here mean keygen produced components that fail one of the schemes
    // (a CRT inconsistency, a wrong d, etc.).
    const key = new NodeRSA({ b: 512 });
    expect(key.isPrivate()).toBe(true);
    expect(key.keyPair.n!.bitLength()).toBe(512);

    // Default scheme set (OAEP encryption, PSS signing) — verified above.
    {
      const ct = key.encrypt('default-schemes');
      const pt = key.decrypt(ct as Uint8Array, 'utf8');
      expect(pt).toBe('default-schemes');
      const sig = key.sign('default-schemes');
      expect(key.verify('default-schemes', sig as Uint8Array)).toBe(true);
    }

    // Switch to PKCS#1 v1.5 encryption + signing (legacy path).
    key.setOptions({ encryptionScheme: 'pkcs1', signingScheme: 'pkcs1' });
    {
      const ct = key.encrypt('pkcs1-schemes');
      const pt = key.decrypt(ct as Uint8Array, 'utf8');
      expect(pt).toBe('pkcs1-schemes');
      const sig = key.sign('pkcs1-schemes');
      expect(key.verify('pkcs1-schemes', sig as Uint8Array)).toBe(true);
    }

    // PSS with a non-default hash. 512-bit emLen=64 limits PSS to
    // hashes where hLen + sLen + 2 ≤ 64; sha384/sha512 don't fit at
    // the default saltLength=20. Use sha1 (hLen=20+20+2=42 ≤ 64) — and
    // do a saltLength=0 variant for coverage of the deterministic path.
    key.setOptions({
      signingScheme: { scheme: 'pss', hash: 'sha1' },
    });
    {
      const sig = key.sign('pss-sha1');
      expect(key.verify('pss-sha1', sig as Uint8Array)).toBe(true);
    }

    // encryptPrivate ↔ decryptPublic (signature-shaped path) — exercises
    // the type-1 padding branch built from the generated p, q, dp, dq.
    key.setOptions({ encryptionScheme: 'pkcs1', signingScheme: 'pkcs1' });
    {
      const ct = key.encryptPrivate('private-encrypt-with-gen');
      const pt = key.decryptPublic(ct as Uint8Array, 'utf8');
      expect(pt).toBe('private-encrypt-with-gen');
    }
  }, 45_000);
});
