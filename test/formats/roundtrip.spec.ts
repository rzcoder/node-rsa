import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { equals, toHex, toUtf8 } from '../../src/crypto/bytes.js';
import {
  componentsFormat,
  detectAndExport,
  detectAndImport,
  opensshFormat,
  pkcs1Format,
  pkcs8Format,
} from '../../src/formats/index.js';
import { RSAKey } from '../../src/rsa/key.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../../test/keys');

function readBin(name: string): Uint8Array {
  const buf = readFileSync(resolve(keysDir, name));
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

describe('PKCS#1 DER round-trip', () => {
  it('private_pkcs1.der → import → export → byte-identical', () => {
    const orig = readBin('private_pkcs1.der');
    const key = new RSAKey();
    pkcs1Format.privateImport?.(key, orig, { type: 'der' });
    expect(key.isPrivate()).toBe(true);
    const re = pkcs1Format.privateExport?.(key, { type: 'der' }) as Uint8Array;
    expect(toHex(re)).toBe(toHex(orig));
  });

  it('public_pkcs1.der → import → export → byte-identical', () => {
    const orig = readBin('public_pkcs1.der');
    const key = new RSAKey();
    pkcs1Format.publicImport?.(key, orig, { type: 'der' });
    expect(key.isPublic()).toBe(true);
    const re = pkcs1Format.publicExport?.(key, { type: 'der' }) as Uint8Array;
    expect(toHex(re)).toBe(toHex(orig));
  });
});

describe('PKCS#1 PEM round-trip', () => {
  it('private_pkcs1.pem → import → export → byte-equal trimmed', () => {
    const orig = readStr('private_pkcs1.pem');
    const key = new RSAKey();
    pkcs1Format.privateImport?.(key, orig);
    const re = pkcs1Format.privateExport?.(key) as string;
    expect(stripPem(re)).toBe(stripPem(orig));
  });

  it('public_pkcs1.pem → import → export → byte-equal trimmed', () => {
    const orig = readStr('public_pkcs1.pem');
    const key = new RSAKey();
    pkcs1Format.publicImport?.(key, orig);
    const re = pkcs1Format.publicExport?.(key) as string;
    expect(stripPem(re)).toBe(stripPem(orig));
  });
});

describe('PKCS#8 DER round-trip', () => {
  it('private_pkcs8.der', () => {
    const orig = readBin('private_pkcs8.der');
    const key = new RSAKey();
    pkcs8Format.privateImport?.(key, orig, { type: 'der' });
    const re = pkcs8Format.privateExport?.(key, { type: 'der' }) as Uint8Array;
    expect(toHex(re)).toBe(toHex(orig));
  });

  it('public_pkcs8.der', () => {
    const orig = readBin('public_pkcs8.der');
    const key = new RSAKey();
    pkcs8Format.publicImport?.(key, orig, { type: 'der' });
    const re = pkcs8Format.publicExport?.(key, { type: 'der' }) as Uint8Array;
    expect(toHex(re)).toBe(toHex(orig));
  });
});

describe('PKCS#8 PEM round-trip', () => {
  it('private_pkcs8.pem', () => {
    const orig = readStr('private_pkcs8.pem');
    const key = new RSAKey();
    pkcs8Format.privateImport?.(key, orig);
    const re = pkcs8Format.privateExport?.(key) as string;
    expect(stripPem(re)).toBe(stripPem(orig));
  });

  it('public_pkcs8.pem', () => {
    const orig = readStr('public_pkcs8.pem');
    const key = new RSAKey();
    pkcs8Format.publicImport?.(key, orig);
    const re = pkcs8Format.publicExport?.(key) as string;
    expect(stripPem(re)).toBe(stripPem(orig));
  });
});

describe('OpenSSH round-trip', () => {
  it('id_rsa.pub (public key) parses and round-trips', () => {
    const orig = readStr('id_rsa.pub');
    const key = new RSAKey();
    opensshFormat.publicImport?.(key, orig);
    expect(key.isPublic()).toBe(true);
    const re = opensshFormat.publicExport?.(key) as string;
    // OpenSSH public format: "ssh-rsa BASE64 [comment]\n"
    expect(re.startsWith('ssh-rsa ')).toBe(true);
    // Round trip the base64 part
    expect(extractB64(re)).toBe(extractB64(orig));
  });

  it('id_rsa (private key) parses and round-trips', () => {
    const orig = readStr('id_rsa');
    const key = new RSAKey();
    opensshFormat.privateImport?.(key, orig);
    expect(key.isPrivate()).toBe(true);
    const re = opensshFormat.privateExport?.(key) as string;
    expect(stripPem(re)).toBe(stripPem(orig));
  });

  it('id_rsa_comment preserves the comment field', () => {
    const orig = readStr('id_rsa_comment.pub');
    const key = new RSAKey();
    opensshFormat.publicImport?.(key, orig);
    expect(key.sshcomment).toBeDefined();
    expect(key.sshcomment).not.toBe('');
  });
});

describe('components format', () => {
  it('round-trips a key through { n, e, d, p, q, dmp1, dmq1, coeff }', () => {
    const src = new RSAKey();
    pkcs1Format.privateImport?.(src, readBin('private_pkcs1.der'), { type: 'der' });
    const components = componentsFormat.privateExport?.(src) as Record<string, unknown>;
    const dst = new RSAKey();
    componentsFormat.privateImport?.(dst, components);
    expect(equals(dst.n?.toBuffer() as Uint8Array, src.n?.toBuffer() as Uint8Array)).toBe(true);
    expect(dst.e).toBe(src.e);
    expect(equals(dst.d?.toBuffer() as Uint8Array, src.d?.toBuffer() as Uint8Array)).toBe(true);
  });

  it('rejects missing private fields', () => {
    const key = new RSAKey();
    expect(() => componentsFormat.privateImport?.(key, { n: new Uint8Array([1, 2]) })).toThrow();
  });
});

describe('detectAndImport / detectAndExport', () => {
  it('detects PKCS#1 PEM private', () => {
    const key = new RSAKey();
    expect(detectAndImport(key, readStr('private_pkcs1.pem'))).toBe(true);
    expect(key.isPrivate()).toBe(true);
  });

  it('detects PKCS#8 PEM public', () => {
    const key = new RSAKey();
    expect(detectAndImport(key, readStr('public_pkcs8.pem'))).toBe(true);
    expect(key.isPublic()).toBe(true);
  });

  it('explicit format string drives export', () => {
    const key = new RSAKey();
    pkcs1Format.privateImport?.(key, readBin('private_pkcs1.der'), { type: 'der' });
    const pem = detectAndExport(key, 'pkcs8-private-pem') as string;
    expect(pem).toContain('BEGIN PRIVATE KEY');
  });

  it('throws when exporting private from a public-only key', () => {
    const key = new RSAKey();
    pkcs1Format.publicImport?.(key, readBin('public_pkcs1.der'), { type: 'der' });
    expect(() => detectAndExport(key, 'pkcs1-private-pem')).toThrow(/not private/);
  });

  it('throws for unsupported format', () => {
    const key = new RSAKey();
    pkcs1Format.privateImport?.(key, readBin('private_pkcs1.der'), { type: 'der' });
    expect(() => detectAndExport(key, 'magic-private-pem')).toThrow(/Unsupported/);
  });
});

function stripPem(s: string): string {
  return s.replace(/\r?\n/g, '\n').trim();
}

function extractB64(s: string): string {
  // "ssh-rsa <b64> [comment]\n" → return <b64>
  const after = s.replace(/^ssh-rsa\s+/, '');
  const space = after.indexOf(' ');
  const b64 = space === -1 ? after : after.substring(0, space);
  return b64.trim();
}

// Suppress unused warning
void toUtf8;
