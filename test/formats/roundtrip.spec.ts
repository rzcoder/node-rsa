import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { toHex, toUtf8 } from '../../src/crypto/bytes.js';
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
    expect(dst.n?.toBuffer() as Uint8Array).toEqual(src.n?.toBuffer() as Uint8Array);
    expect(dst.e).toBe(src.e);
    expect(dst.d?.toBuffer() as Uint8Array).toEqual(src.d?.toBuffer() as Uint8Array);
  });

  it('rejects missing private fields', () => {
    const key = new RSAKey();
    expect(() => componentsFormat.privateImport?.(key, { n: new Uint8Array([1, 2]) })).toThrow();
  });

  it('round-trips a public key through { n, e }', () => {
    const src = new RSAKey();
    pkcs1Format.publicImport?.(src, readBin('public_pkcs1.der'), { type: 'der' });
    expect(src.isPublic()).toBe(true);
    const components = componentsFormat.publicExport?.(src) as Record<string, unknown>;
    expect(components).toHaveProperty('n');
    expect(components).toHaveProperty('e');
    const dst = new RSAKey();
    componentsFormat.publicImport?.(dst, components);
    expect(dst.isPublic()).toBe(true);
    expect(dst.isPrivate()).toBe(false);
    expect(dst.n?.toBuffer() as Uint8Array).toEqual(src.n?.toBuffer() as Uint8Array);
    expect(dst.e).toBe(src.e);
  });

  it('rejects missing public fields (no n)', () => {
    const key = new RSAKey();
    expect(() => componentsFormat.publicImport?.(key, { e: 65537 })).toThrow();
  });
});

describe('cross-format equivalence — same key parsed three ways yields identical components', () => {
  // The PKCS#1, PKCS#8, and OpenSSH fixtures in test/keys/ are all
  // serialisations of the same RSA key. A parse mismatch (a renamed CRT
  // field, an off-by-one in OpenSSH's component order — which is
  // n,e,d,coeff,p,q not n,e,d,p,q,coeff — etc.) would silently let one
  // format diverge while the others keep round-tripping. This test pins
  // the invariant directly.
  it('PKCS#1 DER ≡ PKCS#8 DER ≡ OpenSSH (n,e,d,p,q,dmp1,dmq1,coeff)', () => {
    const fromPkcs1 = new RSAKey();
    pkcs1Format.privateImport?.(fromPkcs1, readBin('private_pkcs1.der'), { type: 'der' });

    const fromPkcs8 = new RSAKey();
    pkcs8Format.privateImport?.(fromPkcs8, readBin('private_pkcs8.der'), { type: 'der' });

    const fromOpenssh = new RSAKey();
    opensshFormat.privateImport?.(fromOpenssh, readStr('id_rsa'));

    const fields: Array<'n' | 'd' | 'p' | 'q' | 'dmp1' | 'dmq1' | 'coeff'> = [
      'n',
      'd',
      'p',
      'q',
      'dmp1',
      'dmq1',
      'coeff',
    ];
    for (const f of fields) {
      const a = fromPkcs1[f]?.toBuffer() as Uint8Array;
      const b = fromPkcs8[f]?.toBuffer() as Uint8Array;
      const c = fromOpenssh[f]?.toBuffer() as Uint8Array;
      expect(toHex(b), `PKCS#1 vs PKCS#8: ${f}`).toBe(toHex(a));
      expect(toHex(c), `PKCS#1 vs OpenSSH: ${f}`).toBe(toHex(a));
    }
    expect(fromPkcs8.e).toBe(fromPkcs1.e);
    expect(fromOpenssh.e).toBe(fromPkcs1.e);
  });

  it('public PKCS#1 DER ≡ public PKCS#8 DER (n, e)', () => {
    const fromPkcs1 = new RSAKey();
    pkcs1Format.publicImport?.(fromPkcs1, readBin('public_pkcs1.der'), { type: 'der' });
    const fromPkcs8 = new RSAKey();
    pkcs8Format.publicImport?.(fromPkcs8, readBin('public_pkcs8.der'), { type: 'der' });
    expect(toHex(fromPkcs8.n?.toBuffer() as Uint8Array)).toBe(
      toHex(fromPkcs1.n?.toBuffer() as Uint8Array),
    );
    expect(fromPkcs8.e).toBe(fromPkcs1.e);
  });

  it('id_rsa_comment.pub preserves a non-empty SSH comment', () => {
    // id_rsa_comment.pub carries a non-empty trailing comment that gets
    // routed into key.sshcomment. Lets us round-trip through publicExport
    // and confirm the comment survives.
    const key = new RSAKey();
    opensshFormat.publicImport?.(key, readStr('id_rsa_comment.pub'));
    expect(key.sshcomment).toBeDefined();
    expect((key.sshcomment as string).length).toBeGreaterThan(0);
    const re = opensshFormat.publicExport?.(key) as string;
    // Export format: "ssh-rsa <b64> <comment>\n" — comment must appear.
    expect(re).toContain(key.sshcomment as string);
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
