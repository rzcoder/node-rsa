import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DerReader, DerWriter } from '../../src/asn1/index.js';
import { toHex } from '../../src/crypto/bytes.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../../test/keys');

function loadDer(name: string): Uint8Array {
  const buf = readFileSync(resolve(keysDir, name));
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Generic DER tree walker. Recurses into SEQUENCE and copies primitive TLVs
 * verbatim. Round-tripping a well-formed DER document through this should
 * produce byte-identical output.
 */
function roundTrip(bytes: Uint8Array): Uint8Array {
  const w = new DerWriter();
  copyAll(new DerReader(bytes), w);
  return w.toBytes();
}

function copyAll(r: DerReader, w: DerWriter): void {
  while (r.hasMore()) {
    const { tag, value } = r.readTlv();
    if (tag === 0x30 /* SEQUENCE */) {
      w.startSequence();
      copyAll(new DerReader(value), w);
      w.endSequence();
    } else {
      w.writeTlv(tag, value);
    }
  }
}

describe('DER fixture round-trip', () => {
  const FIXTURES = [
    'private_pkcs1.der',
    'private_pkcs8.der',
    'public_pkcs1.der',
    'public_pkcs8.der',
  ];

  for (const name of FIXTURES) {
    it(`${name} round-trips byte-identical`, () => {
      const original = loadDer(name);
      const out = roundTrip(original);
      expect(toHex(out)).toBe(toHex(original));
    });
  }
});

describe('PKCS#1 public key fixture inspection', () => {
  it('parses the public key structure', () => {
    const bytes = loadDer('public_pkcs1.der');
    const seq = new DerReader(bytes).readSequence();
    const n = seq.readInteger();
    const e = seq.readSmallInteger();
    expect(e).toBe(65537);
    // Modulus byte length (with optional 0x00 sign prefix) is multiple-of-8
    // bytes plus 0..1. For a 1024-bit fixture: 128 or 129.
    expect(n.length).toBeGreaterThan(60);
    expect(n.length % 8 === 0 || (n.length - 1) % 8 === 0).toBe(true);
  });
});

describe('PKCS#1 private key fixture inspection', () => {
  it('parses the private key structure', () => {
    const bytes = loadDer('private_pkcs1.der');
    const seq = new DerReader(bytes).readSequence();
    expect(seq.readSmallInteger()).toBe(0); // version
    const n = seq.readInteger();
    const e = seq.readSmallInteger();
    seq.readInteger(); // d
    const p = seq.readInteger();
    const q = seq.readInteger();
    seq.readInteger(); // dmp1
    seq.readInteger(); // dmq1
    seq.readInteger(); // coeff
    expect(e).toBe(65537);
    // p and q should each be roughly half the modulus length.
    expect(Math.abs(p.length - q.length)).toBeLessThanOrEqual(1);
    expect(p.length * 2).toBeGreaterThanOrEqual(n.length - 2);
  });
});

describe('PKCS#8 public key fixture inspection', () => {
  it('contains the rsaEncryption OID and an embedded SubjectPublicKey BIT STRING', () => {
    const bytes = loadDer('public_pkcs8.der');
    const outer = new DerReader(bytes).readSequence();
    const header = outer.readSequence();
    expect(header.readOid()).toBe('1.2.840.113549.1.1.1');
    header.readNull();
    const bitContent = outer.readBitString();
    const inner = new DerReader(bitContent).readSequence();
    inner.readInteger(); // n
    expect(inner.readSmallInteger()).toBe(65537);
  });
});

describe('PKCS#8 private key fixture inspection', () => {
  it('contains version=0, rsaEncryption OID, and an embedded OCTET STRING private key body', () => {
    const bytes = loadDer('private_pkcs8.der');
    const outer = new DerReader(bytes).readSequence();
    expect(outer.readSmallInteger()).toBe(0);
    const header = outer.readSequence();
    expect(header.readOid()).toBe('1.2.840.113549.1.1.1');
    header.readNull();
    const inner = new DerReader(outer.readOctetString()).readSequence();
    expect(inner.readSmallInteger()).toBe(0);
    inner.readInteger(); // n
    expect(inner.readSmallInteger()).toBe(65537);
  });
});
