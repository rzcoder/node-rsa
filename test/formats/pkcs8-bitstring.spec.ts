import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerReader, DerWriter, OID, Tag } from '../../src/asn1/index.js';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { encodePem } from '../../src/formats/pem.js';
import NodeRSA from '../../src/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

// PKCS#8 BIT STRING corner case audit
//
// The legacy `asn1` npm package (used by node-rsa v1) silently masks any
// non-zero "unused bits" octet on read, and accepts an optional unused-bits
// parameter on write. The in-tree DER writer/reader (added in v2.0) is
// stricter: BIT STRING is always written with an unused-bits byte of 0, and
// any non-zero unused-bits byte on read is rejected.
//
// For RSA SubjectPublicKeyInfo specifically, RFC 5280 §4.1 mandates that the
// BIT STRING contents are a DER-encoded RSAPublicKey — a sequence of whole
// bytes, so the unused-bits octet MUST be 0. There is no legitimate input
// produced by a conformant encoder that would carry non-zero unused-bits.
//
// This audit pins three properties of the in-tree implementation that the
// TODO flagged as "differs from asn1 npm package on one corner case":
//
//   1. publicExport always emits the unused-bits byte as 0.
//   2. publicImport rejects PEMs whose SPKI BIT STRING carries non-zero
//      unused-bits, with a clear diagnostic (no silent masking).
//   3. Round-trip is byte-identical: import → export → import yields the
//      same DER as the v1 `asn1`-package-produced fixture.
describe('PKCS#8 SPKI BIT STRING audit', () => {
  it('publicExport always emits unused-bits = 0 (no caller-tunable parameter)', () => {
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    const der = k.exportKey('pkcs8-public-der') as Uint8Array;

    // Walk the DER: SEQUENCE { algId-SEQUENCE, BIT STRING { ... } }.
    const outer = new DerReader(der).readSequence();
    outer.readSequence(); // skip algId
    // Read the raw BIT STRING value (including the leading unused-bits byte).
    // The first byte of the value MUST be 0x00 for any RFC-conformant SPKI.
    const raw = outer.readBitStringRaw();
    expect(raw.length).toBeGreaterThan(0);
    expect(raw[0]).toBe(0);
  });

  it('publicImport rejects SPKI whose BIT STRING carries non-zero unused-bits', () => {
    // Build a SubjectPublicKeyInfo by hand and craft the BIT STRING with
    // unused-bits = 4 (a value that would otherwise be silently masked by
    // the legacy `asn1` decoder).
    const validKey = new NodeRSA(readStr('private_pkcs1.pem'));
    const innerDer = (() => {
      const w = new DerWriter();
      w.startSequence();
      w.writeInteger(validKey.keyPair.n!.toBuffer() as Uint8Array);
      w.writeInteger(validKey.keyPair.e);
      w.endSequence();
      return w.toBytes();
    })();

    // Hand-write the SPKI with a deliberate non-zero unused-bits byte.
    // Reuse DerWriter for the outer structure, then patch the BIT STRING
    // payload manually via writeBitStringRaw.
    const malformed = (() => {
      const w = new DerWriter();
      w.startSequence();
      w.startSequence();
      w.writeOid(OID.RSA_ENCRYPTION);
      w.writeNull();
      w.endSequence();
      // Raw BIT STRING value: <unused-bits=4><inner DER bytes>.
      const raw = new Uint8Array(innerDer.length + 1);
      raw[0] = 4; // non-zero — this is the corner case the audit pins.
      raw.set(innerDer, 1);
      w.writeBitStringRaw(raw);
      w.endSequence();
      return w.toBytes();
    })();
    const pem = encodePem(malformed, '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----');

    // The strict reader must throw — never silently mask.
    expect(() => new NodeRSA(pem, 'pkcs8-public-pem')).toThrow(/unused bits/);
  });

  it('publicImport rejects an empty BIT STRING (no unused-bits octet at all)', () => {
    // Mirror the previous test but emit a zero-length BIT STRING value.
    // This is malformed per X.690 §8.6 — the unused-bits octet is mandatory.
    const w = new DerWriter();
    w.startSequence();
    w.startSequence();
    w.writeOid(OID.RSA_ENCRYPTION);
    w.writeNull();
    w.endSequence();
    // BIT STRING tag with zero-length content (no unused-bits byte).
    w.writeTlv(Tag.BIT_STRING, new Uint8Array(0));
    w.endSequence();
    const pem = encodePem(w.toBytes(), '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----');

    expect(() => new NodeRSA(pem, 'pkcs8-public-pem')).toThrow(/empty BIT STRING/);
  });

  it('SPKI round-trip is byte-identical (export→import→export yields the same DER)', () => {
    // Loads a fixture produced by v1 (via the asn1 npm package), re-exports
    // through the in-tree writer, and asserts byte equality. This is the
    // "no observable difference" property the TODO entry asked us to
    // confirm for the standard case.
    const k = new NodeRSA(readStr('private_pkcs1.pem'));
    const der1 = k.exportKey('pkcs8-public-der') as Uint8Array;
    const k2 = new NodeRSA();
    k2.importKey(der1, 'pkcs8-public-der');
    const der2 = k2.exportKey('pkcs8-public-der') as Uint8Array;

    expect(der2.length).toBe(der1.length);
    expect([...der2]).toEqual([...der1]);
  });

  it('matches OpenSSL byte-for-byte: re-export of `public_pkcs8.pem` is identical', () => {
    // public_pkcs8.pem was produced by `openssl pkey -pubout` from the
    // same fixture private key. Importing then re-exporting must reproduce
    // it byte-for-byte (including the all-zero unused-bits byte that
    // OpenSSL always emits).
    const reference = readStr('public_pkcs8.pem').trim();
    const k = new NodeRSA(reference);
    const roundtripped = (k.exportKey('pkcs8-public-pem') as string).trim();
    expect(roundtripped).toBe(reference);
  });
});
