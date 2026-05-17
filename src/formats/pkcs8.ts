import { DerReader, DerWriter, OID } from '../asn1/index.js';
import type { RSAKey } from '../rsa/key.js';
import { encodePem, resolveBytes } from './pem.js';
import type { ExportOptions, FormatProvider, ImportOptions } from './types.js';

const PRIVATE_OPENING = '-----BEGIN PRIVATE KEY-----';
const PRIVATE_CLOSING = '-----END PRIVATE KEY-----';
const PUBLIC_OPENING = '-----BEGIN PUBLIC KEY-----';
const PUBLIC_CLOSING = '-----END PUBLIC KEY-----';

/**
 * PKCS#8 (RFC 5958) — `PRIVATE KEY` / `PUBLIC KEY` PEM, or raw DER. Wraps a
 * PKCS#1 body inside an algorithm-id envelope; only `rsaEncryption` OID is
 * accepted (RSASSA-PSS / RSAES-OAEP variants are rejected with a clear error).
 */
export const pkcs8Format: FormatProvider = {
  privateExport(key: RSAKey, options: ExportOptions = {}): Uint8Array | string {
    if (!key.n || !key.d || !key.p || !key.q || !key.dmp1 || !key.dmq1 || !key.coeff) {
      throw new Error('PKCS#8 export: incomplete private key');
    }
    // Inner: PKCS#1 private key body
    const body = new DerWriter();
    body.startSequence();
    body.writeInteger(0);
    body.writeInteger(key.n.toBuffer() as Uint8Array);
    body.writeInteger(key.e);
    body.writeInteger(key.d.toBuffer() as Uint8Array);
    body.writeInteger(key.p.toBuffer() as Uint8Array);
    body.writeInteger(key.q.toBuffer() as Uint8Array);
    body.writeInteger(key.dmp1.toBuffer() as Uint8Array);
    body.writeInteger(key.dmq1.toBuffer() as Uint8Array);
    body.writeInteger(key.coeff.toBuffer() as Uint8Array);
    body.endSequence();

    const w = new DerWriter();
    w.startSequence();
    w.writeInteger(0); // version
    w.startSequence();
    w.writeOid(OID.RSA_ENCRYPTION);
    w.writeNull();
    w.endSequence();
    w.writeOctetString(body.toBytes());
    w.endSequence();

    const bytes = w.toBytes();
    return options.type === 'der' ? bytes : encodePem(bytes, PRIVATE_OPENING, PRIVATE_CLOSING);
  },

  privateImport(key: RSAKey, data: Uint8Array | string, options: ImportOptions = {}): void {
    const buffer = resolveBytes(data, options, PRIVATE_OPENING, PRIVATE_CLOSING);
    const outer = new DerReader(buffer).readSequence();
    // RFC 5958 §2: PrivateKeyInfo / OneAsymmetricKey version ∈ {0, 1}.
    const outerVersion = outer.readSmallInteger();
    if (outerVersion !== 0 && outerVersion !== 1) {
      throw new Error(`PKCS#8: unsupported version ${outerVersion} (RFC 5958 §2 requires 0 or 1)`);
    }
    const header = outer.readSequence();
    const oid = header.readOid();
    if (oid !== OID.RSA_ENCRYPTION) {
      throw pkcs8OidError(oid, 'private');
    }
    header.readNull();
    const body = new DerReader(outer.readOctetString()).readSequence();
    // RFC 8017 §A.1.2: 0 = two-prime, 1 = multi-prime. Two-prime only.
    const innerVersion = body.readSmallInteger();
    if (innerVersion !== 0) {
      throw new Error(
        `PKCS#8: PKCS#1 multi-prime keys (version ${innerVersion}) are not supported`,
      );
    }
    const n = body.readInteger();
    const e = body.readSmallInteger();
    const d = body.readInteger();
    const p = body.readInteger();
    const q = body.readInteger();
    const dmp1 = body.readInteger();
    const dmq1 = body.readInteger();
    const coeff = body.readInteger();
    key.setPrivate(n, e, d, p, q, dmp1, dmq1, coeff);
  },

  publicExport(key: RSAKey, options: ExportOptions = {}): Uint8Array | string {
    if (!key.n) throw new Error('PKCS#8 export: missing modulus');
    // Inner: SEQUENCE { n, e }
    const inner = new DerWriter();
    inner.startSequence();
    inner.writeInteger(key.n.toBuffer() as Uint8Array);
    inner.writeInteger(key.e);
    inner.endSequence();

    const w = new DerWriter();
    w.startSequence();
    w.startSequence();
    w.writeOid(OID.RSA_ENCRYPTION);
    w.writeNull();
    w.endSequence();
    w.writeBitString(inner.toBytes());
    w.endSequence();

    const bytes = w.toBytes();
    return options.type === 'der' ? bytes : encodePem(bytes, PUBLIC_OPENING, PUBLIC_CLOSING);
  },

  publicImport(key: RSAKey, data: Uint8Array | string, options: ImportOptions = {}): void {
    const buffer = resolveBytes(data, options, PUBLIC_OPENING, PUBLIC_CLOSING);
    const outer = new DerReader(buffer).readSequence();
    const header = outer.readSequence();
    const oid = header.readOid();
    if (oid !== OID.RSA_ENCRYPTION) {
      throw pkcs8OidError(oid, 'public');
    }
    header.readNull();
    const inner = new DerReader(outer.readBitString()).readSequence();
    const n = inner.readInteger();
    const e = inner.readSmallInteger();
    key.setPublic(n, e);
  },

  autoImport(key: RSAKey, data: unknown): boolean {
    const text =
      typeof data === 'string'
        ? data
        : data instanceof Uint8Array
          ? new TextDecoder().decode(data)
          : null;
    if (text === null) return false;
    if (
      /^[\S\s]*-----BEGIN PRIVATE KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END PRIVATE KEY-----[\S\s]*$/g.test(
        text,
      )
    ) {
      pkcs8Format.privateImport?.(key, text);
      return true;
    }
    if (
      /^[\S\s]*-----BEGIN PUBLIC KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END PUBLIC KEY-----[\S\s]*$/g.test(
        text,
      )
    ) {
      pkcs8Format.publicImport?.(key, text);
      return true;
    }
    return false;
  },
};

/**
 * RFC 5958 §2 and RFC 8017 require rsaEncryption (1.2.840.113549.1.1.1)
 * in the PKCS#8 privateKeyAlgorithm field — not PSS/OAEP-specific OIDs.
 * Some implementations get this wrong; surface a clear diagnostic instead
 * of a generic "invalid format" that tempts maintainers to relax the check.
 */
function pkcs8OidError(oid: string, kind: 'private' | 'public'): Error {
  if (oid === '1.2.840.113549.1.1.10') {
    return new Error(
      `PKCS#8 ${kind} key: RSASSA-PSS-only keys (1.2.840.113549.1.1.10) are not supported; expected rsaEncryption`,
    );
  }
  if (oid === '1.2.840.113549.1.1.7') {
    return new Error(
      `PKCS#8 ${kind} key: RSAES-OAEP-only keys (1.2.840.113549.1.1.7) are not supported; expected rsaEncryption`,
    );
  }
  return new Error(
    `PKCS#8 ${kind} key: unsupported algorithm OID ${oid}; expected rsaEncryption (1.2.840.113549.1.1.1)`,
  );
}
