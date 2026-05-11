import { DerReader, DerWriter, OID } from '../asn1/index.js';
import type { RSAKey } from '../rsa/key.js';
import { decodePem, encodePem } from './pem.js';
import type { ExportOptions, FormatProvider, ImportOptions } from './types.js';

const PRIVATE_OPENING = '-----BEGIN PRIVATE KEY-----';
const PRIVATE_CLOSING = '-----END PRIVATE KEY-----';
const PUBLIC_OPENING = '-----BEGIN PUBLIC KEY-----';
const PUBLIC_CLOSING = '-----END PUBLIC KEY-----';

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
    outer.readSmallInteger(); // version
    const header = outer.readSequence();
    if (header.readOid() !== OID.RSA_ENCRYPTION) throw new Error('Invalid Public key format');
    header.readNull();
    const body = new DerReader(outer.readOctetString()).readSequence();
    body.readSmallInteger(); // PKCS#1 inner version
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
    if (header.readOid() !== OID.RSA_ENCRYPTION) throw new Error('Invalid Public key format');
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

function resolveBytes(
  data: Uint8Array | string,
  options: ImportOptions,
  opening: string,
  closing: string,
): Uint8Array {
  if (options.type === 'der') {
    if (data instanceof Uint8Array) return data;
    throw new Error('Unsupported key format');
  }
  if (data instanceof Uint8Array) {
    return decodePem(new TextDecoder().decode(data), opening, closing);
  }
  if (typeof data === 'string') {
    return decodePem(data, opening, closing);
  }
  throw new Error('Unsupported key format');
}
