import { DerReader, DerWriter } from '../asn1/index.js';
import type { RSAKey } from '../rsa/key.js';
import { encodePem, resolveBytes } from './pem.js';
import type { ExportOptions, FormatProvider, ImportOptions } from './types.js';

const PRIVATE_OPENING = '-----BEGIN RSA PRIVATE KEY-----';
const PRIVATE_CLOSING = '-----END RSA PRIVATE KEY-----';
const PUBLIC_OPENING = '-----BEGIN RSA PUBLIC KEY-----';
const PUBLIC_CLOSING = '-----END RSA PUBLIC KEY-----';

/** PKCS#1 (RFC 8017 §A.1) — `RSA PRIVATE KEY` / `RSA PUBLIC KEY` PEM, or raw DER. */
export const pkcs1Format: FormatProvider = {
  privateExport(key: RSAKey, options: ExportOptions = {}): Uint8Array | string {
    if (!key.n || !key.d || !key.p || !key.q || !key.dmp1 || !key.dmq1 || !key.coeff) {
      throw new Error('PKCS#1 export: incomplete private key');
    }
    const w = new DerWriter();
    w.startSequence();
    w.writeInteger(0);
    w.writeInteger(key.n.toBuffer() as Uint8Array);
    w.writeInteger(key.e);
    w.writeInteger(key.d.toBuffer() as Uint8Array);
    w.writeInteger(key.p.toBuffer() as Uint8Array);
    w.writeInteger(key.q.toBuffer() as Uint8Array);
    w.writeInteger(key.dmp1.toBuffer() as Uint8Array);
    w.writeInteger(key.dmq1.toBuffer() as Uint8Array);
    w.writeInteger(key.coeff.toBuffer() as Uint8Array);
    w.endSequence();
    const bytes = w.toBytes();
    return options.type === 'der' ? bytes : encodePem(bytes, PRIVATE_OPENING, PRIVATE_CLOSING);
  },

  privateImport(key: RSAKey, data: Uint8Array | string, options: ImportOptions = {}): void {
    const buffer = resolveBytes(data, options, PRIVATE_OPENING, PRIVATE_CLOSING);
    const seq = new DerReader(buffer).readSequence();
    seq.readSmallInteger(); // version
    const n = seq.readInteger();
    const e = seq.readSmallInteger();
    const d = seq.readInteger();
    const p = seq.readInteger();
    const q = seq.readInteger();
    const dmp1 = seq.readInteger();
    const dmq1 = seq.readInteger();
    const coeff = seq.readInteger();
    key.setPrivate(n, e, d, p, q, dmp1, dmq1, coeff);
  },

  publicExport(key: RSAKey, options: ExportOptions = {}): Uint8Array | string {
    if (!key.n) throw new Error('PKCS#1 export: missing modulus');
    const w = new DerWriter();
    w.startSequence();
    w.writeInteger(key.n.toBuffer() as Uint8Array);
    w.writeInteger(key.e);
    w.endSequence();
    const bytes = w.toBytes();
    return options.type === 'der' ? bytes : encodePem(bytes, PUBLIC_OPENING, PUBLIC_CLOSING);
  },

  publicImport(key: RSAKey, data: Uint8Array | string, options: ImportOptions = {}): void {
    const buffer = resolveBytes(data, options, PUBLIC_OPENING, PUBLIC_CLOSING);
    const seq = new DerReader(buffer).readSequence();
    const n = seq.readInteger();
    const e = seq.readSmallInteger();
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
      /^[\S\s]*-----BEGIN RSA PRIVATE KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END RSA PRIVATE KEY-----[\S\s]*$/g.test(
        text,
      )
    ) {
      pkcs1Format.privateImport?.(key, text);
      return true;
    }
    if (
      /^[\S\s]*-----BEGIN RSA PUBLIC KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END RSA PUBLIC KEY-----[\S\s]*$/g.test(
        text,
      )
    ) {
      pkcs1Format.publicImport?.(key, text);
      return true;
    }
    return false;
  },
};
