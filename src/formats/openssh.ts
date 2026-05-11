import { BigInteger } from '../bigint/big-integer.js';
import {
  concat,
  fromBase64,
  fromUtf8,
  readUInt32BE,
  toBase64,
  toUtf8,
  writeUInt32BE,
} from '../crypto/bytes.js';
import type { RSAKey } from '../rsa/key.js';
import { linebrk, trimSurroundingText } from './pem.js';
import type { ExportOptions, FormatProvider, ImportOptions } from './types.js';

const PRIVATE_OPENING = '-----BEGIN OPENSSH PRIVATE KEY-----';
const PRIVATE_CLOSING = '-----END OPENSSH PRIVATE KEY-----';

export const opensshFormat: FormatProvider = {
  privateExport(key: RSAKey, options: ExportOptions = {}): Uint8Array | string {
    if (!key.n || !key.d || !key.p || !key.q || !key.coeff) {
      throw new Error('OpenSSH export: incomplete private key');
    }

    const nbuf = key.n.toBuffer() as Uint8Array;
    let ebuf = new Uint8Array(4);
    writeUInt32BE(key.e, ebuf, 0);
    // Strip leading zero bytes
    while (ebuf.length > 0 && ebuf[0] === 0) ebuf = ebuf.subarray(1);

    const dbuf = key.d.toBuffer() as Uint8Array;
    const coeffbuf = key.coeff.toBuffer() as Uint8Array;
    const pbuf = key.p.toBuffer() as Uint8Array;
    const qbuf = key.q.toBuffer() as Uint8Array;
    const commentbuf = key.sshcomment ? fromUtf8(key.sshcomment) : new Uint8Array(0);

    const pubkeyLength = 11 + 4 + ebuf.byteLength + 4 + nbuf.byteLength;
    const privateKeyLength =
      8 +
      11 +
      4 +
      nbuf.byteLength +
      4 +
      ebuf.byteLength +
      4 +
      dbuf.byteLength +
      4 +
      coeffbuf.byteLength +
      4 +
      pbuf.byteLength +
      4 +
      qbuf.byteLength +
      4 +
      commentbuf.byteLength;
    const paddingLength = Math.ceil(privateKeyLength / 8) * 8 - privateKeyLength;
    const totalLength = 15 + 16 + 4 + 4 + 4 + pubkeyLength + 4 + privateKeyLength + paddingLength;

    const buf = new Uint8Array(totalLength);
    const writer = new SshWriter(buf);

    // "openssh-key-v1\0"
    buf.set(fromUtf8('openssh-key-v1'), 0);
    buf[14] = 0;
    writer.off = 15;

    writer.writeString(fromUtf8('none'));
    writer.writeString(fromUtf8('none'));
    writer.writeString(new Uint8Array(0));

    writer.writeUInt32(1); // number of keys
    writer.writeUInt32(pubkeyLength);

    writer.writeString(fromUtf8('ssh-rsa'));
    writer.writeString(ebuf);
    writer.writeString(nbuf);

    writer.writeUInt32(totalLength - 47 - pubkeyLength);
    writer.off += 8; // unused checksum

    writer.writeString(fromUtf8('ssh-rsa'));
    writer.writeString(nbuf);
    writer.writeString(ebuf);
    writer.writeString(dbuf);
    writer.writeString(coeffbuf);
    writer.writeString(pbuf);
    writer.writeString(qbuf);
    writer.writeString(commentbuf);

    let pad = 0x01;
    while (writer.off < totalLength) {
      buf[writer.off++] = pad++;
    }

    if (options.type === 'der') return buf;
    return `${PRIVATE_OPENING}\n${linebrk(toBase64(buf), 70)}\n${PRIVATE_CLOSING}\n`;
  },

  privateImport(key: RSAKey, data: Uint8Array | string, options: ImportOptions = {}): void {
    let buffer: Uint8Array;
    if (options.type !== 'der') {
      const text = data instanceof Uint8Array ? toUtf8(data) : (data as string);
      const trimmed = trimSurroundingText(text, PRIVATE_OPENING, PRIVATE_CLOSING).replace(
        /\s+/g,
        '',
      );
      buffer = fromBase64(trimmed);
    } else if (data instanceof Uint8Array) {
      buffer = data;
    } else {
      throw new Error('Unsupported key format');
    }

    const magic = toUtf8(buffer.subarray(0, 14));
    if (magic !== 'openssh-key-v1') throw new Error('Invalid file format.');

    const reader = new SshReader(buffer);
    reader.off = 15;

    if (toUtf8(reader.readString()) !== 'none') throw new Error('Unsupported key type');
    if (toUtf8(reader.readString()) !== 'none') throw new Error('Unsupported key type');
    if (toUtf8(reader.readString()) !== '') throw new Error('Unsupported key type');

    reader.off += 4; // keynum
    reader.off += 4; // sshpublength

    if (toUtf8(reader.readString()) !== 'ssh-rsa') throw new Error('Unsupported key type');
    reader.readString(); // public e
    reader.readString(); // public n

    reader.off += 12; // private length + 8 byte unused checksum
    if (toUtf8(reader.readString()) !== 'ssh-rsa') throw new Error('Unsupported key type');

    const n = reader.readString();
    const e = reader.readString();
    const d = reader.readString();
    const coeff = reader.readString();
    const p = reader.readString();
    const q = reader.readString();

    // Derive dp = d mod (p-1) and dq = d mod (q-1)
    const dint = new BigInteger(d);
    const pint = new BigInteger(p);
    const qint = new BigInteger(q);
    const dp = dint.mod(pint.subtract(BigInteger.ONE)).toBuffer() as Uint8Array;
    const dq = dint.mod(qint.subtract(BigInteger.ONE)).toBuffer() as Uint8Array;

    key.setPrivate(n, e, d, p, q, dp, dq, coeff);
    key.sshcomment = toUtf8(reader.readString());
  },

  publicExport(key: RSAKey, options: ExportOptions = {}): Uint8Array | string {
    if (!key.n) throw new Error('OpenSSH export: missing modulus');
    let ebuf = new Uint8Array(4);
    writeUInt32BE(key.e, ebuf, 0);
    while (ebuf.length > 0 && ebuf[0] === 0) ebuf = ebuf.subarray(1);
    const nbuf = key.n.toBuffer() as Uint8Array;

    const buf = new Uint8Array(ebuf.byteLength + 4 + nbuf.byteLength + 4 + 'ssh-rsa'.length + 4);
    const writer = new SshWriter(buf);
    writer.writeString(fromUtf8('ssh-rsa'));
    writer.writeString(ebuf);
    writer.writeString(nbuf);

    if (options.type === 'der') return buf;
    const comment = key.sshcomment ?? '';
    return `ssh-rsa ${toBase64(buf)} ${comment}\n`;
  },

  publicImport(key: RSAKey, data: Uint8Array | string, options: ImportOptions = {}): void {
    let buffer: Uint8Array;
    if (options.type !== 'der') {
      const text = data instanceof Uint8Array ? toUtf8(data) : (data as string);
      if (text.substring(0, 8) !== 'ssh-rsa ') throw new Error('Unsupported key format');
      let pemEnd = text.indexOf(' ', 8);
      if (pemEnd === -1) {
        pemEnd = text.length;
      } else {
        key.sshcomment = text.substring(pemEnd + 1).replace(/\s+$/g, '');
      }
      const pem = text.substring(8, pemEnd).replace(/\s+/g, '');
      buffer = fromBase64(pem);
    } else if (data instanceof Uint8Array) {
      buffer = data;
    } else {
      throw new Error('Unsupported key format');
    }

    const reader = new SshReader(buffer);
    const type = toUtf8(reader.readString());
    if (type !== 'ssh-rsa') throw new Error(`Invalid key type: ${type}`);
    const e = reader.readString();
    const n = reader.readString();
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
      /^[\S\s]*-----BEGIN OPENSSH PRIVATE KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END OPENSSH PRIVATE KEY-----[\S\s]*$/g.test(
        text,
      )
    ) {
      opensshFormat.privateImport?.(key, text);
      return true;
    }
    if (/^[\S\s]*ssh-rsa \s*(?=(([A-Za-z0-9+/=]+\s*)+))\1[\S\s]*$/g.test(text)) {
      opensshFormat.publicImport?.(key, text);
      return true;
    }
    return false;
  },
};

class SshReader {
  off = 0;
  constructor(readonly buf: Uint8Array) {}
  readString(): Uint8Array {
    const len = readUInt32BE(this.buf, this.off);
    this.off += 4;
    const out = this.buf.subarray(this.off, this.off + len);
    this.off += len;
    return out;
  }
}

class SshWriter {
  off = 0;
  constructor(readonly buf: Uint8Array) {}
  writeString(data: Uint8Array): void {
    writeUInt32BE(data.byteLength, this.buf, this.off);
    this.off += 4;
    this.buf.set(data, this.off);
    this.off += data.byteLength;
  }
  writeUInt32(value: number): void {
    writeUInt32BE(value, this.buf, this.off);
    this.off += 4;
  }
}

// Suppress "unused" — concat is re-exported below for tree-shake friendliness
void concat;
