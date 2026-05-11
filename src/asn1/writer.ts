import { concat } from '../crypto/bytes.js';
import { Tag } from './tags.js';

export class DerWriter {
  private chunks: Uint8Array[] = [];
  private sequenceStack: Uint8Array[][] = [];

  /** Append raw bytes verbatim (no TLV wrapping). */
  writeRaw(bytes: Uint8Array): void {
    this.chunks.push(bytes);
  }

  /** Write a generic TLV with the given tag and value bytes. */
  writeTlv(tag: number, value: Uint8Array): void {
    this.chunks.push(new Uint8Array([tag]));
    this.chunks.push(encodeLength(value.length));
    this.chunks.push(value);
  }

  /**
   * Write an INTEGER. Accepts:
   *  - a positive JS number,
   *  - an unsigned big-endian byte array (a leading zero will be prepended
   *    if the MSB is set, to preserve positive sign).
   */
  writeInteger(value: number | Uint8Array): void {
    if (typeof value === 'number') {
      this.writeTlv(Tag.INTEGER, encodeSmallInteger(value));
    } else {
      this.writeTlv(Tag.INTEGER, normalizePositiveInteger(value));
    }
  }

  writeOid(oid: string): void {
    this.writeTlv(Tag.OBJECT_IDENTIFIER, encodeOid(oid));
  }

  writeNull(): void {
    this.writeTlv(Tag.NULL, new Uint8Array(0));
  }

  /** Write a BIT STRING. Always emits an unused-bits prefix byte of 0x00. */
  writeBitString(content: Uint8Array): void {
    const body = new Uint8Array(content.length + 1);
    body[0] = 0;
    body.set(content, 1);
    this.writeTlv(Tag.BIT_STRING, body);
  }

  /**
   * Write a BIT STRING whose value bytes (including the leading unused-bits
   * octet) are supplied directly. Mirrors callers that build the bit-string
   * payload externally.
   */
  writeBitStringRaw(valueIncludingUnusedBitsByte: Uint8Array): void {
    this.writeTlv(Tag.BIT_STRING, valueIncludingUnusedBitsByte);
  }

  writeOctetString(content: Uint8Array): void {
    this.writeTlv(Tag.OCTET_STRING, content);
  }

  /** Begin a nested SEQUENCE; subsequent writes go into it until endSequence(). */
  startSequence(): void {
    this.sequenceStack.push(this.chunks);
    this.chunks = [];
  }

  /** Close the most recently opened SEQUENCE, emitting it as a TLV in the parent. */
  endSequence(): void {
    if (this.sequenceStack.length === 0) {
      throw new Error('DerWriter: endSequence without startSequence');
    }
    const inner = concat(...this.chunks);
    this.chunks = this.sequenceStack.pop() as Uint8Array[];
    this.writeTlv(Tag.SEQUENCE, inner);
  }

  /** Return the assembled DER bytes. Throws if any SEQUENCE is unclosed. */
  toBytes(): Uint8Array {
    if (this.sequenceStack.length > 0) {
      throw new Error(`DerWriter: ${this.sequenceStack.length} SEQUENCE(s) unclosed`);
    }
    return concat(...this.chunks);
  }
}

function encodeLength(n: number): Uint8Array {
  if (n < 0) throw new Error(`DerWriter: negative length ${n}`);
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  let temp = n;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp = Math.floor(temp / 256);
  }
  if (bytes.length > 0x7f) {
    throw new Error(`DerWriter: length ${n} exceeds DER limits`);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function encodeSmallInteger(n: number): Uint8Array {
  if (n < 0) throw new Error(`DerWriter: negative integers not supported (got ${n})`);
  if (n === 0) return new Uint8Array([0]);
  if (!Number.isSafeInteger(n)) {
    throw new Error(`DerWriter: integer ${n} not a safe integer`);
  }
  const bytes: number[] = [];
  let temp = n;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp = Math.floor(temp / 256);
  }
  // Prepend 0x00 if MSB is set so the value is parsed as unsigned/positive.
  if ((bytes[0] as number) & 0x80) bytes.unshift(0);
  return new Uint8Array(bytes);
}

function normalizePositiveInteger(value: Uint8Array): Uint8Array {
  // Strip leading zeros, but keep one if MSB of the next byte is set.
  let i = 0;
  while (i < value.length - 1 && value[i] === 0 && ((value[i + 1] as number) & 0x80) === 0) {
    i++;
  }
  const trimmed = value.subarray(i);
  // Prepend a 0x00 if MSB is set, to signal positive.
  if (trimmed.length > 0 && (trimmed[0] as number) & 0x80) {
    const out = new Uint8Array(trimmed.length + 1);
    out[0] = 0;
    out.set(trimmed, 1);
    return out;
  }
  return trimmed.length === 0 ? new Uint8Array([0]) : trimmed;
}

function encodeOid(oid: string): Uint8Array {
  const arcs = oid.split('.').map((s) => {
    const n = Number(s);
    if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
      throw new Error(`DerWriter: invalid OID arc "${s}"`);
    }
    return n;
  });
  if (arcs.length < 2) {
    throw new Error(`DerWriter: OID must have at least 2 arcs, got "${oid}"`);
  }
  const arc0 = arcs[0] as number;
  const arc1 = arcs[1] as number;
  if (arc0 > 2 || (arc0 < 2 && arc1 >= 40)) {
    throw new Error(`DerWriter: invalid leading arcs ${arc0}.${arc1}`);
  }
  // The first byte encodes (40*arc0 + arc1) using base-128 — needed when
  // arc0 = 2 and arc1 >= 48, where the combined value exceeds a single octet.
  const out: number[] = [];
  encodeBase128Into(arc0 * 40 + arc1, out);
  for (let i = 2; i < arcs.length; i++) {
    encodeBase128Into(arcs[i] as number, out);
  }
  return new Uint8Array(out);
}

function encodeBase128Into(n: number, out: number[]): void {
  if (n === 0) {
    out.push(0);
    return;
  }
  const bytes: number[] = [];
  let temp = n;
  while (temp > 0) {
    bytes.unshift(temp & 0x7f);
    temp = Math.floor(temp / 128);
  }
  for (let i = 0; i < bytes.length - 1; i++) {
    bytes[i] = (bytes[i] as number) | 0x80;
  }
  out.push(...bytes);
}
