import { Tag, tagName } from './tags.js';

export class DerReader {
  private pos = 0;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  get position(): number {
    return this.pos;
  }

  get remaining(): number {
    return this.bytes.length - this.pos;
  }

  hasMore(): boolean {
    return this.pos < this.bytes.length;
  }

  /**
   * Read a generic TLV. If `expectedTag` is supplied, asserts the tag matches.
   * Returns the value bytes (no tag, no length octets).
   */
  readTlv(expectedTag?: number): { tag: number; value: Uint8Array } {
    if (this.pos >= this.bytes.length) {
      throw new Error('DerReader: unexpected end of input');
    }
    const tag = this.bytes[this.pos++] as number;
    if (expectedTag !== undefined && tag !== expectedTag) {
      throw new Error(
        `DerReader: expected ${tagName(expectedTag)} (0x${expectedTag.toString(16)}) but got ${tagName(tag)} (0x${tag.toString(16)})`,
      );
    }
    const length = this.readLength();
    const end = this.pos + length;
    if (end > this.bytes.length) {
      throw new Error(
        `DerReader: TLV length ${length} exceeds buffer (pos=${this.pos}, len=${this.bytes.length})`,
      );
    }
    const value = this.bytes.subarray(this.pos, end);
    this.pos = end;
    return { tag, value };
  }

  private readLength(): number {
    if (this.pos >= this.bytes.length) {
      throw new Error('DerReader: missing length octet');
    }
    const first = this.bytes[this.pos++] as number;
    if ((first & 0x80) === 0) return first;
    const numBytes = first & 0x7f;
    if (numBytes === 0) {
      throw new Error('DerReader: indefinite length not permitted in DER');
    }
    if (numBytes > 4) {
      throw new Error(`DerReader: unsupported length width ${numBytes}`);
    }
    let len = 0;
    for (let i = 0; i < numBytes; i++) {
      if (this.pos >= this.bytes.length) {
        throw new Error('DerReader: truncated length');
      }
      const b = this.bytes[this.pos++] as number;
      // X.690 §10.1: long-form length octets must be the minimum number
      // necessary — no leading zeros.
      if (i === 0 && b === 0 && numBytes > 1) {
        throw new Error('DerReader: non-canonical length (leading zero in long-form)');
      }
      len = (len << 8) | b;
    }
    // X.690 §10.1: short-form is required when the value is < 128.
    if (len < 128) {
      throw new Error(`DerReader: non-canonical length (long-form used for length ${len} < 128)`);
    }
    return len;
  }

  /** Read a SEQUENCE and return a sub-reader scoped to its contents. */
  readSequence(): DerReader {
    return new DerReader(this.readTlv(Tag.SEQUENCE).value);
  }

  /** Read an INTEGER and return its raw value bytes (DER content). */
  readInteger(): Uint8Array {
    const bytes = this.readTlv(Tag.INTEGER).value;
    if (bytes.length === 0) {
      throw new Error('DerReader: INTEGER must have at least one content octet');
    }
    // X.690 §8.3.2: a leading 0x00 is allowed only when the next byte's MSB
    // is set (sign-bit padding); a leading 0xff only when it's clear.
    if (bytes.length >= 2) {
      if (bytes[0] === 0x00 && (bytes[1]! & 0x80) === 0) {
        throw new Error('DerReader: non-canonical INTEGER (redundant leading 0x00)');
      }
      if (bytes[0] === 0xff && (bytes[1]! & 0x80) !== 0) {
        throw new Error('DerReader: non-canonical INTEGER (redundant leading 0xff)');
      }
    }
    return bytes;
  }

  /**
   * Read an INTEGER, decoding it as an unsigned JavaScript number.
   * Throws if the value doesn't fit in a safe-integer.
   */
  readSmallInteger(): number {
    const bytes = this.readInteger();
    // Skip any leading zero used to indicate sign (positive)
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const meaningful = bytes.subarray(i);
    if (meaningful.length > 6) {
      throw new Error(`DerReader: integer too large for safe number (${meaningful.length} bytes)`);
    }
    let n = 0;
    for (const b of meaningful) {
      n = n * 256 + b;
    }
    return n;
  }

  /** Read an OBJECT IDENTIFIER and return its dotted-string form. */
  readOid(): string {
    return decodeOid(this.readTlv(Tag.OBJECT_IDENTIFIER).value);
  }

  /** Read a NULL TLV. Throws if the value is non-empty. */
  readNull(): void {
    const { value } = this.readTlv(Tag.NULL);
    if (value.length !== 0) {
      throw new Error(`DerReader: NULL must be zero-length, got ${value.length}`);
    }
  }

  /** Read a BIT STRING and return its value bytes INCLUDING the leading unused-bits octet. */
  readBitStringRaw(): Uint8Array {
    return this.readTlv(Tag.BIT_STRING).value;
  }

  /**
   * Read a BIT STRING and return its content octets (after the unused-bits byte).
   * Asserts unused-bits is zero.
   */
  readBitString(): Uint8Array {
    const raw = this.readBitStringRaw();
    if (raw.length === 0) {
      throw new Error('DerReader: empty BIT STRING');
    }
    if (raw[0] !== 0) {
      throw new Error(`DerReader: non-zero unused bits (${raw[0]}) not supported`);
    }
    return raw.subarray(1);
  }

  /** Read an OCTET STRING and return its value bytes. */
  readOctetString(): Uint8Array {
    return this.readTlv(Tag.OCTET_STRING).value;
  }
}

function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    throw new Error('DerReader: empty OID');
  }
  let i = 0;
  // First base-128 sequence encodes (40*arc0 + arc1).
  let combined = 0;
  let b: number;
  do {
    if (i >= bytes.length) throw new Error('DerReader: truncated OID');
    b = bytes[i++] as number;
    combined = combined * 128 + (b & 0x7f);
  } while ((b & 0x80) !== 0);

  const arcs: number[] = [];
  if (combined < 40) {
    arcs.push(0, combined);
  } else if (combined < 80) {
    arcs.push(1, combined - 40);
  } else {
    arcs.push(2, combined - 80);
  }

  while (i < bytes.length) {
    let arc = 0;
    do {
      if (i >= bytes.length) throw new Error('DerReader: truncated OID arc');
      b = bytes[i++] as number;
      arc = arc * 128 + (b & 0x7f);
    } while ((b & 0x80) !== 0);
    arcs.push(arc);
  }
  return arcs.join('.');
}
