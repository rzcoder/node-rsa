import { describe, expect, it } from 'vitest';
import { DerReader, Tag } from '../../src/asn1/index.js';
import { fromHex } from '../../src/crypto/bytes.js';

/**
 * Regression coverage for the strict-DER and bounds-check fixes in
 * src/asn1/reader.ts. A future refactor that loosens any of these checks
 * should make a test here fail.
 */

describe('DerReader — TLV bounds and structural errors', () => {
  it('rejects truncated TLV where length exceeds remaining buffer', () => {
    // SEQUENCE, length=10, but only 2 content octets follow
    const der = fromHex('300a0500');
    expect(() => new DerReader(der).readSequence()).toThrow(/exceeds buffer/);
  });

  it('rejects unexpected end of input', () => {
    const der = new Uint8Array(0);
    expect(() => new DerReader(der).readTlv()).toThrow(/unexpected end of input/);
  });

  it('rejects missing length octet', () => {
    const der = fromHex('30'); // tag only, no length byte
    expect(() => new DerReader(der).readSequence()).toThrow(/missing length octet/);
  });

  it('rejects truncated long-form length octets', () => {
    // SEQUENCE with numBytes=2 but only 1 length byte follows
    const der = fromHex('308201');
    expect(() => new DerReader(der).readSequence()).toThrow(/truncated length/);
  });

  it('rejects tag mismatch', () => {
    // OCTET STRING (0x04) where SEQUENCE (0x30) expected
    const der = fromHex('040100');
    expect(() => new DerReader(der).readSequence()).toThrow(/expected SEQUENCE/);
  });

  it('rejects unsupported length width (> 4 bytes)', () => {
    // numBytes = 5 in long-form indicator
    const der = fromHex('308500000000000000');
    expect(() => new DerReader(der).readSequence()).toThrow(/unsupported length width/);
  });

  it('rejects indefinite-length encoding (BER-only)', () => {
    // 0x80 means indefinite length — illegal in DER
    const der = fromHex('308000000000');
    expect(() => new DerReader(der).readSequence()).toThrow(/indefinite length/);
  });
});

describe('DerReader — non-canonical length (L5)', () => {
  it('rejects long-form length for value < 128', () => {
    // SEQUENCE { OCTET STRING ""; } with length 2 encoded as long-form 0x81 0x02
    const der = fromHex('3081020400');
    expect(() => new DerReader(der).readSequence()).toThrow(/non-canonical length/);
  });

  it('rejects long-form length with leading zero byte', () => {
    // SEQUENCE length 255 with redundant leading zero in long-form: 0x82 0x00 0xff
    // Minimum form would be 0x81 0xff.
    const der = new Uint8Array([0x30, 0x82, 0x00, 0xff, ...new Uint8Array(255).fill(0)]);
    expect(() => new DerReader(der).readSequence()).toThrow(/non-canonical length/);
  });

  it('accepts short-form (len=127) and long-form (len=128) at the boundary', () => {
    // Short-form at 127: 0x7f
    const short = new Uint8Array([0x04, 0x7f, ...new Uint8Array(127)]);
    expect(() => new DerReader(short).readOctetString()).not.toThrow();
    // Long-form at 128: 0x81 0x80
    const long = new Uint8Array([0x04, 0x81, 0x80, ...new Uint8Array(128)]);
    expect(() => new DerReader(long).readOctetString()).not.toThrow();
  });
});

describe('DerReader — non-canonical INTEGER (L1)', () => {
  it('rejects empty INTEGER content', () => {
    // INTEGER, length=0 — illegal per X.690 §8.3.1
    const der = fromHex('0200');
    expect(() => new DerReader(der).readInteger()).toThrow(/at least one content octet/);
  });

  it('rejects redundant leading 0x00 on positive integer', () => {
    // 0x00 0x42 — minimum form is 0x42 (since 0x42 has MSB clear, sign byte is redundant)
    const der = fromHex('02020042');
    expect(() => new DerReader(der).readInteger()).toThrow(/non-canonical INTEGER/);
  });

  it('rejects redundant leading 0xff on negative integer', () => {
    // 0xff 0x7f — minimum form is 0x7f? Actually 0xff means -1*256+0x7f = -129 in DER negatives.
    // For negative: leading 0xff allowed only if next byte's MSB is clear.
    // Here next byte 0x7f has MSB clear, so the 0xff is REQUIRED (would be -129).
    // We want a redundant case: 0xff 0xff (= -1) — minimum is just 0xff.
    const der = fromHex('0202ffff');
    expect(() => new DerReader(der).readInteger()).toThrow(/non-canonical INTEGER/);
  });

  it('accepts canonical 0x00 0x80 (positive 128 with required sign byte)', () => {
    // 0x80 alone would be -128; the leading 0x00 is required to express positive 128.
    const der = fromHex('02020080');
    expect(() => new DerReader(der).readInteger()).not.toThrow();
  });

  it('accepts canonical single-byte integers', () => {
    for (const hex of ['020100', '020101', '02017f', '0201ff']) {
      const der = fromHex(hex);
      expect(() => new DerReader(der).readInteger()).not.toThrow();
    }
  });
});

describe('DerReader — BIT STRING and OID edge cases', () => {
  it('rejects BIT STRING with non-zero unused-bits octet', () => {
    // 0x03 (BIT STRING), length 2, unused-bits=3, content 0xff
    const der = fromHex('030203ff');
    expect(() => new DerReader(der).readBitString()).toThrow(/non-zero unused bits/);
  });

  it('rejects empty BIT STRING (no unused-bits octet)', () => {
    const der = fromHex('0300');
    expect(() => new DerReader(der).readBitString()).toThrow(/empty BIT STRING/);
  });

  it('rejects NULL with non-empty content', () => {
    // NULL must have length 0; here length 1
    const der = fromHex('050100');
    expect(() => new DerReader(der).readNull()).toThrow(/zero-length/);
  });

  it('rejects empty OID', () => {
    const der = fromHex('0600');
    expect(() => new DerReader(der).readOid()).toThrow(/empty OID/);
  });
});

describe('DerReader — readTlv tag filtering', () => {
  it('returns tag and value for unfiltered reads', () => {
    const der = fromHex('040548656c6c6f'); // OCTET STRING "Hello"
    const { tag, value } = new DerReader(der).readTlv();
    expect(tag).toBe(Tag.OCTET_STRING);
    expect(value.length).toBe(5);
  });
});
