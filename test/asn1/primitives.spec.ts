import { describe, expect, it } from 'vitest';
import { DerReader, DerWriter, OID, Tag } from '../../src/asn1/index.js';
import { fromHex, toHex } from '../../src/crypto/bytes.js';

describe('INTEGER', () => {
  it('encodes small numbers', () => {
    const w = new DerWriter();
    w.writeInteger(0);
    expect(toHex(w.toBytes())).toBe('020100');
  });

  it('encodes 1 as 02 01 01', () => {
    const w = new DerWriter();
    w.writeInteger(1);
    expect(toHex(w.toBytes())).toBe('020101');
  });

  it('encodes 127 without a leading zero', () => {
    const w = new DerWriter();
    w.writeInteger(127);
    expect(toHex(w.toBytes())).toBe('02017f');
  });

  it('encodes 128 with a leading zero (positive marker)', () => {
    const w = new DerWriter();
    w.writeInteger(128);
    expect(toHex(w.toBytes())).toBe('02020080');
  });

  it('encodes 65537 (standard RSA public exponent)', () => {
    const w = new DerWriter();
    w.writeInteger(65537);
    expect(toHex(w.toBytes())).toBe('0203010001');
  });

  it('round-trips a multi-byte byte-array INTEGER', () => {
    const value = fromHex('00deadbeef');
    const w = new DerWriter();
    w.writeInteger(value);
    const r = new DerReader(w.toBytes());
    expect(toHex(r.readInteger())).toBe('00deadbeef');
  });

  it('prepends a leading zero when the byte-array MSB is set', () => {
    const value = fromHex('deadbeef');
    const w = new DerWriter();
    w.writeInteger(value);
    const r = new DerReader(w.toBytes());
    // Reader returns the raw DER content bytes (with the leading zero)
    expect(toHex(r.readInteger())).toBe('00deadbeef');
  });

  it('readSmallInteger decodes back', () => {
    for (const n of [0, 1, 127, 128, 255, 256, 65535, 65537, 1234567]) {
      const w = new DerWriter();
      w.writeInteger(n);
      const r = new DerReader(w.toBytes());
      expect(r.readSmallInteger()).toBe(n);
    }
  });
});

describe('NULL', () => {
  it('encodes as 05 00', () => {
    const w = new DerWriter();
    w.writeNull();
    expect(toHex(w.toBytes())).toBe('0500');
  });

  it('readNull consumes the TLV', () => {
    const w = new DerWriter();
    w.writeNull();
    w.writeInteger(7);
    const r = new DerReader(w.toBytes());
    r.readNull();
    expect(r.readSmallInteger()).toBe(7);
  });

  it('readNull rejects non-zero length', () => {
    const r = new DerReader(new Uint8Array([0x05, 0x01, 0x00]));
    expect(() => r.readNull()).toThrow(/zero-length/);
  });
});

describe('OBJECT IDENTIFIER', () => {
  it('encodes rsaEncryption (1.2.840.113549.1.1.1)', () => {
    const w = new DerWriter();
    w.writeOid(OID.RSA_ENCRYPTION);
    // Known canonical DER for rsaEncryption: 06 09 2A 86 48 86 F7 0D 01 01 01
    expect(toHex(w.toBytes())).toBe('06092a864886f70d010101');
  });

  it('round-trips arbitrary OIDs', () => {
    const cases = [
      '1.2.840.113549.1.1.1',
      '0.0',
      '1.2.3',
      '2.999.1234567', // tests large arc
      '1.3.6.1.4.1.311.2.1.4', // Microsoft OID — multibyte arcs
    ];
    for (const oid of cases) {
      const w = new DerWriter();
      w.writeOid(oid);
      const r = new DerReader(w.toBytes());
      expect(r.readOid()).toBe(oid);
    }
  });

  it('rejects invalid leading arcs', () => {
    expect(() => new DerWriter().writeOid('3.0')).toThrow();
    expect(() => new DerWriter().writeOid('0.40')).toThrow();
  });
});

describe('SEQUENCE', () => {
  it('encodes an empty SEQUENCE as 30 00', () => {
    const w = new DerWriter();
    w.startSequence();
    w.endSequence();
    expect(toHex(w.toBytes())).toBe('3000');
  });

  it('encodes a SEQUENCE { INTEGER, NULL }', () => {
    const w = new DerWriter();
    w.startSequence();
    w.writeInteger(0);
    w.writeNull();
    w.endSequence();
    // 30 05 02 01 00 05 00
    expect(toHex(w.toBytes())).toBe('30050201000500');
  });

  it('supports nested sequences', () => {
    const w = new DerWriter();
    w.startSequence();
    w.startSequence();
    w.writeOid(OID.RSA_ENCRYPTION);
    w.writeNull();
    w.endSequence();
    w.writeInteger(42);
    w.endSequence();

    const outer = new DerReader(w.toBytes()).readSequence();
    const header = outer.readSequence();
    expect(header.readOid()).toBe(OID.RSA_ENCRYPTION);
    header.readNull();
    expect(outer.readSmallInteger()).toBe(42);
  });

  it('throws when endSequence has no matching start', () => {
    const w = new DerWriter();
    expect(() => w.endSequence()).toThrow();
  });

  it('throws when toBytes called with unclosed sequences', () => {
    const w = new DerWriter();
    w.startSequence();
    expect(() => w.toBytes()).toThrow(/unclosed/);
  });
});

describe('BIT STRING', () => {
  it('writes with a leading unused-bits byte of 0', () => {
    const w = new DerWriter();
    w.writeBitString(new Uint8Array([0xaa, 0xbb]));
    expect(toHex(w.toBytes())).toBe('0303' + '00aabb');
  });

  it('round-trips via readBitString (asserts unused=0)', () => {
    const w = new DerWriter();
    w.writeBitString(new Uint8Array([1, 2, 3]));
    const r = new DerReader(w.toBytes());
    expect(toHex(r.readBitString())).toBe('010203');
  });

  it('readBitStringRaw includes the unused-bits byte', () => {
    const w = new DerWriter();
    w.writeBitString(new Uint8Array([1, 2, 3]));
    const r = new DerReader(w.toBytes());
    expect(toHex(r.readBitStringRaw())).toBe('00010203');
  });

  it('readBitString rejects non-zero unused bits', () => {
    // 03 02 04 ff  — a BIT STRING with 4 unused bits and one content byte
    const r = new DerReader(new Uint8Array([0x03, 0x02, 0x04, 0xff]));
    expect(() => r.readBitString()).toThrow(/unused bits/);
  });
});

describe('OCTET STRING', () => {
  it('round-trips', () => {
    const w = new DerWriter();
    w.writeOctetString(fromHex('0102deadbeef'));
    const r = new DerReader(w.toBytes());
    expect(toHex(r.readOctetString())).toBe('0102deadbeef');
  });
});

describe('Length codec', () => {
  it('short form (n < 128)', () => {
    const w = new DerWriter();
    w.writeOctetString(new Uint8Array(127));
    const bytes = w.toBytes();
    expect(bytes[0]).toBe(Tag.OCTET_STRING);
    expect(bytes[1]).toBe(127); // short form
  });

  it('long form 1-byte length (128..255)', () => {
    const w = new DerWriter();
    w.writeOctetString(new Uint8Array(200));
    const bytes = w.toBytes();
    expect(bytes[0]).toBe(Tag.OCTET_STRING);
    expect(bytes[1]).toBe(0x81); // 1 byte follows
    expect(bytes[2]).toBe(200);
  });

  it('long form 2-byte length (256..65535)', () => {
    const w = new DerWriter();
    w.writeOctetString(new Uint8Array(300));
    const bytes = w.toBytes();
    expect(bytes[1]).toBe(0x82);
    expect((bytes[2] as number) * 256 + (bytes[3] as number)).toBe(300);
  });

  it('reader handles all length encodings', () => {
    for (const size of [0, 1, 127, 128, 255, 256, 1000, 65535]) {
      const w = new DerWriter();
      w.writeOctetString(new Uint8Array(size));
      const r = new DerReader(w.toBytes());
      expect(r.readOctetString().length).toBe(size);
    }
  });

  it('reader rejects indefinite length', () => {
    const r = new DerReader(new Uint8Array([0x04, 0x80, 0x00, 0x00]));
    expect(() => r.readOctetString()).toThrow(/indefinite/);
  });
});

describe('Reader semantics', () => {
  it('asserts the expected tag', () => {
    const w = new DerWriter();
    w.writeInteger(42);
    const r = new DerReader(w.toBytes());
    expect(() => r.readOid()).toThrow(/expected/);
  });

  it('tracks position and remaining', () => {
    const w = new DerWriter();
    w.writeInteger(1);
    w.writeInteger(2);
    const r = new DerReader(w.toBytes());
    expect(r.hasMore()).toBe(true);
    r.readSmallInteger();
    expect(r.hasMore()).toBe(true);
    r.readSmallInteger();
    expect(r.hasMore()).toBe(false);
  });

  it('rejects truncated input', () => {
    const r = new DerReader(new Uint8Array([0x02, 0x10])); // INTEGER tag claiming 16 bytes
    expect(() => r.readInteger()).toThrow(/exceeds buffer/);
  });
});
