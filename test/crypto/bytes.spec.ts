import { describe, expect, it } from 'vitest';
import {
  alloc,
  asUint8Array,
  concat,
  constantTimeEqual,
  equals,
  fromBase64,
  fromHex,
  fromUtf8,
  readUInt32BE,
  toBase64,
  toHex,
  toUtf8,
  writeUInt32BE,
} from '../../src/crypto/bytes.js';

describe('bytes.alloc', () => {
  it('returns zero-filled Uint8Array', () => {
    const a = alloc(5);
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(5);
    expect(Array.from(a)).toEqual([0, 0, 0, 0, 0]);
  });

  it('supports a fill value', () => {
    expect(Array.from(alloc(3, 0xff))).toEqual([0xff, 0xff, 0xff]);
  });
});

describe('bytes.concat', () => {
  it('concatenates multiple arrays', () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5, 6]));
    expect(Array.from(out)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('handles empty inputs', () => {
    expect(concat().length).toBe(0);
    expect(Array.from(concat(new Uint8Array([1]), new Uint8Array(0), new Uint8Array([2])))).toEqual(
      [1, 2],
    );
  });
});

describe('bytes.equals / constantTimeEqual', () => {
  it('returns true for identical content', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(equals(a, b)).toBe(true);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('returns false for different content or length', () => {
    expect(equals(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(equals(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });
});

describe('bytes.toHex / fromHex', () => {
  it('round-trips arbitrary bytes', () => {
    const data = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xff, 0xab, 0xcd]);
    const hex = toHex(data);
    expect(hex).toBe('00017f80ffabcd');
    expect(Array.from(fromHex(hex))).toEqual(Array.from(data));
  });

  it('accepts upper-case hex and 0x prefix', () => {
    expect(Array.from(fromHex('DEADbeef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(Array.from(fromHex('0xdeadbeef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it('rejects odd-length hex and invalid characters', () => {
    expect(() => fromHex('abc')).toThrow(/odd length/);
    expect(() => fromHex('zz')).toThrow(/Invalid hex/);
  });
});

describe('bytes.toBase64 / fromBase64', () => {
  it('round-trips arbitrary bytes', () => {
    const data = new Uint8Array([0, 1, 2, 250, 100, 200, 50, 0xff]);
    const b64 = toBase64(data);
    expect(Array.from(fromBase64(b64))).toEqual(Array.from(data));
  });

  it('matches known vectors', () => {
    expect(toBase64(new Uint8Array([72, 101, 108, 108, 111]))).toBe('SGVsbG8=');
    expect(Array.from(fromBase64('SGVsbG8='))).toEqual([72, 101, 108, 108, 111]);
  });

  it('handles large arrays (chunked path)', () => {
    const data = new Uint8Array(100_000);
    for (let i = 0; i < data.length; i++) data[i] = i & 0xff;
    const round = fromBase64(toBase64(data));
    expect(round.length).toBe(data.length);
    expect(round[99_999]).toBe(99_999 & 0xff);
  });
});

describe('bytes.fromUtf8 / toUtf8', () => {
  it('round-trips ASCII', () => {
    expect(toUtf8(fromUtf8('hello world'))).toBe('hello world');
  });

  it('round-trips multibyte unicode', () => {
    const s = 'тест 测试 🚀';
    expect(toUtf8(fromUtf8(s))).toBe(s);
  });
});

describe('bytes.readUInt32BE / writeUInt32BE', () => {
  it('round-trips values', () => {
    const buf = new Uint8Array(4);
    writeUInt32BE(0xdeadbeef, buf, 0);
    expect(Array.from(buf)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(readUInt32BE(buf, 0)).toBe(0xdeadbeef);
  });

  it('handles offset writes', () => {
    const buf = new Uint8Array(8);
    writeUInt32BE(0x01020304, buf, 2);
    expect(Array.from(buf)).toEqual([0, 0, 1, 2, 3, 4, 0, 0]);
    expect(readUInt32BE(buf, 2)).toBe(0x01020304);
  });

  it('handles zero', () => {
    const buf = new Uint8Array(4);
    writeUInt32BE(0, buf, 0);
    expect(readUInt32BE(buf, 0)).toBe(0);
  });

  it('throws on out-of-range offsets', () => {
    expect(() => readUInt32BE(new Uint8Array(4), 1)).toThrow(/out of range/);
    expect(() => writeUInt32BE(1, new Uint8Array(4), 1)).toThrow(/out of range/);
  });
});

describe('bytes.asUint8Array', () => {
  it('returns Uint8Array views unchanged', () => {
    const u = new Uint8Array([1, 2, 3]);
    expect(asUint8Array(u)).toBe(u);
  });

  it('wraps a raw ArrayBuffer', () => {
    const ab = new ArrayBuffer(4);
    new Uint8Array(ab).set([9, 8, 7, 6]);
    const out = asUint8Array(ab);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(Array.from(out)).toEqual([9, 8, 7, 6]);
  });
});
