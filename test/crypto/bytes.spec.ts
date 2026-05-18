import { describe, expect, it } from 'vitest';
import {
  concat,
  constantTimeEqual,
  fromBase64,
  fromHex,
  fromLatin1,
  fromUtf8,
  readUInt32BE,
  toBase64,
  toHex,
  toLatin1,
  toUtf8,
  writeUInt32BE,
} from '../../src/crypto/bytes.js';

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

describe('bytes.constantTimeEqual', () => {
  it('returns true for identical content', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('returns false for different content or length', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
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

  it('rejects malformed base64 input with characters outside the alphabet', () => {
    // The library wraps `atob`, which throws on illegal characters. Pin
    // the throwing behaviour so a future refactor doesn't silently swap to
    // a permissive decoder (which would let key fixtures with garbage in
    // them decode to wrong bytes).
    for (const bad of ['====', '!!!!', 'AB$D', '@@@@']) {
      expect(() => fromBase64(bad), `input "${bad}"`).toThrow();
    }
  });

  it('round-trips empty input through base64', () => {
    expect(toBase64(new Uint8Array(0))).toBe('');
    expect(Array.from(fromBase64(''))).toEqual([]);
  });

  it('round-trips length-1 / length-2 inputs (padding-edge cases)', () => {
    // Single-byte → "XX==", two-byte → "XXX=" canonical padding shapes.
    const one = new Uint8Array([0xab]);
    const two = new Uint8Array([0xab, 0xcd]);
    expect(Array.from(fromBase64(toBase64(one)))).toEqual([0xab]);
    expect(Array.from(fromBase64(toBase64(two)))).toEqual([0xab, 0xcd]);
  });
});

describe('bytes.fromUtf8 / toUtf8', () => {
  it('round-trips ASCII', () => {
    expect(toUtf8(fromUtf8('hello world'))).toBe('hello world');
  });

  it('round-trips multibyte unicode', () => {
    const s = 'テスト　тест 测试 🚀';
    expect(toUtf8(fromUtf8(s))).toBe(s);
  });
});

describe('bytes.fromLatin1 / toLatin1', () => {
  it('round-trips every byte 0x00-0xFF without corruption', () => {
    // The whole point of latin1 (vs UTF-8) is bytes ≥0x80 survive verbatim:
    // through TextDecoder they would expand to multi-byte sequences or hit
    // U+FFFD replacement on invalid runs. This is the regression guard for
    // the legacy `'binary'` Node-RSA encoding.
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    const s = toLatin1(all);
    expect(s.length).toBe(256);
    expect(Array.from(fromLatin1(s))).toEqual(Array.from(all));
  });

  it('handles chunk boundary at 0x8000', () => {
    const big = new Uint8Array(0x8000 + 17);
    for (let i = 0; i < big.length; i++) big[i] = (i * 31 + 7) & 0xff;
    expect(Array.from(fromLatin1(toLatin1(big)))).toEqual(Array.from(big));
  });

  it('round-trips empty input', () => {
    expect(toLatin1(new Uint8Array(0))).toBe('');
    expect(Array.from(fromLatin1(''))).toEqual([]);
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
