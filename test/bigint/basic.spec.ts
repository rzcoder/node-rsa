import { beforeAll, describe, expect, it } from 'vitest';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

describe('BigInteger constants', () => {
  it('ZERO and ONE are defined and round-trip via toString', () => {
    expect(BigInteger.ZERO.toString(10)).toBe('0');
    expect(BigInteger.ONE.toString(10)).toBe('1');
    expect(BigInteger.ZERO.signum()).toBe(0);
    expect(BigInteger.ONE.signum()).toBe(1);
  });
});

describe('BigInteger from string', () => {
  it('parses decimal', () => {
    const x = new BigInteger('123456789012345678901234567890', 10);
    expect(x.toString(10)).toBe('123456789012345678901234567890');
  });

  it('parses hex (with leading sign byte stripped on unsigned import)', () => {
    const x = new BigInteger('1abcdef0', 16);
    expect(x.toString(16)).toBe('1abcdef0');
  });

  it('parses negative decimals', () => {
    const x = new BigInteger('-42', 10);
    expect(x.toString(10)).toBe('-42');
    expect(x.signum()).toBe(-1);
  });
});

describe('BigInteger arithmetic', () => {
  const a = new BigInteger('100000000000000000000', 10);
  const b = new BigInteger('3', 10);

  it('add', () => {
    expect(a.add(b).toString(10)).toBe('100000000000000000003');
  });

  it('subtract', () => {
    expect(a.subtract(b).toString(10)).toBe('99999999999999999997');
  });

  it('multiply', () => {
    expect(a.multiply(b).toString(10)).toBe('300000000000000000000');
  });

  it('divide and remainder', () => {
    const [q, r] = a.divideAndRemainder(b);
    expect(q.toString(10)).toBe('33333333333333333333');
    expect(r.toString(10)).toBe('1');
  });

  it('square == multiply(this, this)', () => {
    expect(a.square().toString(10)).toBe(a.multiply(a).toString(10));
  });

  it('compareTo', () => {
    expect(a.compareTo(b)).toBeGreaterThan(0);
    expect(b.compareTo(a)).toBeLessThan(0);
    expect(a.compareTo(a)).toBe(0);
  });
});

describe('BigInteger bit operations', () => {
  it('bitLength on small values', () => {
    expect(new BigInteger('1', 10).bitLength()).toBe(1);
    expect(new BigInteger('7', 10).bitLength()).toBe(3);
    expect(new BigInteger('8', 10).bitLength()).toBe(4);
    expect(new BigInteger('255', 10).bitLength()).toBe(8);
    expect(new BigInteger('256', 10).bitLength()).toBe(9);
  });

  it('shiftLeft / shiftRight round-trip', () => {
    const x = new BigInteger('12345', 10);
    expect(x.shiftLeft(100).shiftRight(100).toString(10)).toBe('12345');
  });

  it('testBit', () => {
    const x = new BigInteger('10', 10); // binary 1010
    expect(x.testBit(0)).toBe(false);
    expect(x.testBit(1)).toBe(true);
    expect(x.testBit(2)).toBe(false);
    expect(x.testBit(3)).toBe(true);
  });
});

describe('BigInteger mod / modPow / modInverse', () => {
  const five = new BigInteger('5', 10);
  const seven = new BigInteger('7', 10);
  const thirteen = new BigInteger('13', 10);

  it('mod', () => {
    expect(new BigInteger('1000', 10).mod(seven).toString(10)).toBe('6');
  });

  it('modPow: 5^3 mod 13 = 8', () => {
    expect(five.modPow(new BigInteger('3', 10), thirteen).toString(10)).toBe('8');
  });

  it('modPowInt: 5^3 mod 13 = 8', () => {
    expect(five.modPowInt(3, thirteen).toString(10)).toBe('8');
  });

  it('modInverse: 3^-1 mod 11 = 4', () => {
    const inv = new BigInteger('3', 10).modInverse(new BigInteger('11', 10));
    expect(inv.toString(10)).toBe('4');
  });

  it('modInverse round trip: (a * a^-1) mod m == 1', () => {
    const a = new BigInteger('1234567890', 10);
    const m = new BigInteger('100000007', 10); // prime
    const inv = a.modInverse(m);
    const product = a.multiply(inv).mod(m);
    expect(product.toString(10)).toBe('1');
  });
});

describe('BigInteger gcd', () => {
  it('coprime → 1', () => {
    expect(new BigInteger('21', 10).gcd(new BigInteger('4', 10)).toString(10)).toBe('1');
  });

  it('gcd(48, 18) = 6', () => {
    expect(new BigInteger('48', 10).gcd(new BigInteger('18', 10)).toString(10)).toBe('6');
  });

  it('gcd(n, 0) = n', () => {
    expect(new BigInteger('42', 10).gcd(BigInteger.ZERO).toString(10)).toBe('42');
  });
});

describe('BigInteger primality', () => {
  it('detects known small primes', () => {
    for (const n of [2, 3, 5, 7, 11, 13, 17, 19, 23, 97]) {
      expect(new BigInteger(String(n), 10).isProbablePrime(20)).toBe(true);
    }
  });

  it('rejects composites', () => {
    for (const n of [4, 9, 15, 21, 25, 100, 1000]) {
      expect(new BigInteger(String(n), 10).isProbablePrime(20)).toBe(false);
    }
  });

  it('recognises a known large prime (2^61 - 1, Mersenne)', () => {
    const p = new BigInteger('2305843009213693951', 10);
    expect(p.isProbablePrime(20)).toBe(true);
  });
});

describe('BigInteger Buffer round-trip', () => {
  it('round-trips an unsigned big-endian byte array', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const x = new BigInteger(bytes);
    expect(x.toString(16)).toBe('deadbeef');
    const out = x.toBuffer(true);
    expect(out).toBeInstanceOf(Uint8Array);
    expect([...(out as Uint8Array)]).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it('toBuffer with size parameter zero-pads', () => {
    const x = new BigInteger('5', 10);
    const out = x.toBuffer(4) as Uint8Array;
    expect([...out]).toEqual([0, 0, 0, 5]);
  });

  it('toBuffer with size parameter trims leading zeros only', () => {
    const x = new BigInteger(new Uint8Array([0x12, 0x34]));
    const out = x.toBuffer(2) as Uint8Array;
    expect([...out]).toEqual([0x12, 0x34]);
  });

  it('toBuffer returns null if value does not fit in requested size', () => {
    const x = new BigInteger(new Uint8Array([0xff, 0xff, 0xff]));
    expect(x.toBuffer(2)).toBe(null);
  });
});

describe('BigInteger keygen RNG hook', () => {
  it('errors helpfully if no backend is set (and then recovers)', async () => {
    setBigIntegerBackend(undefined as never);
    expect(() => new BigInteger(64)).toThrow(/backend not initialized/);
    setBigIntegerBackend(nodeBackend);
  });

  it('new BigInteger(n) generates an n-bit random integer', () => {
    setBigIntegerBackend(nodeBackend);
    for (const bits of [16, 64, 128]) {
      const x = new BigInteger(bits);
      // bitLength is between bits-7 (if top byte happens to be < 0x80) and bits (after the mask).
      expect(x.bitLength()).toBeLessThanOrEqual(bits);
      expect(x.signum()).not.toBe(-1);
    }
  });
});
