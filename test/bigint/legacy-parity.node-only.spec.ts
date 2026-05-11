import { createRequire } from 'node:module';
import { beforeAll, describe, expect, it } from 'vitest';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { toHex } from '../../src/crypto/bytes.js';

const requireLegacy = createRequire(import.meta.url);
// biome-ignore lint/suspicious/noExplicitAny: legacy JS shape is dynamic
const LegacyBI = requireLegacy('../../src.legacy/libs/jsbn.js') as any;

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

const FIXTURES = [
  '0',
  '1',
  '2',
  '255',
  '256',
  '65537',
  '4294967295', // 2^32 - 1
  '12345678901234567890',
  '999999999999999999999999999',
  '1234567890123456789012345678901234567890',
];

describe('BigInteger ↔ legacy jsbn: toString parity', () => {
  for (const s of FIXTURES) {
    it(`"${s}" decimal toString matches`, () => {
      expect(new BigInteger(s, 10).toString(10)).toBe(new LegacyBI(s, 10).toString(10));
    });

    it(`"${s}" hex toString matches`, () => {
      expect(new BigInteger(s, 10).toString(16)).toBe(new LegacyBI(s, 10).toString(16));
    });
  }
});

describe('BigInteger ↔ legacy jsbn: arithmetic parity', () => {
  const pairs: Array<[string, string]> = [
    ['100', '7'],
    ['12345678901234567890', '999999999'],
    [`1${'0'.repeat(100)}`, '12345678901234567890'],
  ];

  for (const [a, b] of pairs) {
    it(`${a} + ${b}`, () => {
      expect(new BigInteger(a, 10).add(new BigInteger(b, 10)).toString(10)).toBe(
        new LegacyBI(a, 10).add(new LegacyBI(b, 10)).toString(10),
      );
    });

    it(`${a} - ${b}`, () => {
      expect(new BigInteger(a, 10).subtract(new BigInteger(b, 10)).toString(10)).toBe(
        new LegacyBI(a, 10).subtract(new LegacyBI(b, 10)).toString(10),
      );
    });

    it(`${a} * ${b}`, () => {
      expect(new BigInteger(a, 10).multiply(new BigInteger(b, 10)).toString(10)).toBe(
        new LegacyBI(a, 10).multiply(new LegacyBI(b, 10)).toString(10),
      );
    });

    it(`${a} / ${b}`, () => {
      expect(new BigInteger(a, 10).divide(new BigInteger(b, 10)).toString(10)).toBe(
        new LegacyBI(a, 10).divide(new LegacyBI(b, 10)).toString(10),
      );
    });

    it(`${a} mod ${b}`, () => {
      expect(new BigInteger(a, 10).mod(new BigInteger(b, 10)).toString(10)).toBe(
        new LegacyBI(a, 10).mod(new LegacyBI(b, 10)).toString(10),
      );
    });
  }
});

describe('BigInteger ↔ legacy jsbn: modPow parity', () => {
  const cases: Array<[string, string, string]> = [
    // base, exponent, modulus
    ['5', '13', '17'],
    ['2', '128', '1000000007'],
    [
      '7654321098765432109876543210',
      '65537',
      '11111111111111111111111111111111111111111111111111111111111111111',
    ],
  ];

  for (const [b, e, m] of cases) {
    it(`${b}^${e} mod ${`${m}`.slice(0, 12)}…`, () => {
      const ours = new BigInteger(b, 10).modPow(new BigInteger(e, 10), new BigInteger(m, 10));
      const legacy = new LegacyBI(b, 10).modPow(new LegacyBI(e, 10), new LegacyBI(m, 10));
      expect(ours.toString(10)).toBe(legacy.toString(10));
    });
  }
});

describe('BigInteger ↔ legacy jsbn: modInverse parity', () => {
  const cases: Array<[string, string]> = [
    ['3', '11'],
    ['65537', '12345678901234567'],
    [
      '7654321098765432109876543210',
      '11111111111111111111111111111111111111111111111111111111111111111',
    ],
  ];

  for (const [a, m] of cases) {
    it(`${a}^-1 mod ${m.slice(0, 12)}…`, () => {
      const ours = new BigInteger(a, 10).modInverse(new BigInteger(m, 10));
      const legacy = new LegacyBI(a, 10).modInverse(new LegacyBI(m, 10));
      expect(ours.toString(10)).toBe(legacy.toString(10));
    });
  }
});

describe('BigInteger ↔ legacy jsbn: gcd parity', () => {
  const cases: Array<[string, string]> = [
    ['48', '18'],
    ['100000000000000000000', '99999999999999999991'],
    ['1234567890123456789012345678901234567890', '9876543210987654321098765432109876543210'],
  ];

  for (const [a, b] of cases) {
    it(`gcd(${a.slice(0, 12)}…, ${b.slice(0, 12)}…)`, () => {
      const ours = new BigInteger(a, 10).gcd(new BigInteger(b, 10));
      const legacy = new LegacyBI(a, 10).gcd(new LegacyBI(b, 10));
      expect(ours.toString(10)).toBe(legacy.toString(10));
    });
  }
});

describe('BigInteger ↔ legacy jsbn: byte-array parity', () => {
  const corpora: Array<{ name: string; bytes: Uint8Array }> = [
    { name: 'small (4 bytes, MSB unset)', bytes: new Uint8Array([0x12, 0x34, 0x56, 0x78]) },
    { name: 'small with MSB set', bytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) },
    {
      name: '128-byte unsigned (RSA 1024 modulus shape)',
      bytes: new Uint8Array(128).map((_, i) => ((i * 31 + 7) & 0xff) | (i === 0 ? 0x80 : 0)),
    },
    {
      name: '256-byte unsigned (RSA 2048 modulus shape)',
      bytes: new Uint8Array(256).map((_, i) => (i * 19 + 5) & 0xff),
    },
  ];

  for (const { name, bytes } of corpora) {
    it(`fromBuffer.toString(16) matches legacy: ${name}`, () => {
      const ours = new BigInteger(bytes).toString(16);
      const legacy = new LegacyBI(Buffer.from(bytes)).toString(16);
      expect(ours).toBe(legacy);
    });
  }
});

describe('BigInteger ↔ legacy jsbn: toBuffer parity', () => {
  it('toBuffer with size parameter pads identically', () => {
    const a = new BigInteger('12345678901234567890', 10);
    const b = new LegacyBI('12345678901234567890', 10);
    const ours = a.toBuffer(20);
    const legacy = b.toBuffer(20);
    expect(ours).not.toBe(null);
    expect(toHex(ours as Uint8Array)).toBe(toHex(new Uint8Array(legacy)));
  });

  it('toBuffer(true) strips leading zero identically', () => {
    const a = new BigInteger('255', 10);
    const b = new LegacyBI('255', 10);
    const ours = a.toBuffer(true);
    const legacy = b.toBuffer(true);
    expect(toHex(ours as Uint8Array)).toBe(toHex(new Uint8Array(legacy)));
  });
});
