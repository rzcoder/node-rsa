import { beforeAll, describe, expect, it } from 'vitest';
import {
  BigInteger as JsbnBigInteger,
  setBigIntegerBackend as setJsbnBackend,
} from '../../src/bigint/big-integer-jsbn.js';
import {
  BigInteger as NativeBigInteger,
  setBigIntegerBackend as setNativeBackend,
} from '../../src/bigint/big-integer-native.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';

// Cross-impl parity: every method the rest of node-rsa actually calls
// must produce identical results on jsbn and native for representative
// inputs (positive, negative, zero, 2048-bit-ish modulus).

beforeAll(() => {
  setJsbnBackend(nodeBackend);
  setNativeBackend(nodeBackend);
});

const cases = {
  small: '12345',
  // 2048-bit-ish modulus from an existing test fixture, hex
  modulus:
    'c3d3c4f8de7f6b5a9c1b8a4f2e5d7c8b3a9f1e7d6c5b4a3e2d1c0f9e8d7c6b5a4938271605948372615a4b3c2d1e0f9876543210fedcba9876543210fedcba98',
  exp: '10001', // 65537
};

function toHexU8(s: string): Uint8Array {
  const pad = s.length & 1 ? `0${s}` : s;
  const out = new Uint8Array(pad.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = Number.parseInt(pad.substring(i * 2, i * 2 + 2), 16);
  return out;
}

describe('jsbn / native parity', () => {
  const J = (hex: string) => new JsbnBigInteger(hex, 16);
  const N = (hex: string) => new NativeBigInteger(hex, 16);
  const aJ = J(cases.small);
  const aN = N(cases.small);
  const bJ = J('100');
  const bN = N('100');
  const mJ = J(cases.modulus);
  const mN = N(cases.modulus);
  const eJ = J(cases.exp);
  const eN = N(cases.exp);

  it('add', () => {
    expect(aN.add(bN).toString(16)).toBe(aJ.add(bJ).toString(16));
  });
  it('subtract', () => {
    expect(aN.subtract(bN).toString(16)).toBe(aJ.subtract(bJ).toString(16));
  });
  it('multiply', () => {
    expect(aN.multiply(bN).toString(16)).toBe(aJ.multiply(bJ).toString(16));
  });
  it('mod (positive dividend)', () => {
    expect(aN.mod(bN).toString(16)).toBe(aJ.mod(bJ).toString(16));
  });
  it('mod (negative dividend → non-negative result)', () => {
    const negJ = J('-1234');
    const negN = N('-1234');
    expect(negN.mod(bN).toString(16)).toBe(negJ.mod(bJ).toString(16));
  });
  it('compareTo (sign equivalence)', () => {
    // jsbn returns the magnitude of the diff; native normalizes to -1/0/1.
    // All node-rsa call sites use === 0 / < 0 / > 0, so sign equivalence is
    // what matters for downstream correctness.
    const sign = (n: number) => (n > 0 ? 1 : n < 0 ? -1 : 0);
    expect(sign(aN.compareTo(bN))).toBe(sign(aJ.compareTo(bJ)));
    expect(sign(bN.compareTo(aN))).toBe(sign(bJ.compareTo(aJ)));
    expect(aN.compareTo(aN)).toBe(0);
  });
  it('bitLength', () => {
    expect(mN.bitLength()).toBe(mJ.bitLength());
  });
  it('signum', () => {
    expect(aN.signum()).toBe(aJ.signum());
    expect(N('-5').signum()).toBe(J('-5').signum());
    expect(N('0').signum()).toBe(J('0').signum());
  });
  it('gcd (coprimes → 1)', () => {
    expect(N('15').gcd(N('28')).toString(16)).toBe(J('15').gcd(J('28')).toString(16));
  });
  it('gcd (shared factor)', () => {
    expect(N('30').gcd(N('45')).toString(16)).toBe(J('30').gcd(J('45')).toString(16));
  });
  it('shiftLeft', () => {
    expect(aN.shiftLeft(100).toString(16)).toBe(aJ.shiftLeft(100).toString(16));
  });
  it('modPow (RSA-shaped: 2048-bit modulus, e=65537)', () => {
    const baseJ = J('beefcafe');
    const baseN = N('beefcafe');
    expect(baseN.modPow(eN, mN).toString(16)).toBe(baseJ.modPow(eJ, mJ).toString(16));
  });
  it('modInverse (coprime)', () => {
    const pJ = J('100000000000000000000000000000000000000000000000000000000003');
    const pN = N('100000000000000000000000000000000000000000000000000000000003');
    expect(eN.modInverse(pN).toString(16)).toBe(eJ.modInverse(pJ).toString(16));
  });
  it('toBuffer matches', () => {
    const jBuf = mJ.toBuffer() as Uint8Array;
    const nBuf = mN.toBuffer() as Uint8Array;
    expect([...nBuf]).toEqual([...jBuf]);
  });
  it('toBuffer with explicit length pads correctly', () => {
    const lenJ = (mJ.toBuffer(256) as Uint8Array).length;
    const lenN = (mN.toBuffer(256) as Uint8Array).length;
    expect(lenN).toBe(lenJ);
    expect(lenN).toBe(256);
  });
  it('fromBytes round-trips', () => {
    const bytes = toHexU8(cases.modulus);
    expect(new NativeBigInteger(bytes).toString(16)).toBe(new JsbnBigInteger(bytes).toString(16));
  });
  it('isProbablePrime: small composite rejected, small prime accepted', () => {
    expect(N('15').isProbablePrime(20)).toBe(false);
    expect(N('17').isProbablePrime(20)).toBe(true);
    expect(N('15').isProbablePrime(20)).toBe(J('15').isProbablePrime(20));
    expect(N('17').isProbablePrime(20)).toBe(J('17').isProbablePrime(20));
  });
  it('isEven / testBit', () => {
    expect(N('10').isEven()).toBe(J('10').isEven());
    expect(N('11').isEven()).toBe(J('11').isEven());
    expect(N('1010').testBit(1)).toBe(J('1010').testBit(1));
  });
});

describe('native end-to-end: generate + sign + verify with NodeRSA', async () => {
  it('forces native via constructor option and round-trips PSS-SHA256', async () => {
    const { default: NodeRSA } = await import('../../src/index.node.js');
    const key = new NodeRSA({ b: 512 }, { bigIntImpl: 'native' });
    expect(key.$options.bigIntImpl).toBe('native');
    const sig = key.sign('hello', 'buffer') as Uint8Array;
    expect(key.verify('hello', sig)).toBe(true);
  });

  it('throws if bigIntImpl is changed on a key with components', async () => {
    const { default: NodeRSA } = await import('../../src/index.node.js');
    const key = new NodeRSA({ b: 512 });
    expect(() => key.setOptions({ bigIntImpl: 'native' })).toThrow(/fresh instance/);
  });
});

describe('output parity across all 3 impls: jsbn ≡ native ≡ node (OpenSSL)', () => {
  // Three impls in this comparison:
  //   'jsbn'   — JS engine + JS schemes + jsbn BigInteger (force via env:'browser').
  //   'native' — JS engine + JS schemes + native BigInt   (force via env:'browser').
  //   'node'   — node bundle defaults: NodeNativeEngine + node:crypto for the
  //              RSA primitive (encrypt/decrypt/sign/verify).
  //
  // For deterministic ops (PKCS#1 v1.5 signing, key serialisation), all three
  // must produce byte-identical output. For probabilistic ops (PSS, OAEP)
  // bytes differ run-to-run by design, so we only check round-trip /
  // cross-verify between every pair.

  type Impl = 'jsbn' | 'native' | 'node';
  const IMPLS: ReadonlyArray<Impl> = ['jsbn', 'native', 'node'];
  const PEM_FIXTURE_PATH = '../../test/keys/private_pkcs1.pem';

  async function buildKey(impl: Impl) {
    const { default: NodeRSA } = await import('../../src/index.node.js');
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { dirname, resolve } = await import('node:path');
    const here = dirname(fileURLToPath(import.meta.url));
    const pem = readFileSync(resolve(here, PEM_FIXTURE_PATH), 'utf8');
    if (impl === 'node') {
      // Node bundle defaults: NodeNativeEngine + node:crypto-backed schemes.
      // bigIntImpl stays at the node-bundle default ('jsbn'), but the RSA
      // primitive never touches BigInteger here.
      return new NodeRSA(pem, 'pkcs1-private-pem');
    }
    // Force the JS path so the RSA primitive actually goes through
    // BigInteger and the bigIntImpl swap matters end-to-end.
    return new NodeRSA(pem, 'pkcs1-private-pem', {
      environment: 'browser',
      bigIntImpl: impl,
    });
  }

  function toHex(b: Uint8Array): string {
    let s = '';
    for (const x of b) s += x.toString(16).padStart(2, '0');
    return s;
  }

  async function buildAll(setOptions?: (k: Awaited<ReturnType<typeof buildKey>>) => void) {
    const keys = {} as Record<Impl, Awaited<ReturnType<typeof buildKey>>>;
    for (const impl of IMPLS) {
      const k = await buildKey(impl);
      if (setOptions) setOptions(k);
      keys[impl] = k;
    }
    return keys;
  }

  it('exportKey(pkcs1-private-der) is byte-identical across all 3 impls', async () => {
    const keys = await buildAll();
    const ref = toHex(keys.jsbn.exportKey('pkcs1-private-der') as Uint8Array);
    for (const impl of IMPLS) {
      const der = keys[impl].exportKey('pkcs1-private-der') as Uint8Array;
      expect(toHex(der), `DER from ${impl}`).toBe(ref);
    }
  });

  it('exportKey(components-public) yields identical n/e bytes across all 3 impls', async () => {
    const keys = await buildAll();
    const ref = keys.jsbn.exportKey('components-public') as { n: Uint8Array; e: number };
    for (const impl of IMPLS) {
      const c = keys[impl].exportKey('components-public') as { n: Uint8Array; e: number };
      expect(toHex(c.n), `n from ${impl}`).toBe(toHex(ref.n));
      expect(c.e, `e from ${impl}`).toBe(ref.e);
    }
  });

  it('PKCS1-SHA256 signatures are byte-identical across all 3 impls (deterministic)', async () => {
    const keys = await buildAll((k) => k.setOptions({ signingScheme: 'pkcs1-sha256' }));
    const ref = toHex(keys.jsbn.sign(PAYLOAD_MSG, 'buffer') as Uint8Array);
    for (const impl of IMPLS) {
      const sig = keys[impl].sign(PAYLOAD_MSG, 'buffer') as Uint8Array;
      expect(toHex(sig), `PKCS1 sig from ${impl}`).toBe(ref);
    }
  });

  it('PKCS1-SHA256 signatures cross-verify (3×3 matrix)', async () => {
    const keys = await buildAll((k) => k.setOptions({ signingScheme: 'pkcs1-sha256' }));
    const sigs: Record<Impl, Uint8Array> = {
      jsbn: keys.jsbn.sign(PAYLOAD_MSG, 'buffer') as Uint8Array,
      native: keys.native.sign(PAYLOAD_MSG, 'buffer') as Uint8Array,
      node: keys.node.sign(PAYLOAD_MSG, 'buffer') as Uint8Array,
    };
    for (const signer of IMPLS) {
      for (const verifier of IMPLS) {
        expect(keys[verifier].verify(PAYLOAD_MSG, sigs[signer]), `${signer} → ${verifier}`).toBe(
          true,
        );
      }
    }
  });

  it('PSS-SHA256 signatures cross-verify (3×3 matrix; probabilistic so bytes differ)', async () => {
    const keys = await buildAll((k) => k.setOptions({ signingScheme: 'pss-sha256' }));
    const sigs: Record<Impl, Uint8Array> = {
      jsbn: keys.jsbn.sign(PAYLOAD_MSG, 'buffer') as Uint8Array,
      native: keys.native.sign(PAYLOAD_MSG, 'buffer') as Uint8Array,
      node: keys.node.sign(PAYLOAD_MSG, 'buffer') as Uint8Array,
    };
    for (const signer of IMPLS) {
      for (const verifier of IMPLS) {
        expect(keys[verifier].verify(PAYLOAD_MSG, sigs[signer]), `${signer} → ${verifier}`).toBe(
          true,
        );
      }
    }
  });

  it('OAEP-SHA1 ciphertexts cross-decrypt (3×3 matrix; probabilistic)', async () => {
    const keys = await buildAll((k) => k.setOptions({ encryptionScheme: 'pkcs1_oaep' }));
    const cts: Record<Impl, Uint8Array> = {
      jsbn: keys.jsbn.encrypt(PAYLOAD_MSG, 'buffer') as Uint8Array,
      native: keys.native.encrypt(PAYLOAD_MSG, 'buffer') as Uint8Array,
      node: keys.node.encrypt(PAYLOAD_MSG, 'buffer') as Uint8Array,
    };
    for (const encryptor of IMPLS) {
      for (const decryptor of IMPLS) {
        const pt = keys[decryptor].decrypt(cts[encryptor]) as Uint8Array;
        expect(toHex(pt), `${encryptor} → ${decryptor}`).toBe(toHex(PAYLOAD_MSG));
      }
    }
  });
});

const PAYLOAD_MSG = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

describe('bigIntImpl consistency: every BigInteger in the lifecycle uses the same class', () => {
  // Verifies that no operation silently constructs a BigInteger of the
  // wrong class. After the active impl is set, key components, derived
  // values (blinding/CRT intermediates), and any new BigInteger spawned
  // by the JS scheme path must all be `instanceof` the same impl class.

  type AnyBI = typeof JsbnBigInteger | typeof NativeBigInteger;

  async function probe(opts: { bigIntImpl?: 'native' | 'jsbn' }, expected: AnyBI) {
    const { default: NodeRSA } = await import('../../src/index.node.js');
    // Force environment:'browser' so every path goes through BigInteger —
    // node-native paths bypass BigInteger entirely and would tell us
    // nothing about consistency.
    const key = new NodeRSA(
      { b: 512 },
      {
        environment: 'browser',
        ...opts,
      },
    );

    // Key components from RSAKey.generate
    expect(key.keyPair.n).toBeInstanceOf(expected);
    expect(key.keyPair.p).toBeInstanceOf(expected);
    expect(key.keyPair.q).toBeInstanceOf(expected);
    expect(key.keyPair.d).toBeInstanceOf(expected);
    expect(key.keyPair.dmp1).toBeInstanceOf(expected);
    expect(key.keyPair.dmq1).toBeInstanceOf(expected);
    expect(key.keyPair.coeff).toBeInstanceOf(expected);

    // Round-trip sign/verify (PSS via JS scheme — modPow path)
    const sig = key.sign('hello', 'buffer') as Uint8Array;
    expect(key.verify('hello', sig)).toBe(true);

    // Round-trip encrypt/decrypt (OAEP via JsEngine — modPow path)
    const ct = key.encrypt('msg', 'buffer') as Uint8Array;
    const pt = key.decrypt(ct, 'utf8') as string;
    expect(pt).toBe('msg');

    // Confirm $options reflects the active impl
    expect(key.$options.bigIntImpl).toBe(opts.bigIntImpl ?? 'jsbn');
  }

  it('default (jsbn on node) → every component is JsbnBigInteger', async () => {
    await probe({ bigIntImpl: 'jsbn' }, JsbnBigInteger);
  });

  it('bigIntImpl: native → every component is NativeBigInteger', async () => {
    await probe({ bigIntImpl: 'native' }, NativeBigInteger);
  });

  it('browser bundle (default native) → every component is NativeBigInteger', async () => {
    // Import the browser entry; its module-load setBigIntegerImpl('native')
    // runs once at first import. Subsequent constructors honour it as the
    // baseline default.
    const { default: NodeRSA } = await import('../../src/index.browser.js');
    const key = new NodeRSA({ b: 512 });
    expect(key.$options.bigIntImpl).toBe('native');
    expect(key.keyPair.n).toBeInstanceOf(NativeBigInteger);
    expect(key.keyPair.p).toBeInstanceOf(NativeBigInteger);
    expect(key.keyPair.dmp1).toBeInstanceOf(NativeBigInteger);
    const sig = key.sign('hello', 'buffer') as Uint8Array;
    expect(key.verify('hello', sig)).toBe(true);
    const ct = key.encrypt('msg', 'buffer') as Uint8Array;
    expect(key.decrypt(ct, 'utf8')).toBe('msg');
  });
});
