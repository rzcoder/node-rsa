import { BigInteger } from '../bigint/big-integer.js';
import type { CryptoBackend } from '../crypto/types.js';
import type { EncryptionScheme, SchemeOptions, SignatureScheme } from '../schemes/types.js';

/**
 * Asymmetric RSA key (public or private). Mirrors the v1 `RSAKey` shape so
 * the higher-level NodeRSA class can keep its surface unchanged.
 *
 * Field semantics (RFC 3447):
 *   n     — modulus
 *   e     — public exponent
 *   d     — private exponent
 *   p, q  — prime factors of n (n = p * q)
 *   dmp1  — d mod (p - 1)
 *   dmq1  — d mod (q - 1)
 *   coeff — (q^-1) mod p, used by CRT decryption
 */
export class RSAKey {
  n: BigInteger | null = null;
  e = 0;
  d: BigInteger | null = null;
  p: BigInteger | null = null;
  q: BigInteger | null = null;
  dmp1: BigInteger | null = null;
  dmq1: BigInteger | null = null;
  coeff: BigInteger | null = null;

  // Cached per-update key metrics.
  cache: { keyBitLength: number; keyByteLength: number } = {
    keyBitLength: 0,
    keyByteLength: 0,
  };

  // Scheme bindings — populated by setOptions().
  encryptionScheme!: EncryptionScheme;
  signingScheme!: SignatureScheme;
  options!: SchemeOptions;

  /** OpenSSH key comment field (preserved across import/export). */
  sshcomment?: string;

  setOptions(
    options: SchemeOptions,
    schemes: Record<string, { makeScheme(key: RSAKey, opts: SchemeOptions): unknown }>,
  ): void {
    this.options = options;
    const sigProvider = schemes[options.signingScheme];
    const encProvider = schemes[options.encryptionScheme];
    if (!sigProvider) throw new Error(`Unknown signing scheme: ${options.signingScheme}`);
    if (!encProvider) throw new Error(`Unknown encryption scheme: ${options.encryptionScheme}`);

    if (sigProvider === encProvider) {
      const scheme = sigProvider.makeScheme(this, options) as EncryptionScheme & SignatureScheme;
      this.signingScheme = scheme;
      this.encryptionScheme = scheme;
    } else {
      this.encryptionScheme = encProvider.makeScheme(this, options) as EncryptionScheme;
      this.signingScheme = sigProvider.makeScheme(this, options) as SignatureScheme;
    }
  }

  /**
   * Generate a fresh `B`-bit private key with public exponent E (hex string).
   * Matches v1's algorithm and RNG call pattern exactly.
   */
  generate(B: number, E: string): void {
    const qs = B >> 1;
    this.e = Number.parseInt(E, 16);
    const ee = new BigInteger(E, 16);
    // Audit fix H4: Miller-Rabin rounds for the outer prime-acceptance check.
    // Legacy `isProbablePrime(10)` was halved to ~5 effective rounds (see C1+H4
    // fix in big-integer.ts:millerRabin). FIPS 186-4 Table C.3 requires ≥40
    // rounds for 1024-bit primes (n=2048-bit key) and ≥28 for ≥1536-bit primes.
    // We pick rounds by half-modulus bit length.
    const mrRounds = B >= 4096 ? 16 : B >= 3072 ? 28 : 40;
    while (true) {
      while (true) {
        // Inner loop: `BigInteger(bits, 1)` runs fromNumber's sequential prime
        // search with certainty=1 (one MR round per candidate). Combined with
        // trial-division by 168 small primes and the strong outer check below,
        // this is a standard sieve-then-validate flow.
        this.p = new BigInteger(B - qs, 1);
        if (
          this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 &&
          this.p.isProbablePrime(mrRounds)
        ) {
          break;
        }
      }
      while (true) {
        this.q = new BigInteger(qs, 1);
        if (
          this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 &&
          this.q.isProbablePrime(mrRounds)
        ) {
          break;
        }
      }
      if (this.p.compareTo(this.q) <= 0) {
        const t = this.p;
        this.p = this.q;
        this.q = t;
      }
      const p1 = this.p.subtract(BigInteger.ONE);
      const q1 = this.q.subtract(BigInteger.ONE);
      const phi = p1.multiply(q1);
      if (phi.gcd(ee).compareTo(BigInteger.ONE) === 0) {
        this.n = this.p.multiply(this.q);
        if (this.n.bitLength() < B) continue;
        this.d = ee.modInverse(phi);
        this.dmp1 = this.d.mod(p1);
        this.dmq1 = this.d.mod(q1);
        this.coeff = this.q.modInverse(this.p);
        break;
      }
    }
    this.recalculateCache();
  }

  setPrivate(
    N: Uint8Array,
    E: number | Uint8Array,
    D: Uint8Array,
    P?: Uint8Array,
    Q?: Uint8Array,
    DP?: Uint8Array,
    DQ?: Uint8Array,
    C?: Uint8Array,
  ): void {
    if (!N || N.length === 0) throw new Error('Invalid RSA private key');
    if (typeof E !== 'number' && (!E || E.length === 0)) throw new Error('Invalid RSA private key');
    if (!D || D.length === 0) throw new Error('Invalid RSA private key');

    this.n = new BigInteger(N);
    this.e = typeof E === 'number' ? E : readBigEndianUInt(E);
    this.d = new BigInteger(D);

    if (P && Q && DP && DQ && C) {
      this.p = new BigInteger(P);
      this.q = new BigInteger(Q);
      this.dmp1 = new BigInteger(DP);
      this.dmq1 = new BigInteger(DQ);
      this.coeff = new BigInteger(C);
    }
    this.recalculateCache();
  }

  setPublic(N: Uint8Array, E: number | Uint8Array): void {
    if (!N || N.length === 0) throw new Error('Invalid RSA public key');
    if (typeof E !== 'number' && (!E || E.length === 0)) throw new Error('Invalid RSA public key');

    this.n = new BigInteger(N);
    this.e = typeof E === 'number' ? E : readBigEndianUInt(E);
    this.recalculateCache();
  }

  /** x^d mod n, using CRT if p/q are available, otherwise direct. */
  $doPrivate(x: BigInteger): BigInteger {
    if (!this.n || !this.d) throw new Error('No private key');
    if (!this.p || !this.q || !this.dmp1 || !this.dmq1 || !this.coeff) {
      return x.modPow(this.d, this.n);
    }
    let xp = x.mod(this.p).modPow(this.dmp1, this.p);
    const xq = x.mod(this.q).modPow(this.dmq1, this.q);
    while (xp.compareTo(xq) < 0) xp = xp.add(this.p);
    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
  }

  /** x^e mod n. */
  $doPublic(x: BigInteger): BigInteger {
    if (!this.n) throw new Error('No public key');
    return x.modPowInt(this.e, this.n);
  }

  isPrivate(): boolean {
    return !!(this.n && this.e && this.d);
  }

  isPublic(strict?: boolean): boolean {
    if (!this.n || !this.e) return false;
    if (strict && this.d) return false;
    return true;
  }

  get keySize(): number {
    return this.cache.keyBitLength;
  }

  get encryptedDataLength(): number {
    return this.cache.keyByteLength;
  }

  get maxMessageLength(): number {
    return this.encryptionScheme.maxMessageLength();
  }

  recalculateCache(): void {
    if (!this.n) {
      this.cache = { keyBitLength: 0, keyByteLength: 0 };
      return;
    }
    const keyBitLength = this.n.bitLength();
    this.cache = {
      keyBitLength,
      keyByteLength: (keyBitLength + 6) >> 3,
    };
  }

  /** Convenience: get the backend bound via setOptions. */
  get backend(): CryptoBackend {
    return this.options.backend;
  }
}

function readBigEndianUInt(buf: Uint8Array): number {
  let n = 0;
  for (let i = 0; i < buf.length; i++) n = n * 256 + (buf[i] as number);
  return n;
}
