import { BigInteger } from '../bigint/big-integer.js';
import type { CryptoBackend } from '../crypto/types.js';
import type { EncryptionSchemeImpl, SchemeOptions, SignatureScheme } from '../schemes/types.js';

// One-shot guard so repeated small-key calls don't spam stderr.
let warnedSmallKey = false;

/**
 * Asymmetric RSA key (public or private).
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
  encryptionScheme!: EncryptionSchemeImpl;
  signingScheme!: SignatureScheme;
  options!: SchemeOptions;

  /** OpenSSH key comment field (preserved across import/export). */
  sshcomment?: string;

  /**
   * BigInteger constructor that owns this key's components. Read off
   * `n.constructor` so a later `setBigIntegerImpl()` swap by another
   * NodeRSA instance can't corrupt operations on this key — fresh
   * BigIntegers spawned during sign/encrypt/blinding stay the same class
   * as `n`, `d`, `p`, `q` etc.
   */
  get BI(): typeof BigInteger {
    if (!this.n) throw new Error('RSAKey: no key components');
    return this.n.constructor as typeof BigInteger;
  }

  /**
   * Bind encryption + signing scheme instances to this key. If both schemes
   * resolve to the same provider (PKCS#1 v1.5 covers both), one instance is
   * shared so internal padding state stays consistent. Throws on unknown
   * scheme names.
   */
  setOptions(
    options: SchemeOptions,
    schemes: Record<
      string,
      { makeScheme(key: RSAKey, opts: SchemeOptions): EncryptionSchemeImpl | SignatureScheme }
    >,
  ): void {
    this.options = options;
    const sigProvider = schemes[options.signingScheme];
    const encProvider = schemes[options.encryptionScheme];
    if (!sigProvider) throw new Error(`Unknown signing scheme: ${options.signingScheme}`);
    if (!encProvider) throw new Error(`Unknown encryption scheme: ${options.encryptionScheme}`);

    if (sigProvider === encProvider) {
      const scheme = sigProvider.makeScheme(this, options) as EncryptionSchemeImpl &
        SignatureScheme;
      this.signingScheme = scheme;
      this.encryptionScheme = scheme;
    } else {
      this.encryptionScheme = encProvider.makeScheme(this, options) as EncryptionSchemeImpl;
      this.signingScheme = sigProvider.makeScheme(this, options) as SignatureScheme;
    }
  }

  /**
   * Generate a fresh `B`-bit private key with public exponent E (hex string).
   * Matches v1's algorithm and RNG call pattern exactly.
   */
  generate(B: number, E: string): void {
    if (B < 512) {
      throw new Error(
        `Key size ${B} bits is cryptographically broken (< 512); refusing to generate`,
      );
    }
    if (B < 2048 && !warnedSmallKey) {
      warnedSmallKey = true;
      // Below NIST SP 800-56B §6.1.6.2's 2048-bit minimum.
      // eslint-disable-next-line no-console
      console.warn(
        `node-rsa: generating ${B}-bit RSA key — below NIST SP 800-56B §6.1.6.2 minimum (2048 bits); not recommended for production`,
      );
    }
    const qs = B >> 1;
    this.e = Number.parseInt(E, 16);
    const ee = new BigInteger(E, 16);
    // FIPS 186-4 Table C.3 Miller-Rabin minimums by half-modulus bit length.
    const mrRounds = B >= 4096 ? 16 : B >= 3072 ? 28 : 40;
    // FIPS 186-4 §B.3.6 Fermat-factoring defence: require |p − q| > 2^(B/2 − 100).
    // With CSPRNG primes the rejection rate is ≈ 2⁻¹⁰⁰ per pair.
    const minPQDiff = BigInteger.ONE.shiftLeft((B >> 1) - 100);
    while (true) {
      while (true) {
        // `BigInteger(bits, 1)` is fromNumber's sequential prime search with
        // one Miller-Rabin round per candidate — combined with trial division
        // by 168 small primes, fast enough for the sieve. The outer
        // isProbablePrime(mrRounds) below does the strong validation.
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
      // Regenerate the pair if p and q are too close (Fermat defence).
      if (this.p.subtract(this.q).compareTo(minPQDiff) < 0) continue;
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

  /**
   * Install private-key components (raw big-endian bytes; E may be a number).
   * If any CRT field (P/Q/DP/DQ/C) is omitted the key works without CRT —
   * slower decrypt but valid. Throws if N/E/D are missing or if CRT fields
   * are present but mathematically inconsistent (Boneh-DeMillo-Lipton
   * fault-attack guard).
   */
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
    this.validateExponent();
    this.validatePrivateConsistency();
    this.recalculateCache();
  }

  /** Install public-key components (raw big-endian bytes; E may be a number). Throws if N/E are missing or E is invalid. */
  setPublic(N: Uint8Array, E: number | Uint8Array): void {
    if (!N || N.length === 0) throw new Error('Invalid RSA public key');
    if (typeof E !== 'number' && (!E || E.length === 0)) throw new Error('Invalid RSA public key');

    this.n = new BigInteger(N);
    this.e = typeof E === 'number' ? E : readBigEndianUInt(E);
    this.validateExponent();
    this.recalculateCache();
  }

  /**
   * RFC 8017 §3.1 requires 1 < e < n with e odd. e=1 makes ciphertext ==
   * plaintext; even e breaks RSA invertibility entirely. The e < n side
   * is implicit (n ≥ 2^512 ≫ any JS-number-encodable e).
   */
  private validateExponent(): void {
    if (this.e <= 1) {
      throw new Error('Invalid RSA exponent: e must be > 1');
    }
    if ((this.e & 1) === 0) {
      throw new Error('Invalid RSA exponent: e must be odd');
    }
  }

  /**
   * Cross-check CRT invariants for an imported private key. Inconsistent
   * components (n ≠ p·q, mismatched dp/dq, bad coeff) don't just produce
   * garbage on decrypt — they enable Boneh-DeMillo-Lipton fault attacks
   * where a single faulted signature reveals gcd(s_correct − s_faulted, n)
   * and factors n. Skipped when CRT components are absent (basic n, e, d
   * key still works, just without CRT).
   */
  private validatePrivateConsistency(): void {
    if (!this.n || !this.d || !this.p || !this.q || !this.dmp1 || !this.dmq1 || !this.coeff) {
      return;
    }
    if (this.p.multiply(this.q).compareTo(this.n) !== 0) {
      throw new Error('RSA private key inconsistent: n ≠ p × q');
    }
    const p1 = this.p.subtract(BigInteger.ONE);
    const q1 = this.q.subtract(BigInteger.ONE);
    if (this.d.mod(p1).compareTo(this.dmp1) !== 0) {
      throw new Error('RSA private key inconsistent: dp ≠ d mod (p − 1)');
    }
    if (this.d.mod(q1).compareTo(this.dmq1) !== 0) {
      throw new Error('RSA private key inconsistent: dq ≠ d mod (q − 1)');
    }
    if (this.q.multiply(this.coeff).mod(this.p).compareTo(BigInteger.ONE) !== 0) {
      throw new Error('RSA private key inconsistent: q × coeff ≢ 1 (mod p)');
    }
    const eBig = new BigInteger(this.e.toString(16), 16);
    if (eBig.multiply(this.dmp1).mod(p1).compareTo(BigInteger.ONE) !== 0) {
      throw new Error('RSA private key inconsistent: e × dp ≢ 1 (mod p − 1)');
    }
    if (eBig.multiply(this.dmq1).mod(q1).compareTo(BigInteger.ONE) !== 0) {
      throw new Error('RSA private key inconsistent: e × dq ≢ 1 (mod q − 1)');
    }
  }

  /** x^d mod n, using CRT if p/q are available, otherwise direct. */
  $doPrivate(x: BigInteger): BigInteger {
    if (!this.n || !this.d) throw new Error('No private key');
    // RFC 8017 §5.1.2 / §3.2 mandate inputs in [0, n-1]. Without this
    // check, ciphertext c and c+kn would decrypt the same (malleability)
    // and negative intermediates would corrupt CRT recombination.
    if (x.signum() < 0 || x.compareTo(this.n) >= 0) {
      throw new Error('RSA: input out of range (must be 0 ≤ x < n)');
    }

    // Base blinding (Kocher 1996): the variable-time modPow leaks d-bits
    // unless its input is masked from the attacker. Pre-multiply by r^e,
    // post-multiply by r^-1, with r ← random coprime to n:
    //   (x · r^e)^d  =  x^d · r^(e·d)  =  x^d · r  (mod n)
    //   then × r^-1 mod n = x^d mod n
    const blinding = this.makeBlinding();
    const inputX = blinding ? x.multiply(blinding.re).mod(this.n) : x;

    let result: BigInteger;
    if (!this.p || !this.q || !this.dmp1 || !this.dmq1 || !this.coeff) {
      result = inputX.modPow(this.d, this.n);
    } else {
      const xp = inputX.mod(this.p).modPow(this.dmp1, this.p);
      const xq = inputX.mod(this.q).modPow(this.dmq1, this.q);
      // Garner recombination without a data-dependent `while (xp < xq)`
      // loop: BigInteger.mod normalises any negative dividend to [0, p).
      result = xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
    }

    if (blinding) {
      result = result.multiply(blinding.rInv).mod(this.n);
    }
    return result;
  }

  /**
   * Produce a fresh blinding pair (r^e mod n, r^-1 mod n) for one private
   * operation. Returns null only in the astronomically rare case that the
   * RNG keeps producing r with gcd(r, n) ≠ 1 — probability ≈ 2/√n per
   * attempt; 10 attempts is overkill safety.
   *
   * Returns null also if there's no backend yet (e.g., key without
   * setOptions() — only happens in some test setups).
   */
  private makeBlinding(): { re: BigInteger; rInv: BigInteger } | null {
    if (!this.n || !this.options) return null;
    const n = this.n;
    const BI = this.BI;
    const byteLen = ((n.bitLength() + 7) >> 3) + 1;
    const two = new BI(Uint8Array.of(2));
    const nMinus3 = n.subtract(BI.ONE).subtract(two); // range size for [2, n-2]

    for (let attempt = 0; attempt < 10; attempt++) {
      const rb = this.options.backend.randomBytes(byteLen);
      const r = new BI(rb).mod(nMinus3).add(two);
      const rInv = r.modInverse(n);
      if (rInv.signum() === 0) continue; // gcd(r, n) ≠ 1; retry
      const re = r.modPowInt(this.e, n);
      return { re, rInv };
    }
    return null;
  }

  /** x^e mod n. */
  $doPublic(x: BigInteger): BigInteger {
    if (!this.n) throw new Error('No public key');
    // RFC 8017 §5.2.2 / §3.2 mandate inputs in [0, n-1]; rejects s ≥ n
    // on verify and m ≥ n on encrypt.
    if (x.signum() < 0 || x.compareTo(this.n) >= 0) {
      throw new Error('RSA: input out of range (must be 0 ≤ x < n)');
    }
    return x.modPowInt(this.e, this.n);
  }

  /** True iff `d` is loaded (n, e implied). */
  isPrivate(): boolean {
    return !!(this.n && this.e && this.d);
  }

  /** True iff `n` and `e` are set. With `strict=true` additionally requires `d` to be absent. */
  isPublic(strict?: boolean): boolean {
    if (!this.n || !this.e) return false;
    if (strict && this.d) return false;
    return true;
  }

  /** Modulus size in bits (0 if no key loaded). */
  get keySize(): number {
    return this.cache.keyBitLength;
  }

  /** Ciphertext block size in bytes. */
  get encryptedDataLength(): number {
    return this.cache.keyByteLength;
  }

  /** Largest single-chunk plaintext the configured encryption scheme will accept. */
  get maxMessageLength(): number {
    return this.encryptionScheme.maxMessageLength();
  }

  /** Recompute cached key-size metrics. */
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

  /**
   * Clear all key material from this instance. Call when the key is no
   * longer needed to reduce the window in which private components are
   * reachable from the JS heap (heap snapshots, core dumps, swap).
   *
   * JavaScript has no guaranteed deterministic memory zeroing — GC-managed
   * BigInteger internals may linger until collected. This method removes
   * references as early as possible, which is the strongest guarantee the
   * language offers.
   */
  destroy(): void {
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
    this.cache = { keyBitLength: 0, keyByteLength: 0 };
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
