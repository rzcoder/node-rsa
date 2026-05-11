import { BigInteger } from '../bigint/big-integer.js';
import type { CryptoBackend } from '../crypto/types.js';
import type { EncryptionScheme, SchemeOptions, SignatureScheme } from '../schemes/types.js';

// Audit fix H5: one-shot small-key warning. Module-level flag so repeated
// calls during a test run (or legitimate small-key usage) don't spam stderr.
let warnedSmallKey = false;

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
    // Audit fix H5: refuse cryptographically trivial sizes outright; emit a
    // one-shot warning for sub-NIST sizes (below SP 800-56B §6.1.6.2's 2048-bit
    // minimum for ≥112-bit symmetric strength). Tests / legacy compat may
    // legitimately use 512–1024-bit keys; production code should not.
    if (B < 512) {
      throw new Error(
        `Key size ${B} bits is cryptographically broken (< 512); refusing to generate`,
      );
    }
    if (B < 2048 && !warnedSmallKey) {
      warnedSmallKey = true;
      // eslint-disable-next-line no-console
      console.warn(
        `node-rsa: generating ${B}-bit RSA key — below NIST SP 800-56B §6.1.6.2 minimum (2048 bits); not recommended for production`,
      );
    }
    const qs = B >> 1;
    this.e = Number.parseInt(E, 16);
    const ee = new BigInteger(E, 16);
    // Audit fix H4: Miller-Rabin rounds for the outer prime-acceptance check.
    // Legacy `isProbablePrime(10)` was halved to ~5 effective rounds (see C1+H4
    // fix in big-integer.ts:millerRabin). FIPS 186-4 Table C.3 requires ≥40
    // rounds for 1024-bit primes (n=2048-bit key) and ≥28 for ≥1536-bit primes.
    // We pick rounds by half-modulus bit length.
    const mrRounds = B >= 4096 ? 16 : B >= 3072 ? 28 : 40;
    // Audit fix H6: FIPS 186-4 §B.3.6 — require |p − q| > 2^(B/2 − 100) so the
    // modulus is not vulnerable to Fermat factoring. With CSPRNG-generated
    // primes the rejection rate is ≈ 2⁻¹⁰⁰ per pair (effectively never), but
    // omitting the check is a compliance gap.
    const minPQDiff = BigInteger.ONE.shiftLeft((B >> 1) - 100);
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
      // H6: regenerate the pair if p and q are too close.
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

  setPublic(N: Uint8Array, E: number | Uint8Array): void {
    if (!N || N.length === 0) throw new Error('Invalid RSA public key');
    if (typeof E !== 'number' && (!E || E.length === 0)) throw new Error('Invalid RSA public key');

    this.n = new BigInteger(N);
    this.e = typeof E === 'number' ? E : readBigEndianUInt(E);
    this.validateExponent();
    this.recalculateCache();
  }

  /**
   * Audit fix H1: validate `e` after import. RFC 8017 §3.1 requires
   * 1 < e < n with e odd. Accepting e=1 (ciphertext == plaintext), e=0,
   * or even e (breaks RSA invertibility) leaves a downgrade vector open
   * for malicious key imports.
   *
   * The e < n check is implicit for any realistic key (n ≥ 2^512 ≫ any
   * JS-number-encodable e), so we only enforce e > 1 and oddness here.
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
   * Audit fix H3: validate private-key CRT parameter consistency on import.
   *
   * Without this check, a maliciously crafted PEM/PKCS#8/OpenSSH file can
   * deliver components (p, q, dp, dq, qinv) that don't satisfy the RSA
   * invariants. The danger isn't garbage decryption — that's caught at
   * use time — but Boneh-DeMillo-Lipton fault-injection: with a corrupted
   * private key, even one faulted signature gives the attacker
   * gcd(s_correct − s_faulted, n), which factors n.
   *
   * Checks (skipped if CRT components weren't provided — basic n, e, d
   * key still works, just without CRT):
   *   1. n = p × q
   *   2. dp = d mod (p − 1)
   *   3. dq = d mod (q − 1)
   *   4. q × coeff ≡ 1 (mod p)        (coeff = q⁻¹ mod p)
   *   5. e × dp ≡ 1 (mod p − 1)       ⟹ e × d ≡ 1 (mod λ(n))
   *   6. e × dq ≡ 1 (mod q − 1)
   *
   * Cost: a handful of multiplications + four mods — much less than one
   * encrypt/decrypt. One-time on import.
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
    // Audit fix H2: RFC 8017 §5.1.2 / §3.2 require the RSA primitive input
    // to lie in [0, n-1]. Without this check, `x.mod(n)` would silently
    // accept x≥n (creating ciphertext malleability c → c+kn) and any
    // negative intermediate would corrupt CRT recombination.
    if (x.signum() < 0 || x.compareTo(this.n) >= 0) {
      throw new Error('RSA: input out of range (must be 0 ≤ x < n)');
    }

    // Audit fix C2: Base blinding (Kocher 1996). The variable-time `modPow`
    // (C3) leaks bits of d/dmp1/dmq1 unless the input is masked from the
    // attacker. We pre-multiply by r^e and post-multiply by r^-1, where r
    // is freshly random and coprime to n. Math:
    //   blindedX^d mod n = (x * r^e)^d mod n = x^d * r^(e*d) mod n = x^d * r mod n
    //   result = (x^d * r) * r^-1 mod n = x^d mod n
    const blinding = this.makeBlinding();
    const inputX = blinding ? x.multiply(blinding.re).mod(this.n) : x;

    let result: BigInteger;
    if (!this.p || !this.q || !this.dmp1 || !this.dmq1 || !this.coeff) {
      result = inputX.modPow(this.d, this.n);
    } else {
      const xp = inputX.mod(this.p).modPow(this.dmp1, this.p);
      const xq = inputX.mod(this.q).modPow(this.dmq1, this.q);
      // Audit fix H7: legacy `while (xp.compareTo(xq) < 0) xp = xp.add(this.p)`
      // executed 0 or 1 iterations depending on secret-dependent (xp, xq)
      // values, leaking the low bit of (xp - xq) via wall-clock. BigInteger.mod
      // normalises any negative dividend to [0, modulus), so the difference
      // can be computed directly — no branch, no data-dependent loop.
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
    const byteLen = ((n.bitLength() + 7) >> 3) + 1;
    const two = new BigInteger(Uint8Array.of(2));
    const nMinus3 = n.subtract(BigInteger.ONE).subtract(two); // range size for [2, n-2]

    for (let attempt = 0; attempt < 10; attempt++) {
      const rb = this.options.backend.randomBytes(byteLen);
      const r = new BigInteger(rb).mod(nMinus3).add(two);
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
    // Audit fix H2: same RFC 8017 §5.2.2 / §3.2 input-range requirement
    // as $doPrivate. Rejects s ≥ n on verify and m ≥ n on encrypt.
    if (x.signum() < 0 || x.compareTo(this.n) >= 0) {
      throw new Error('RSA: input out of range (must be 0 ≤ x < n)');
    }
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
