import type { CryptoBackend } from '../crypto/types.js';

// Native-BigInt implementation of the jsbn BigInteger surface used by node-rsa.
// Drop-in for src/bigint/big-integer-jsbn.ts — same exported class name and
// public methods. Selected by src/bigint/big-integer.ts (selector).
//
// Backend injection (random_bytes for primality testing) mirrors the jsbn file.

let _backend: CryptoBackend | undefined;

export function setBigIntegerBackend(backend: CryptoBackend): void {
  _backend = backend;
}

function getBackend(): CryptoBackend {
  if (!_backend) {
    throw new Error(
      'BigInteger (native): backend not set. Did you import the package via its main entry?',
    );
  }
  return _backend;
}

// helpers
const ZERO_BI = 0n;
const ONE_BI = 1n;
const TWO_BI = 2n;

/** big-endian bytes → unsigned bigint (signed if `unsigned === false`). */
function bytesToBigInt(bytes: Uint8Array, unsigned: boolean): bigint {
  if (bytes.length === 0) return ZERO_BI;
  if (!unsigned && (bytes[0]! & 0x80) !== 0) {
    // signed two's complement → negative magnitude
    let inv = ZERO_BI;
    for (let i = 0; i < bytes.length; i++) {
      inv = (inv << 8n) | BigInt(bytes[i]! ^ 0xff);
    }
    return -(inv + ONE_BI);
  }
  let v = ZERO_BI;
  for (let i = 0; i < bytes.length; i++) {
    v = (v << 8n) | BigInt(bytes[i]!);
  }
  return v;
}

/**
 * bigint → big-endian bytes, matching jsbn `toBuffer` semantics:
 *  - If `length` is given, output is exactly that many bytes (left-padded
 *    with zeros, truncated from the left if too long).
 *  - If `length` is omitted, the magnitude is emitted with a leading 0x00
 *    when the high bit would otherwise be set — so the bytes survive an
 *    ASN.1 two's-complement round-trip without sign confusion.
 */
function bigIntToBytes(v: bigint, length?: number): Uint8Array {
  if (v < ZERO_BI) throw new Error('BigInteger.toBuffer: negative value');
  if (v === ZERO_BI) return new Uint8Array(length ?? 1);
  let hex = v.toString(16);
  if (hex.length & 1) hex = `0${hex}`;
  const raw = new Uint8Array(hex.length / 2);
  for (let i = 0; i < raw.length; i++) {
    raw[i] = Number.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  if (length === undefined) {
    // Prepend 0x00 if the high bit is set, matching jsbn's sign-preserving
    // output. ASN.1 writers in this codebase normalize either form, so this
    // is for byte-level parity rather than functional correctness.
    if ((raw[0] as number) & 0x80) {
      const padded = new Uint8Array(raw.length + 1);
      padded.set(raw, 1);
      return padded;
    }
    return raw;
  }
  if (length === raw.length) return raw;
  if (length < raw.length) {
    let cut = 0;
    while (cut < raw.length - length && raw[cut] === 0) cut++;
    if (raw.length - cut === length) return raw.slice(cut);
    return raw.slice(raw.length - length);
  }
  const out = new Uint8Array(length);
  out.set(raw, length - raw.length);
  return out;
}

function bitLengthOf(v: bigint): number {
  if (v === ZERO_BI) return 0;
  const x = v < ZERO_BI ? -v : v;
  return x.toString(2).length;
}

/** square-and-multiply modular exponentiation. */
function modPowBI(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === ONE_BI) return ZERO_BI;
  if (exp < ZERO_BI) {
    // a^-e mod n = (a^-1)^e mod n
    return modPowBI(modInverseBI(base, mod), -exp, mod);
  }
  let b = base % mod;
  if (b < ZERO_BI) b += mod;
  let result = ONE_BI;
  let e = exp;
  while (e > ZERO_BI) {
    if (e & ONE_BI) result = (result * b) % mod;
    e >>= ONE_BI;
    b = (b * b) % mod;
  }
  return result;
}

/** Extended Euclidean inverse; returns 0n if gcd(a, m) ≠ 1 (jsbn behaviour). */
function modInverseBI(a: bigint, m: bigint): bigint {
  if (m <= ZERO_BI) throw new Error('BigInteger.modInverse: modulus must be positive');
  let aNorm = a % m;
  if (aNorm < ZERO_BI) aNorm += m;
  let oldR = aNorm;
  let r = m;
  let oldS = ONE_BI;
  let s = ZERO_BI;
  while (r !== ZERO_BI) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== ONE_BI) return ZERO_BI; // no inverse
  return oldS < ZERO_BI ? oldS + m : oldS;
}

function gcdBI(a: bigint, b: bigint): bigint {
  let x = a < ZERO_BI ? -a : a;
  let y = b < ZERO_BI ? -b : b;
  while (y !== ZERO_BI) {
    [x, y] = [y, x % y];
  }
  return x;
}

// 168 primes below 1000; matches jsbn's sieve table.
// biome-ignore format: dense table reads better unwrapped
const SMALL_PRIMES: ReadonlyArray<number> = [
  2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,
  73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,
  179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,
  283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,
  419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,
  547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,
  661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,
  811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,
  947,953,967,971,977,983,991,997,
];
const SMALL_PRIMES_BI: ReadonlyArray<bigint> = SMALL_PRIMES.map((p) => BigInt(p));

/**
 * Miller-Rabin primality test with CSPRNG witnesses in [2, n-2].
 * Matches src/bigint/big-integer-jsbn.ts's audited semantics.
 */
function millerRabin(n: bigint, rounds: number): boolean {
  if (n < TWO_BI) return false;
  if (n === TWO_BI || n === 3n) return true;
  if ((n & ONE_BI) === ZERO_BI) return false;

  const nMinus1 = n - ONE_BI;
  let s = 0;
  let d = nMinus1;
  while ((d & ONE_BI) === ZERO_BI) {
    d >>= ONE_BI;
    s++;
  }

  const byteLen = ((bitLengthOf(n) + 7) >> 3) + 1;
  const backend = getBackend();
  const nMinus3 = n - 3n; // range size for [0, n-4]; we add 2 → [2, n-2]

  witnessLoop: for (let i = 0; i < rounds; i++) {
    let a: bigint;
    for (;;) {
      a = bytesToBigInt(backend.randomBytes(byteLen), true) % nMinus3;
      a += TWO_BI;
      if (a >= TWO_BI && a <= nMinus1 - ONE_BI) break;
    }
    let x = modPowBI(a, d, n);
    if (x === ONE_BI || x === nMinus1) continue;
    for (let r = 1; r < s; r++) {
      x = (x * x) % n;
      if (x === nMinus1) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function probablePrime(v: bigint, rounds: number): boolean {
  if (v < TWO_BI) return false;
  for (const p of SMALL_PRIMES_BI) {
    if (v === p) return true;
    if (v % p === ZERO_BI) return false;
  }
  return millerRabin(v, rounds);
}

/**
 * Generate a random `bits`-bit number that passes a single Miller-Rabin round.
 * Matches jsbn fromNumber(bits, 1): the caller in RSAKey.generate runs a
 * second isProbablePrime(mrRounds) for full FIPS 186-4 validation.
 */
function generateProbablePrime(bits: number): bigint {
  if (bits < 2) throw new Error('BigInteger: cannot generate prime with < 2 bits');
  const byteLen = (bits + 7) >> 3;
  const backend = getBackend();
  while (true) {
    const x = backend.randomBytes(byteLen);
    // Mask off unused high bits, then force top bit (exact bit length) and bottom bit (odd).
    const tailBits = bits & 7;
    if (tailBits > 0) x[0] = (x[0]! & ((1 << tailBits) - 1)) as number;
    let v = bytesToBigInt(x, true);
    v |= ONE_BI << BigInt(bits - 1);
    v |= ONE_BI;
    // Sequential search; bail and retry with fresh randomness if we'd exceed bit length.
    for (let step = 0; step < 1 << 15; step += 2) {
      if (bitLengthOf(v) > bits) break;
      if (probablePrime(v, 1)) return v;
      v += TWO_BI;
    }
  }
}

function parseFromString(s: string, radix: number): bigint {
  if (s.length === 0) return ZERO_BI;
  let str = s;
  let neg = false;
  if (str[0] === '-') {
    neg = true;
    str = str.substring(1);
  }
  if (str.length === 0) return ZERO_BI;
  let v: bigint;
  if (radix === 10) {
    v = BigInt(str);
  } else if (radix === 16) {
    v = BigInt(`0x${str}`);
  } else {
    const r = BigInt(radix);
    v = ZERO_BI;
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      let d: number;
      if (code >= 48 && code <= 57) d = code - 48;
      else if (code >= 65 && code <= 90) d = code - 55;
      else if (code >= 97 && code <= 122) d = code - 87;
      else continue;
      if (d < 0 || d >= radix) continue;
      v = v * r + BigInt(d);
    }
  }
  return neg ? -v : v;
}

// the public class
export class BigInteger {
  static readonly ONE: BigInteger = new BigInteger(1);
  static readonly ZERO: BigInteger = new BigInteger(0);

  private _v: bigint;

  constructor(a?: number | string | Uint8Array | bigint | null, b?: number, unsigned?: boolean) {
    if (a == null) {
      this._v = ZERO_BI;
    } else if (typeof a === 'bigint') {
      this._v = a;
    } else if (typeof a === 'number') {
      if (b === 1) {
        this._v = generateProbablePrime(a);
      } else {
        this._v = BigInt(a);
      }
    } else if (typeof a === 'string') {
      this._v = parseFromString(a, b ?? 10);
    } else if (a instanceof Uint8Array) {
      // Match jsbn's fromBuffer default: bytes are treated as unsigned
      // big-endian unless the caller explicitly says otherwise. RSA
      // components (n, p, q, …) almost always have the high bit set, so
      // any other default flips them to negative.
      this._v = bytesToBigInt(a, unsigned ?? true);
    } else {
      throw new Error(`BigInteger: unsupported input type ${typeof a}`);
    }
  }

  signum(): -1 | 0 | 1 {
    return this._v === ZERO_BI ? 0 : this._v > ZERO_BI ? 1 : -1;
  }

  compareTo(o: BigInteger): -1 | 0 | 1 {
    if (this._v === o._v) return 0;
    return this._v > o._v ? 1 : -1;
  }

  bitLength(): number {
    return bitLengthOf(this._v);
  }

  testBit(n: number): boolean {
    return ((this._v >> BigInt(n)) & ONE_BI) === ONE_BI;
  }

  isEven(): boolean {
    return (this._v & ONE_BI) === ZERO_BI;
  }

  /** @internal */
  negate(): BigInteger {
    return new BigInteger(-this._v);
  }

  abs(): BigInteger {
    return new BigInteger(this._v < ZERO_BI ? -this._v : this._v);
  }

  add(o: BigInteger): BigInteger {
    return new BigInteger(this._v + o._v);
  }

  subtract(o: BigInteger): BigInteger {
    return new BigInteger(this._v - o._v);
  }

  multiply(o: BigInteger): BigInteger {
    return new BigInteger(this._v * o._v);
  }

  square(): BigInteger {
    return new BigInteger(this._v * this._v);
  }

  /** @internal */
  divide(o: BigInteger): BigInteger {
    return new BigInteger(this._v / o._v);
  }

  /** Returns [quotient, remainder]. Matches jsbn divideAndRemainder. */
  divideAndRemainder(o: BigInteger): [BigInteger, BigInteger] {
    return [new BigInteger(this._v / o._v), new BigInteger(this._v % o._v)];
  }

  /** Always non-negative result for positive modulus (Java/jsbn semantics). */
  mod(o: BigInteger): BigInteger {
    const m = o._v;
    if (m === ZERO_BI) throw new Error('BigInteger.mod: divide by zero');
    let r = this._v % m;
    const absM = m < ZERO_BI ? -m : m;
    if (r < ZERO_BI) r += absM;
    return new BigInteger(r);
  }

  modPow(e: BigInteger, m: BigInteger): BigInteger {
    return new BigInteger(modPowBI(this._v, e._v, m._v));
  }

  modPowInt(e: number, m: BigInteger): BigInteger {
    return new BigInteger(modPowBI(this._v, BigInt(e), m._v));
  }

  modInverse(m: BigInteger): BigInteger {
    return new BigInteger(modInverseBI(this._v, m._v));
  }

  gcd(o: BigInteger): BigInteger {
    return new BigInteger(gcdBI(this._v, o._v));
  }

  shiftLeft(n: number): BigInteger {
    return new BigInteger(n >= 0 ? this._v << BigInt(n) : this._v >> BigInt(-n));
  }

  shiftRight(n: number): BigInteger {
    return new BigInteger(n >= 0 ? this._v >> BigInt(n) : this._v << BigInt(-n));
  }

  isProbablePrime(rounds: number): boolean {
    return probablePrime(this._v, rounds);
  }

  toString(radix?: number): string {
    return this._v.toString(radix ?? 10);
  }

  /** Unsigned big-endian bytes; pads/truncates to `length` if given (jsbn parity). */
  toBuffer(length?: number): Uint8Array | null {
    if (this._v < ZERO_BI) {
      // jsbn returns null on negative; matches callers that check `if (!out) throw`.
      return null;
    }
    return bigIntToBytes(this._v, length);
  }
}
