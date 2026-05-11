/*
 * TypeScript port of Tom Wu's jsbn BigInteger.
 *
 *   Original copyright (c) 2003-2009 Tom Wu — MIT-style license preserved in
 *   src.legacy/libs/jsbn.js. Buffer support added by rzcoder (2014).
 *
 * This port preserves the original digit representation, function names, and
 * algorithm structure 1-to-1 with the legacy implementation so that all
 * keygen RNG and primality-test paths produce byte-identical results.
 *
 * TODO(v2.1): replace with a native-BigInt backend behind the same surface.
 */

import type { CryptoBackend } from '../crypto/types.js';

// ─── Backend injection for RNG ──────────────────────────────────────────────
let _backend: CryptoBackend | undefined;

export function setBigIntegerBackend(backend: CryptoBackend): void {
  _backend = backend;
}

function getBackend(): CryptoBackend {
  if (!_backend) {
    throw new Error(
      'BigInteger crypto backend not initialized. Did you import from src/index.node.ts or src/index.browser.ts?',
    );
  }
  return _backend;
}

// ─── Digit-base constants ───────────────────────────────────────────────────
const DB = 28; // bits per digit
const DM = (1 << DB) - 1;
const DV = 1 << DB;
const BI_FP = 52;
const FV = 2 ** BI_FP;
const F1 = BI_FP - DB;
const F2 = 2 * DB - BI_FP;

// ─── Reducer interface (Classic / Montgomery / Barrett / NullExp) ───────────
interface Reducer {
  convert(x: BigInteger): BigInteger;
  revert(x: BigInteger): BigInteger;
  reduce(x: BigInteger): void;
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void;
  sqrTo(x: BigInteger, r: BigInteger): void;
}

// ─── Radix-conversion tables ────────────────────────────────────────────────
const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
const BI_RC: number[] = [];
{
  let rr = '0'.charCodeAt(0);
  for (let vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
  rr = 'a'.charCodeAt(0);
  for (let vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
  rr = 'A'.charCodeAt(0);
  for (let vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
}

function int2char(n: number): string {
  return BI_RM.charAt(n);
}

function intAt(s: string, i: number): number {
  const c = BI_RC[s.charCodeAt(i)];
  return c == null ? -1 : c;
}

function nbits(x: number): number {
  let r = 1;
  let t: number;
  if ((t = x >>> 16) !== 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) !== 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) !== 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) !== 0) {
    x = t;
    r += 2;
  }
  if ((t = x >> 1) !== 0) {
    x = t;
    r += 1;
  }
  return r;
}

function lbit(x: number): number {
  if (x === 0) return -1;
  let r = 0;
  if ((x & 0xffff) === 0) {
    x >>= 16;
    r += 16;
  }
  if ((x & 0xff) === 0) {
    x >>= 8;
    r += 8;
  }
  if ((x & 0xf) === 0) {
    x >>= 4;
    r += 4;
  }
  if ((x & 3) === 0) {
    x >>= 2;
    r += 2;
  }
  if ((x & 1) === 0) ++r;
  return r;
}

function cbit(x: number): number {
  let r = 0;
  while (x !== 0) {
    x &= x - 1;
    ++r;
  }
  return r;
}

// ─── BigInteger class ───────────────────────────────────────────────────────
export class BigInteger {
  [n: number]: number;
  t = 0;
  s = 0;

  // Mirror legacy `this.DB`/`this.DM`/etc. access patterns
  readonly DB = DB;
  readonly DM = DM;
  readonly DV = DV;
  readonly FV = FV;
  readonly F1 = F1;
  readonly F2 = F2;

  static ZERO: BigInteger;
  static ONE: BigInteger;
  static readonly int2char = int2char;

  constructor(
    a?: number | Uint8Array | number[] | string | null,
    b?: number | string,
    unsigned?: boolean,
  ) {
    if (a == null) return;
    if (typeof a === 'number') {
      this.fromNumber(a, b as number | undefined);
    } else if (a instanceof Uint8Array) {
      this.fromBuffer(a);
    } else if (typeof a === 'string') {
      this.fromString(a, b as number, unsigned);
    } else if (Array.isArray(a)) {
      this.fromByteArray(a, unsigned);
    }
  }

  // ── am3: multiply-accumulate (digit-base 2^28) ───────────────────────────
  am(i: number, x: number, w: BigInteger, j: number, c: number, n: number): number {
    const xl = x & 0x3fff;
    const xh = x >> 14;
    while (--n >= 0) {
      let l = this[i]! & 0x3fff;
      const h = this[i++]! >> 14;
      const m = xh * l + h * xl;
      l = xl * l + ((m & 0x3fff) << 14) + w[j]! + c;
      c = (l >> 28) + (m >> 14) + xh * h;
      w[j++] = l & 0xfffffff;
    }
    return c;
  }

  // ── protected: digit/byte initialisation ─────────────────────────────────
  copyTo(r: BigInteger): void {
    for (let i = this.t - 1; i >= 0; --i) r[i] = this[i]!;
    r.t = this.t;
    r.s = this.s;
  }

  fromInt(x: number): void {
    this.t = 1;
    this.s = x < 0 ? -1 : 0;
    if (x > 0) this[0] = x;
    else if (x < -1) this[0] = x + DV;
    else this.t = 0;
  }

  fromString(data: string | number[] | Uint8Array, radix?: number, unsigned?: boolean): void {
    let k: number;
    switch (radix) {
      case 2:
        k = 1;
        break;
      case 4:
        k = 2;
        break;
      case 8:
        k = 3;
        break;
      case 16:
        k = 4;
        break;
      case 32:
        k = 5;
        break;
      case 256:
        k = 8;
        break;
      default:
        this.fromRadix(data as string, radix);
        return;
    }
    this.t = 0;
    this.s = 0;
    const dataAny = data as { [n: number]: number; length: number; charAt?(i: number): string };
    let i = dataAny.length;
    let mi = false;
    let sh = 0;
    while (--i >= 0) {
      const x = k === 8 ? (dataAny[i] as number) & 0xff : intAt(data as string, i);
      if (x < 0) {
        if (dataAny.charAt && dataAny.charAt(i) === '-') mi = true;
        continue;
      }
      mi = false;
      if (sh === 0) this[this.t++] = x;
      else if (sh + k > this.DB) {
        this[this.t - 1] = (this[this.t - 1]! | ((x & ((1 << (this.DB - sh)) - 1)) << sh)) >>> 0;
        this[this.t++] = x >> (this.DB - sh);
      } else {
        this[this.t - 1] = (this[this.t - 1]! | (x << sh)) >>> 0;
      }
      sh += k;
      if (sh >= this.DB) sh -= this.DB;
    }
    if (!unsigned && k === 8 && ((dataAny[0] as number) & 0x80) !== 0) {
      this.s = -1;
      if (sh > 0)
        this[this.t - 1] = (this[this.t - 1]! | (((1 << (this.DB - sh)) - 1) << sh)) >>> 0;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
  }

  fromByteArray(a: number[], unsigned?: boolean): void {
    this.fromString(a, 256, unsigned);
  }

  fromBuffer(a: Uint8Array): void {
    this.fromString(a, 256, true);
  }

  clamp(): void {
    const c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] === c) --this.t;
  }

  // ── arithmetic on internal digits ────────────────────────────────────────
  dlShiftTo(n: number, r: BigInteger): void {
    let i: number;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i]!;
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
  }

  drShiftTo(n: number, r: BigInteger): void {
    for (let i = n; i < this.t; ++i) r[i - n] = this[i]!;
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
  }

  lShiftTo(n: number, r: BigInteger): void {
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << cbs) - 1;
    const ds = Math.floor(n / this.DB);
    let c = (this.s << bs) & this.DM;
    let i: number;
    for (i = this.t - 1; i >= 0; --i) {
      r[i + ds + 1] = (this[i]! >> cbs) | c;
      c = (this[i]! & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
  }

  rShiftTo(n: number, r: BigInteger): void {
    r.s = this.s;
    const ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
      r.t = 0;
      return;
    }
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << bs) - 1;
    r[0] = this[ds]! >> bs;
    for (let i = ds + 1; i < this.t; ++i) {
      r[i - ds - 1] = (r[i - ds - 1] ?? 0) | ((this[i]! & bm) << cbs);
      r[i - ds] = this[i]! >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] = (r[this.t - ds - 1] ?? 0) | ((this.s & bm) << cbs);
    r.t = this.t - ds;
    r.clamp();
  }

  subTo(a: BigInteger, r: BigInteger): void {
    let i = 0;
    let c = 0;
    const m = Math.min(a.t, this.t);
    while (i < m) {
      c += this[i]! - a[i]!;
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c -= a.s;
      while (i < this.t) {
        c += this[i]!;
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c -= a[i]!;
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c -= a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c;
    else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
  }

  multiplyTo(a: BigInteger, r: BigInteger): void {
    const x = this.abs();
    const y = a.abs();
    let i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i]!, r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s !== a.s) BigInteger.ZERO.subTo(r, r);
  }

  squareTo(r: BigInteger): void {
    const x = this.abs();
    let i = (r.t = 2 * x.t);
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
      const c = x.am(i, x[i]!, r, 2 * i, 0, 1);
      if (
        (r[i + x.t] = (r[i + x.t] ?? 0) + x.am(i + 1, 2 * x[i]!, r, 2 * i + 1, c, x.t - i - 1)) >=
        x.DV
      ) {
        r[i + x.t] = r[i + x.t]! - x.DV;
        r[i + x.t + 1] = 1;
      }
    }
    if (r.t > 0) r[r.t - 1] = (r[r.t - 1] ?? 0) + x.am(i, x[i]!, r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
  }

  divRemTo(m: BigInteger, q: BigInteger | null, r: BigInteger | null): void {
    const pm = m.abs();
    if (pm.t <= 0) return;
    const pt = this.abs();
    if (pt.t < pm.t) {
      if (q != null) q.fromInt(0);
      if (r != null) this.copyTo(r);
      return;
    }
    if (r == null) r = nbi();
    const y = nbi();
    const ts = this.s;
    const ms = m.s;
    const nsh = this.DB - nbits(pm[pm.t - 1]!);
    if (nsh > 0) {
      pm.lShiftTo(nsh, y);
      pt.lShiftTo(nsh, r);
    } else {
      pm.copyTo(y);
      pt.copyTo(r);
    }
    const ys = y.t;
    const y0 = y[ys - 1]!;
    if (y0 === 0) return;
    const yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2]! >> this.F2 : 0);
    const d1 = this.FV / yt;
    const d2 = (1 << this.F1) / yt;
    const e = 1 << this.F2;
    let i = r.t;
    let j = i - ys;
    const t = q == null ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
      r[r.t++] = 1;
      r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y);
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {
      let qd = r[--i]! === y0 ? this.DM : Math.floor(r[i]! * d1 + (r[i - 1]! + e) * d2);
      if ((r[i] = r[i]! + y.am(0, qd, r, j, 0, ys)) < qd) {
        y.dlShiftTo(j, t);
        r.subTo(t, r);
        while (r[i]! < --qd) r.subTo(t, r);
      }
    }
    if (q != null) {
      r.drShiftTo(ys, q);
      if (ts !== ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r);
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
  }

  invDigit(): number {
    if (this.t < 1) return 0;
    const x = this[0]!;
    if ((x & 1) === 0) return 0;
    let y = x & 3;
    y = (y * (2 - (x & 0xf) * y)) & 0xf;
    y = (y * (2 - (x & 0xff) * y)) & 0xff;
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;
    y = (y * (2 - ((x * y) % this.DV))) % this.DV;
    return y > 0 ? this.DV - y : -y;
  }

  isEven(): boolean {
    return ((this.t > 0 ? this[0]! & 1 : this.s) & 1) === 0;
  }

  exp(e: number, z: Reducer): BigInteger {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
    let r = nbi();
    let r2 = nbi();
    const g = z.convert(this);
    let i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
      z.sqrTo(r, r2);
      if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
      else {
        const tmp = r;
        r = r2;
        r2 = tmp;
      }
    }
    return z.revert(r);
  }

  // ── public arithmetic & comparisons ───────────────────────────────────────
  toString(b?: number): string {
    if (this.s < 0) return `-${this.negate().toString(b)}`;
    let k: number;
    if (b === 16) k = 4;
    else if (b === 8) k = 3;
    else if (b === 2) k = 1;
    else if (b === 32) k = 5;
    else if (b === 4) k = 2;
    else return this.toRadix(b);
    const km = (1 << k) - 1;
    let d: number;
    let m = false;
    let r = '';
    let i = this.t;
    let p = this.DB - ((i * this.DB) % k);
    if (i-- > 0) {
      if (p < this.DB && (d = this[i]! >> p) > 0) {
        m = true;
        r = int2char(d);
      }
      while (i >= 0) {
        if (p < k) {
          d = (this[i]! & ((1 << p) - 1)) << (k - p);
          d |= this[--i]! >> (p += this.DB - k);
        } else {
          d = (this[i]! >> (p -= k)) & km;
          if (p <= 0) {
            p += this.DB;
            --i;
          }
        }
        if (d > 0) m = true;
        if (m) r += int2char(d);
      }
    }
    return m ? r : '0';
  }

  negate(): BigInteger {
    const r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
  }

  abs(): BigInteger {
    return this.s < 0 ? this.negate() : this;
  }

  compareTo(a: BigInteger): number {
    let r = this.s - a.s;
    if (r !== 0) return r;
    let i = this.t;
    r = i - a.t;
    if (r !== 0) return this.s < 0 ? -r : r;
    while (--i >= 0) if ((r = this[i]! - a[i]!) !== 0) return r;
    return 0;
  }

  bitLength(): number {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + nbits(this[this.t - 1]! ^ (this.s & this.DM));
  }

  mod(a: BigInteger): BigInteger {
    const r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
  }

  modPowInt(e: number, m: BigInteger): BigInteger {
    const z: Reducer = e < 256 || m.isEven() ? new Classic(m) : new Montgomery(m);
    return this.exp(e, z);
  }

  // ── extended functions ────────────────────────────────────────────────────
  clone(): BigInteger {
    const r = nbi();
    this.copyTo(r);
    return r;
  }

  intValue(): number {
    if (this.s < 0) {
      if (this.t === 1) return this[0]! - this.DV;
      if (this.t === 0) return -1;
    } else if (this.t === 1) return this[0]!;
    else if (this.t === 0) return 0;
    return ((this[1]! & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0]!;
  }

  byteValue(): number {
    return this.t === 0 ? this.s : (this[0]! << 24) >> 24;
  }

  shortValue(): number {
    return this.t === 0 ? this.s : (this[0]! << 16) >> 16;
  }

  chunkSize(r: number): number {
    return Math.floor((Math.LN2 * this.DB) / Math.log(r));
  }

  signum(): number {
    if (this.s < 0) return -1;
    if (this.t <= 0 || (this.t === 1 && this[0]! <= 0)) return 0;
    return 1;
  }

  toRadix(b?: number): string {
    const base = b ?? 10;
    if (this.signum() === 0 || base < 2 || base > 36) return '0';
    const cs = this.chunkSize(base);
    const a = base ** cs;
    const d = nbv(a);
    const y = nbi();
    const z = nbi();
    let r = '';
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
      r = (a + z.intValue()).toString(base).slice(1) + r;
      y.divRemTo(d, y, z);
    }
    return z.intValue().toString(base) + r;
  }

  fromRadix(s: string, b?: number): void {
    this.fromInt(0);
    const base = b ?? 10;
    const cs = this.chunkSize(base);
    const d = base ** cs;
    let mi = false;
    let j = 0;
    let w = 0;
    for (let i = 0; i < s.length; ++i) {
      const x = intAt(s, i);
      if (x < 0) {
        if (s.charAt(i) === '-' && this.signum() === 0) mi = true;
        continue;
      }
      w = base * w + x;
      if (++j >= cs) {
        this.dMultiply(d);
        this.dAddOffset(w, 0);
        j = 0;
        w = 0;
      }
    }
    if (j > 0) {
      this.dMultiply(base ** j);
      this.dAddOffset(w, 0);
    }
    if (mi) BigInteger.ZERO.subTo(this, this);
  }

  fromNumber(a: number, b?: number): void {
    if (typeof b === 'number') {
      // (bits, certainty) → generate probable prime
      if (a < 2) this.fromInt(1);
      else {
        this.fromNumber(a);
        if (!this.testBit(a - 1)) {
          this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
        }
        if (this.isEven()) this.dAddOffset(1, 0);
        while (!this.isProbablePrime(b)) {
          this.dAddOffset(2, 0);
          if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
        }
      }
    } else {
      // (bits) → random a-bit integer
      const x = getBackend().randomBytes((a >> 3) + 1);
      const t = a & 7;
      const bytes = new Uint8Array(x);
      if (t > 0) bytes[0] = bytes[0]! & ((1 << t) - 1);
      else bytes[0] = 0;
      this.fromByteArray(Array.from(bytes));
    }
  }

  toByteArray(): number[] {
    let i = this.t;
    const r: number[] = [];
    r[0] = this.s;
    let p = this.DB - ((i * this.DB) % 8);
    let d: number;
    let k = 0;
    if (i-- > 0) {
      if (p < this.DB && (d = this[i]! >> p) !== (this.s & this.DM) >> p) {
        r[k++] = d | (this.s << (this.DB - p));
      }
      while (i >= 0) {
        if (p < 8) {
          d = (this[i]! & ((1 << p) - 1)) << (8 - p);
          d |= this[--i]! >> (p += this.DB - 8);
        } else {
          d = (this[i]! >> (p -= 8)) & 0xff;
          if (p <= 0) {
            p += this.DB;
            --i;
          }
        }
        if ((d & 0x80) !== 0) d |= -256;
        if (k === 0 && (this.s & 0x80) !== (d & 0x80)) ++k;
        if (k > 0 || d !== this.s) r[k++] = d;
      }
    }
    return r;
  }

  /**
   * Return a Uint8Array of this integer in big-endian unsigned form.
   *
   * - `trimOrSize === true`: drop a leading 0x00 sign byte if present.
   * - `trimOrSize` is a positive integer: left-pad or trim leading zeros to
   *   produce exactly `trimOrSize` bytes. Returns null if trimming would
   *   discard a non-zero byte (i.e., the value doesn't fit).
   * - Otherwise: return the raw two's-complement byte array with possible
   *   leading 0x00 sign byte.
   */
  toBuffer(trimOrSize?: boolean | number): Uint8Array | null {
    let res = Uint8Array.from(this.toByteArray().map((b) => b & 0xff));
    if (trimOrSize === true && res.length > 0 && res[0] === 0) {
      res = res.subarray(1);
    } else if (typeof trimOrSize === 'number') {
      if (res.length > trimOrSize) {
        const excess = res.length - trimOrSize;
        for (let i = 0; i < excess; i++) {
          if (res[i] !== 0) return null;
        }
        return res.subarray(excess).slice();
      }
      if (res.length < trimOrSize) {
        const padded = new Uint8Array(trimOrSize);
        padded.set(res, trimOrSize - res.length);
        return padded;
      }
    }
    return res.slice();
  }

  equals(a: BigInteger): boolean {
    return this.compareTo(a) === 0;
  }

  min(a: BigInteger): BigInteger {
    return this.compareTo(a) < 0 ? this : a;
  }

  max(a: BigInteger): BigInteger {
    return this.compareTo(a) > 0 ? this : a;
  }

  bitwiseTo(a: BigInteger, op: (x: number, y: number) => number, r: BigInteger): void {
    let i: number;
    let f: number;
    const m = Math.min(a.t, this.t);
    for (i = 0; i < m; ++i) r[i] = op(this[i]!, a[i]!);
    if (a.t < this.t) {
      f = a.s & this.DM;
      for (i = m; i < this.t; ++i) r[i] = op(this[i]!, f);
      r.t = this.t;
    } else {
      f = this.s & this.DM;
      for (i = m; i < a.t; ++i) r[i] = op(f, a[i]!);
      r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
  }

  and(a: BigInteger): BigInteger {
    const r = nbi();
    this.bitwiseTo(a, op_and, r);
    return r;
  }
  or(a: BigInteger): BigInteger {
    const r = nbi();
    this.bitwiseTo(a, op_or, r);
    return r;
  }
  xor(a: BigInteger): BigInteger {
    const r = nbi();
    this.bitwiseTo(a, op_xor, r);
    return r;
  }
  andNot(a: BigInteger): BigInteger {
    const r = nbi();
    this.bitwiseTo(a, op_andnot, r);
    return r;
  }
  not(): BigInteger {
    const r = nbi();
    for (let i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i]!;
    r.t = this.t;
    r.s = ~this.s;
    return r;
  }

  shiftLeft(n: number): BigInteger {
    const r = nbi();
    if (n < 0) this.rShiftTo(-n, r);
    else this.lShiftTo(n, r);
    return r;
  }

  shiftRight(n: number): BigInteger {
    const r = nbi();
    if (n < 0) this.lShiftTo(-n, r);
    else this.rShiftTo(n, r);
    return r;
  }

  getLowestSetBit(): number {
    for (let i = 0; i < this.t; ++i) if (this[i] !== 0) return i * this.DB + lbit(this[i]!);
    if (this.s < 0) return this.t * this.DB;
    return -1;
  }

  bitCount(): number {
    let r = 0;
    const x = this.s & this.DM;
    for (let i = 0; i < this.t; ++i) r += cbit(this[i]! ^ x);
    return r;
  }

  testBit(n: number): boolean {
    const j = Math.floor(n / this.DB);
    if (j >= this.t) return this.s !== 0;
    return (this[j]! & (1 << (n % this.DB))) !== 0;
  }

  changeBit(n: number, op: (x: number, y: number) => number): BigInteger {
    const r = BigInteger.ONE.shiftLeft(n);
    this.bitwiseTo(r, op, r);
    return r;
  }
  setBit(n: number): BigInteger {
    return this.changeBit(n, op_or);
  }
  clearBit(n: number): BigInteger {
    return this.changeBit(n, op_andnot);
  }
  flipBit(n: number): BigInteger {
    return this.changeBit(n, op_xor);
  }

  addTo(a: BigInteger, r: BigInteger): void {
    let i = 0;
    let c = 0;
    const m = Math.min(a.t, this.t);
    while (i < m) {
      c += this[i]! + a[i]!;
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c += a.s;
      while (i < this.t) {
        c += this[i]!;
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c += a[i]!;
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c > 0) r[i++] = c;
    else if (c < -1) r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
  }

  add(a: BigInteger): BigInteger {
    const r = nbi();
    this.addTo(a, r);
    return r;
  }
  subtract(a: BigInteger): BigInteger {
    const r = nbi();
    this.subTo(a, r);
    return r;
  }
  multiply(a: BigInteger): BigInteger {
    const r = nbi();
    this.multiplyTo(a, r);
    return r;
  }
  square(): BigInteger {
    const r = nbi();
    this.squareTo(r);
    return r;
  }
  divide(a: BigInteger): BigInteger {
    const r = nbi();
    this.divRemTo(a, r, null);
    return r;
  }
  remainder(a: BigInteger): BigInteger {
    const r = nbi();
    this.divRemTo(a, null, r);
    return r;
  }
  divideAndRemainder(a: BigInteger): [BigInteger, BigInteger] {
    const q = nbi();
    const r = nbi();
    this.divRemTo(a, q, r);
    return [q, r];
  }

  dMultiply(n: number): void {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
  }

  dAddOffset(n: number, w: number): void {
    if (n === 0) return;
    while (this.t <= w) this[this.t++] = 0;
    this[w] = this[w]! + n;
    while (this[w]! >= this.DV) {
      this[w] = this[w]! - this.DV;
      if (++w >= this.t) this[this.t++] = 0;
      this[w] = (this[w] ?? 0) + 1;
    }
  }

  pow(e: number): BigInteger {
    return this.exp(e, new NullExp());
  }

  multiplyLowerTo(a: BigInteger, n: number, r: BigInteger): void {
    let i = Math.min(this.t + a.t, n);
    r.s = 0;
    r.t = i;
    while (i > 0) r[--i] = 0;
    let j: number;
    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i]!, r, i, 0, this.t);
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i]!, r, i, 0, n - i);
    r.clamp();
  }

  multiplyUpperTo(a: BigInteger, n: number, r: BigInteger): void {
    --n;
    let i = (r.t = this.t + a.t - n);
    r.s = 0;
    while (--i >= 0) r[i] = 0;
    for (i = Math.max(n - this.t, 0); i < a.t; ++i) {
      r[this.t + i - n] = this.am(n - i, a[i]!, r, 0, 0, this.t + i - n);
    }
    r.clamp();
    r.drShiftTo(1, r);
  }

  modPow(e: BigInteger, m: BigInteger): BigInteger {
    let i = e.bitLength();
    let k: number;
    let r = nbv(1);
    let z: Reducer;
    if (i <= 0) return r;
    if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;
    if (i < 8) z = new Classic(m);
    else if (m.isEven()) z = new Barrett(m);
    else z = new Montgomery(m);

    const g: BigInteger[] = [];
    let n = 3;
    const k1 = k - 1;
    const km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
      const g2 = nbi();
      z.sqrTo(g[1]!, g2);
      while (n <= km) {
        g[n] = nbi();
        z.mulTo(g2, g[n - 2]!, g[n]!);
        n += 2;
      }
    }

    let j = e.t - 1;
    let w: number;
    let is1 = true;
    let r2 = nbi();
    let t: BigInteger;
    i = nbits(e[j]!) - 1;
    while (j >= 0) {
      if (i >= k1) w = (e[j]! >> (i - k1)) & km;
      else {
        w = (e[j]! & ((1 << (i + 1)) - 1)) << (k1 - i);
        if (j > 0) w |= e[j - 1]! >> (this.DB + i - k1);
      }
      n = k;
      while ((w & 1) === 0) {
        w >>= 1;
        --n;
      }
      if ((i -= n) < 0) {
        i += this.DB;
        --j;
      }
      if (is1) {
        g[w]!.copyTo(r);
        is1 = false;
      } else {
        while (n > 1) {
          z.sqrTo(r, r2);
          z.sqrTo(r2, r);
          n -= 2;
        }
        if (n > 0) z.sqrTo(r, r2);
        else {
          t = r;
          r = r2;
          r2 = t;
        }
        z.mulTo(r2, g[w]!, r);
      }
      while (j >= 0 && (e[j]! & (1 << i)) === 0) {
        z.sqrTo(r, r2);
        t = r;
        r = r2;
        r2 = t;
        if (--i < 0) {
          i = this.DB - 1;
          --j;
        }
      }
    }
    return z.revert(r);
  }

  gcd(a: BigInteger): BigInteger {
    let x = this.s < 0 ? this.negate() : this.clone();
    let y = a.s < 0 ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) {
      const t = x;
      x = y;
      y = t;
    }
    let i = x.getLowestSetBit();
    let g = y.getLowestSetBit();
    if (g < 0) return x;
    if (i < g) g = i;
    if (g > 0) {
      x.rShiftTo(g, x);
      y.rShiftTo(g, y);
    }
    while (x.signum() > 0) {
      if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
      if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
      if (x.compareTo(y) >= 0) {
        x.subTo(y, x);
        x.rShiftTo(1, x);
      } else {
        y.subTo(x, y);
        y.rShiftTo(1, y);
      }
    }
    if (g > 0) y.lShiftTo(g, y);
    return y;
  }

  modInt(n: number): number {
    if (n <= 0) return 0;
    const d = this.DV % n;
    let r = this.s < 0 ? n - 1 : 0;
    if (this.t > 0) {
      if (d === 0) r = this[0]! % n;
      else for (let i = this.t - 1; i >= 0; --i) r = (d * r + this[i]!) % n;
    }
    return r;
  }

  modInverse(m: BigInteger): BigInteger {
    const ac = m.isEven();
    if ((this.isEven() && ac) || m.signum() === 0) return BigInteger.ZERO;
    const u = m.clone();
    const v = this.clone();
    const a = nbv(1);
    const b = nbv(0);
    const c = nbv(0);
    const d = nbv(1);
    while (u.signum() !== 0) {
      while (u.isEven()) {
        u.rShiftTo(1, u);
        if (ac) {
          if (!a.isEven() || !b.isEven()) {
            a.addTo(this, a);
            b.subTo(m, b);
          }
          a.rShiftTo(1, a);
        } else if (!b.isEven()) b.subTo(m, b);
        b.rShiftTo(1, b);
      }
      while (v.isEven()) {
        v.rShiftTo(1, v);
        if (ac) {
          if (!c.isEven() || !d.isEven()) {
            c.addTo(this, c);
            d.subTo(m, d);
          }
          c.rShiftTo(1, c);
        } else if (!d.isEven()) d.subTo(m, d);
        d.rShiftTo(1, d);
      }
      if (u.compareTo(v) >= 0) {
        u.subTo(v, u);
        if (ac) a.subTo(c, a);
        b.subTo(d, b);
      } else {
        v.subTo(u, v);
        if (ac) c.subTo(a, c);
        d.subTo(b, d);
      }
    }
    if (v.compareTo(BigInteger.ONE) !== 0) return BigInteger.ZERO;
    if (d.compareTo(m) >= 0) return d.subtract(m);
    if (d.signum() < 0) d.addTo(m, d);
    return d;
  }

  isProbablePrime(t: number): boolean {
    let i: number;
    const x = this.abs();
    if (x.t === 1 && x[0]! <= lowprimes[lowprimes.length - 1]!) {
      for (i = 0; i < lowprimes.length; ++i) if (x[0] === lowprimes[i]) return true;
      return false;
    }
    if (x.isEven()) return false;
    i = 1;
    while (i < lowprimes.length) {
      let m = lowprimes[i]!;
      let j = i + 1;
      while (j < lowprimes.length && m < lplim) m *= lowprimes[j++]!;
      m = x.modInt(m);
      while (i < j) if (m % lowprimes[i++]! === 0) return false;
    }
    return x.millerRabin(t);
  }

  millerRabin(t: number): boolean {
    const n1 = this.subtract(BigInteger.ONE);
    const k = n1.getLowestSetBit();
    if (k <= 0) return false;
    const r = n1.shiftRight(k);
    t = (t + 1) >> 1;
    if (t > lowprimes.length) t = lowprimes.length;
    const a = nbi();
    for (let i = 0; i < t; ++i) {
      a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]!);
      let y = a.modPow(r, this);
      if (y.compareTo(BigInteger.ONE) !== 0 && y.compareTo(n1) !== 0) {
        let j = 1;
        while (j++ < k && y.compareTo(n1) !== 0) {
          y = y.modPowInt(2, this);
          if (y.compareTo(BigInteger.ONE) === 0) return false;
        }
        if (y.compareTo(n1) !== 0) return false;
      }
    }
    return true;
  }
}

// ─── helpers and reducers ───────────────────────────────────────────────────
function nbi(): BigInteger {
  return new BigInteger(null);
}

function nbv(i: number): BigInteger {
  const r = nbi();
  r.fromInt(i);
  return r;
}

function op_and(x: number, y: number): number {
  return x & y;
}
function op_or(x: number, y: number): number {
  return x | y;
}
function op_xor(x: number, y: number): number {
  return x ^ y;
}
function op_andnot(x: number, y: number): number {
  return x & ~y;
}

class Classic implements Reducer {
  constructor(private readonly m: BigInteger) {}
  convert(x: BigInteger): BigInteger {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    return x;
  }
  revert(x: BigInteger): BigInteger {
    return x;
  }
  reduce(x: BigInteger): void {
    x.divRemTo(this.m, null, x);
  }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
    this.reduce(r);
  }
  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
    this.reduce(r);
  }
}

class Montgomery implements Reducer {
  m: BigInteger;
  mp: number;
  mpl: number;
  mph: number;
  um: number;
  mt2: number;
  constructor(m: BigInteger) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
  }
  convert(x: BigInteger): BigInteger {
    const r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
  }
  revert(x: BigInteger): BigInteger {
    const r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
  reduce(x: BigInteger): void {
    while (x.t <= this.mt2) x[x.t++] = 0;
    for (let i = 0; i < this.m.t; ++i) {
      let j = x[i]! & 0x7fff;
      const u0 =
        (j * this.mpl + (((j * this.mph + (x[i]! >> 15) * this.mpl) & this.um) << 15)) & x.DM;
      j = i + this.m.t;
      x[j] = (x[j] ?? 0) + this.m.am(0, u0, x, i, 0, this.m.t);
      while (x[j]! >= x.DV) {
        x[j] = x[j]! - x.DV;
        x[++j] = (x[j] ?? 0) + 1;
      }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
    this.reduce(r);
  }
  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
    this.reduce(r);
  }
}

class Barrett implements Reducer {
  r2: BigInteger;
  q3: BigInteger;
  mu: BigInteger;
  m: BigInteger;
  constructor(m: BigInteger) {
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
    this.m = m;
  }
  convert(x: BigInteger): BigInteger {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
    if (x.compareTo(this.m) < 0) return x;
    const r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
  revert(x: BigInteger): BigInteger {
    return x;
  }
  reduce(x: BigInteger): void {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) {
      x.t = this.m.t + 1;
      x.clamp();
    }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
    this.reduce(r);
  }
  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
    this.reduce(r);
  }
}

class NullExp implements Reducer {
  convert(x: BigInteger): BigInteger {
    return x;
  }
  revert(x: BigInteger): BigInteger {
    return x;
  }
  reduce(_x: BigInteger): void {}
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
  }
  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
  }
}

// ─── lowprimes table for primality testing ──────────────────────────────────
// biome-ignore format: keep the lowprimes table on one line for clarity vs the legacy file
const lowprimes: number[] = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
const lplim = (1 << 26) / lowprimes[lowprimes.length - 1]!;

// ─── constants — defined after the class because they call nbv ──────────────
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
