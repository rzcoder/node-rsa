import { BigInteger } from '../bigint/big-integer.js';
import { concat, constantTimeEqual, fromHex } from '../crypto/bytes.js';
import type { HashAlg } from '../crypto/types.js';
import type { RSAKey } from '../rsa/key.js';
import type { EncryptionScheme, SchemeOptions, SignatureScheme } from './types.js';

export const RSA_NO_PADDING = 3;

const SIGN_INFO_HEAD: Partial<Record<HashAlg, Uint8Array>> = {
  md5: fromHex('3020300c06082a864886f70d020505000410'),
  sha1: fromHex('3021300906052b0e03021a05000414'),
  sha224: fromHex('302d300d06096086480165030402040500041c'),
  sha256: fromHex('3031300d060960864801650304020105000420'),
  sha384: fromHex('3041300d060960864801650304020205000430'),
  sha512: fromHex('3051300d060960864801650304020305000440'),
  ripemd160: fromHex('3021300906052b2403020105000414'),
};

const DEFAULT_HASH: HashAlg = 'sha256';

class Pkcs1Scheme implements EncryptionScheme, SignatureScheme {
  constructor(
    private readonly key: RSAKey,
    private readonly options: SchemeOptions,
  ) {}

  private noPadding(): boolean {
    return this.options.encryptionSchemeOptions.padding === RSA_NO_PADDING;
  }

  maxMessageLength(): number {
    if (this.noPadding()) return this.key.encryptedDataLength;
    return this.key.encryptedDataLength - 11;
  }

  encPad(buffer: Uint8Array, opts?: { type?: number }): Uint8Array {
    const { type } = opts ?? {};

    if (buffer.length > this.maxMessageLength()) {
      throw new Error(
        `Message too long for RSA (n=${this.key.encryptedDataLength}, l=${buffer.length})`,
      );
    }

    if (this.noPadding()) {
      const filled = new Uint8Array(this.maxMessageLength() - buffer.length);
      return concat(filled, buffer);
    }

    if (type === 1) {
      // Type 1: zeros padding for private-key encrypt (signing)
      const filled = new Uint8Array(this.key.encryptedDataLength - buffer.length - 1);
      filled.fill(0xff, 0, filled.length - 1);
      filled[0] = 1;
      filled[filled.length - 1] = 0;
      return concat(filled, buffer);
    }

    // Type 2: random non-zero padding for public-key encrypt
    const filled = new Uint8Array(this.key.encryptedDataLength - buffer.length);
    filled[0] = 0;
    filled[1] = 2;
    const rand = this.options.backend.randomBytes(filled.length - 3);
    for (let i = 0; i < rand.length; i++) {
      let r = rand[i] as number;
      while (r === 0) {
        r = this.options.backend.randomBytes(1)[0] as number;
      }
      filled[i + 2] = r;
    }
    filled[filled.length - 1] = 0;
    return concat(filled, buffer);
  }

  /**
   * Constant-time PKCS#1 v1.5 decode per RFC 8017 §7.2.2: header byte,
   * padding-type byte, PS validity, and minimum PS length all accumulate
   * into a single bitwise `bad` flag with no early return; one `return
   * null` for all failure modes.
   *
   * Full Bleichenbacher mitigation (RFC §7.2.2 NOTE — return synthetic
   * plaintext instead of null) would require session-key plumbing and an
   * API change (callers expect a throw). This closes only the internal
   * differential timing oracle; the valid/invalid binary oracle inherent
   * to PKCS#1 v1.5 remains — use OAEP for untrusted ciphertexts.
   */
  encUnPad(buffer: Uint8Array, opts?: { type?: number }): Uint8Array | null {
    const { type } = opts ?? {};

    if (this.noPadding()) {
      // RSA_NO_PADDING: strip leading zero pad — matches legacy
      // lastIndexOf('\0') semantics. Not security-sensitive (no padding).
      let lastZero = -1;
      for (let j = buffer.length - 1; j >= 0; j--) {
        if (buffer[j] === 0) {
          lastZero = j;
          break;
        }
      }
      return buffer.subarray(lastZero + 1).slice();
    }

    // Length precondition — public-known (= key chunk size); safe to branch.
    if (buffer.length < 11) return null;

    const expectedType = type === 1 ? 1 : 2;

    // From here on: all checks accumulate into `bad`; no branch on data.
    let bad = buffer[0] as number; // must be 0x00
    bad |= (buffer[1] as number) ^ expectedType; // must match type

    let found = 0;
    let sepPos = 0;
    for (let i = 2; i < buffer.length; i++) {
      const b = buffer[i] as number;
      const isZero = (((b | -b) >>> 31) ^ 1) & 1; // 1 if b == 0
      const notFoundYet = (1 - found) & 1;
      if (expectedType === 1) {
        // PS bytes must be 0xff. Mark `bad` if a byte before separator is
        // neither 0xff (continue PS) nor 0x00 (separator).
        const isNotFF = ((b ^ 0xff) === 0 ? 0 : 1) & 1;
        bad |= notFoundYet & (1 - isZero) & isNotFF;
      }
      // For type 2: PS bytes are random non-zero; first 0x00 is the separator.
      // No per-byte check needed beyond the separator-position validation below.

      // Record sepPos = i the first time we see 0x00.
      const recordMask = -(notFoundYet & isZero);
      sepPos = (sepPos & ~recordMask) | (i & recordMask);
      found |= isZero;
    }
    bad |= 1 - found;
    // PS must be ≥ 8 bytes (RFC 8017 §7.2.1) → sepPos ≥ 10 (indices 2..9 inclusive are PS).
    bad |= ((sepPos - 10) >>> 31) & 1;

    if (bad) return null;
    return buffer.subarray(sepPos + 1).slice();
  }

  sign(buffer: Uint8Array): Uint8Array {
    const hashAlgorithm = this.options.signingSchemeOptions.hash ?? DEFAULT_HASH;
    const hash = this.options.backend.digest(hashAlgorithm, buffer);
    const padded = this.pkcs1pad(hash, hashAlgorithm);
    const signed = this.key.$doPrivate(new BigInteger(padded));
    const out = signed.toBuffer(this.key.encryptedDataLength);
    if (!out) throw new Error('PKCS#1 sign: output overflow');
    return out;
  }

  verify(buffer: Uint8Array, signature: Uint8Array): boolean {
    if (this.noPadding()) return false; // RSA_NO_PADDING has no verify data
    const hashAlgorithm = this.options.signingSchemeOptions.hash ?? DEFAULT_HASH;
    const hash = this.options.backend.digest(hashAlgorithm, buffer);
    const padded = this.pkcs1pad(hash, hashAlgorithm);
    // RFC 8017 §8.2.2 step 2.b: an out-of-range signature representative
    // (or any other RSA-primitive failure) must yield "invalid signature",
    // not a thrown error.
    let m: Uint8Array | null;
    try {
      m = this.key.$doPublic(new BigInteger(signature)).toBuffer();
    } catch {
      return false;
    }
    if (!m) return false;
    return constantTimeEqual(m, padded);
  }

  pkcs1pad(hashBuf: Uint8Array, hashAlgorithm: HashAlg): Uint8Array {
    const digest = SIGN_INFO_HEAD[hashAlgorithm];
    if (!digest) throw new Error(`Unsupported hash algorithm: ${hashAlgorithm}`);
    const data = concat(digest, hashBuf);
    if (data.length + 10 > this.key.encryptedDataLength) {
      throw new Error(`Key is too short for signing algorithm (${hashAlgorithm})`);
    }
    const filled = new Uint8Array(this.key.encryptedDataLength - data.length - 1);
    filled.fill(0xff, 0, filled.length - 1);
    filled[0] = 1;
    filled[filled.length - 1] = 0;
    return concat(filled, data);
  }
}

export const pkcs1Scheme = {
  isEncryption: true as const,
  isSignature: true as const,
  makeScheme(key: RSAKey, options: SchemeOptions): EncryptionScheme & SignatureScheme {
    return new Pkcs1Scheme(key, options);
  },
};
