import { concat, constantTimeEqual, writeUInt32BE } from '../crypto/bytes.js';
import { DIGEST_LENGTH } from '../crypto/digest-length.js';
import type { CryptoBackend, HashAlg } from '../crypto/types.js';
import type { RSAKey } from '../rsa/key.js';
import type { EncryptionScheme, MaskGenerationFunction, SchemeOptions } from './types.js';

const DEFAULT_HASH: HashAlg = 'sha1';

/** Default MGF1 implementation bound to a backend. */
export function mgf1(
  seed: Uint8Array,
  maskLength: number,
  hash: HashAlg,
  backend: CryptoBackend,
): Uint8Array {
  const hLen = DIGEST_LENGTH[hash];
  const count = Math.ceil(maskLength / hLen);
  const out = new Uint8Array(hLen * count);
  const counter = new Uint8Array(4);
  for (let i = 0; i < count; i++) {
    writeUInt32BE(i, counter, 0);
    const h = backend.digest(hash, concat(seed, counter));
    out.set(h, i * hLen);
  }
  return out.subarray(0, maskLength);
}

class OaepScheme implements EncryptionScheme {
  constructor(
    private readonly key: RSAKey,
    private readonly options: SchemeOptions,
  ) {}

  private hash(): HashAlg {
    return this.options.encryptionSchemeOptions.hash ?? DEFAULT_HASH;
  }

  private mgf(): MaskGenerationFunction {
    const userMgf = this.options.encryptionSchemeOptions.mgf;
    if (userMgf) return userMgf;
    const backend = this.options.backend;
    return (seed, maskLength, hash) => mgf1(seed, maskLength, hash, backend);
  }

  maxMessageLength(): number {
    return this.key.encryptedDataLength - 2 * DIGEST_LENGTH[this.hash()] - 2;
  }

  encPad(buffer: Uint8Array): Uint8Array {
    const hash = this.hash();
    const mgf = this.mgf();
    const label = this.options.encryptionSchemeOptions.label ?? new Uint8Array(0);
    const emLen = this.key.encryptedDataLength;
    const hLen = DIGEST_LENGTH[hash];

    if (buffer.length > emLen - 2 * hLen - 2) {
      throw new Error(
        `Message is too long to encode into an encoded message with a length of ${emLen} bytes, increaseemLen to fix this error (minimum size: ${emLen - 2 * hLen - 2})`,
      );
    }

    const lHash = this.options.backend.digest(hash, label);
    const PS = new Uint8Array(emLen - buffer.length - 2 * hLen - 1);
    PS[PS.length - 1] = 1;
    const DB = concat(lHash, PS, buffer);
    const seed = this.options.backend.randomBytes(hLen);

    const dbMask = mgf(seed, DB.length, hash);
    for (let i = 0; i < DB.length; i++) DB[i] = (DB[i] as number) ^ (dbMask[i] as number);

    const seedMask = mgf(DB, hLen, hash);
    for (let i = 0; i < seed.length; i++) seed[i] = (seed[i] as number) ^ (seedMask[i] as number);

    const em = new Uint8Array(1 + seed.length + DB.length);
    em[0] = 0;
    em.set(seed, 1);
    em.set(DB, 1 + seed.length);
    return em;
  }

  /**
   * Audit fix C4 (Manger oracle): RFC 8017 §7.1.2 requires that ALL
   * decryption failure modes be indistinguishable in timing. The legacy
   * implementation had:
   *   - early throw on lHash byte mismatch (leaks position byte-by-byte),
   *   - linear scan for 0x01 separator (leaks separator position),
   *   - distinct throw messages for each failure mode (leak via wall-clock),
   *   - no check that EM[0] == 0x00 (Y, per RFC step 3).
   *
   * Fixed: single boolean `bad` aggregated bitwise without branches; one
   * common `return null` for all failures. Engine.ts wraps null in a
   * single generic "Decryption failed (invalid padding)" throw.
   *
   * Also folds in audit M8: validate `msg.length <= maxMessageLength()`
   * before returning, per RFC 8017 §7.1.1 step 1.b.
   */
  encUnPad(buffer: Uint8Array): Uint8Array | null {
    const hash = this.hash();
    const mgf = this.mgf();
    const label = this.options.encryptionSchemeOptions.label ?? new Uint8Array(0);
    const hLen = DIGEST_LENGTH[hash];

    // Length precondition — public-known info (key size), safe to branch on.
    if (buffer.length < 2 * hLen + 2) return null;

    // From here on, all checks are constant-time and accumulate into `bad`.
    const work = buffer.slice();

    // RFC step 3 (post 3.e): Y must equal 0x00. Was missing entirely.
    let bad = work[0] === 0x00 ? 0 : 1;

    const seed = work.subarray(1, hLen + 1);
    const DB = work.subarray(1 + hLen);

    const seedMask = mgf(DB, hLen, hash);
    for (let i = 0; i < seed.length; i++) seed[i] = (seed[i] as number) ^ (seedMask[i] as number);

    const dbMask = mgf(seed, DB.length, hash);
    for (let i = 0; i < DB.length; i++) DB[i] = (DB[i] as number) ^ (dbMask[i] as number);

    // lHash compare in constant time.
    const lHash = this.options.backend.digest(hash, label);
    const lHashEM = DB.subarray(0, hLen);
    bad |= constantTimeEqual(lHashEM, lHash) ? 0 : 1;

    // Constant-iteration separator scan. Walk the entire DB from hLen onward,
    // recording the position of the first 0x01 byte. Any non-{0x00,0x01} byte
    // before the separator, or no separator at all, marks `bad`.
    let found = 0;
    let msgStart = 0;
    for (let j = hLen; j < DB.length; j++) {
      const b = DB[j] as number;
      // isOne = 1 if b==0x01 else 0 (constant-time, no branch).
      const isOne = (((b ^ 0x01) - 1) >>> 31) & 1;
      // isZero = 1 if b==0x00 else 0.
      const isZero = (((b | -b) >>> 31) ^ 1) & 1;
      const notFoundYet = (1 - found) & 1;
      // Record msgStart = j+1 (first byte after the separator) the first
      // time we see 0x01. Use arithmetic mask, not branch.
      const recordMask = -(notFoundYet & isOne);
      msgStart = (msgStart & ~recordMask) | ((j + 1) & recordMask);
      // Before separator, any byte ≠ 0x00 and ≠ 0x01 marks bad.
      bad |= notFoundYet & (1 - isOne) & (1 - isZero);
      found |= isOne;
    }
    bad |= 1 - found;

    if (bad) return null;

    const msg = DB.subarray(msgStart).slice();
    // Audit M8: RFC 8017 §7.1.1 step 1.b bound.
    if (msg.length > this.maxMessageLength()) return null;
    return msg;
  }
}

export const oaepScheme = {
  isEncryption: true as const,
  isSignature: false as const,
  digestLength: DIGEST_LENGTH,
  mgf1,
  makeScheme(key: RSAKey, options: SchemeOptions): EncryptionScheme {
    return new OaepScheme(key, options);
  },
};
