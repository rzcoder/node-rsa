import { constantTimeEqual } from '../crypto/bytes.js';
import { DIGEST_LENGTH } from '../crypto/digest-length.js';
import type { HashingAlgorithm } from '../crypto/types.js';
import type { RSAKey } from '../rsa/key.js';
import { mgf1 } from './oaep.js';
import type { MaskGenerationFunction, SchemeOptions, SignatureScheme } from './types.js';

const DEFAULT_HASH: HashingAlgorithm = 'sha1';
const DEFAULT_SALT_LENGTH = 20;

class PssScheme implements SignatureScheme {
  constructor(
    private readonly key: RSAKey,
    private readonly options: SchemeOptions,
  ) {}

  private hash(): HashingAlgorithm {
    return this.options.signingSchemeOptions.hash ?? DEFAULT_HASH;
  }

  private mgf(): MaskGenerationFunction {
    const userMgf = this.options.signingSchemeOptions.mgf;
    if (userMgf) return userMgf;
    const backend = this.options.backend;
    return (seed, maskLength, hash) => mgf1(seed, maskLength, hash, backend);
  }

  private saltLen(): number {
    return this.options.signingSchemeOptions.saltLength ?? DEFAULT_SALT_LENGTH;
  }

  sign(buffer: Uint8Array): Uint8Array {
    const hash = this.hash();
    const mHash = this.options.backend.digest(hash, buffer);
    const encoded = this.emsaPssEncode(mHash, this.key.keySize - 1);
    const signed = this.key.$doPrivate(new this.key.BI(encoded));
    const out = signed.toBuffer(this.key.encryptedDataLength);
    if (!out) throw new Error('PSS sign: output overflow');
    return out;
  }

  verify(buffer: Uint8Array, signature: Uint8Array): boolean {
    const hash = this.hash();
    const emLen = Math.ceil((this.key.keySize - 1) / 8);
    // RFC 8017 §8.1.2 step 2.b: signature-representative out of range
    // (or any other RSA-primitive failure) yields "invalid signature",
    // not a thrown error.
    let m: Uint8Array | null;
    try {
      m = this.key.$doPublic(new this.key.BI(signature)).toBuffer(emLen);
    } catch {
      return false;
    }
    if (!m) return false;
    const mHash = this.options.backend.digest(hash, buffer);
    return this.emsaPssVerify(mHash, m, this.key.keySize - 1);
  }

  /** EMSA-PSS-ENCODE — RFC 3447 §9.1.1 */
  private emsaPssEncode(mHash: Uint8Array, emBits: number): Uint8Array {
    const hash = this.hash();
    const mgf = this.mgf();
    const sLen = this.saltLen();
    const hLen = DIGEST_LENGTH[hash];
    const emLen = Math.ceil(emBits / 8);

    if (emLen < hLen + sLen + 2) {
      throw new Error(
        `Output length passed to emBits(${emBits}) is too small for the options specified(${hash}, ${sLen}). To fix this issue increase the value of emBits. (minimum size: ${8 * hLen + 8 * sLen + 9})`,
      );
    }

    const salt = this.options.backend.randomBytes(sLen);

    const mPrime = new Uint8Array(8 + hLen + sLen);
    mPrime.set(mHash, 8);
    mPrime.set(salt, 8 + mHash.length);

    const H = this.options.backend.digest(hash, mPrime);

    const DB = new Uint8Array(emLen - hLen - 1);
    DB[emLen - hLen - 1 - sLen - 1] = 0x01;
    DB.set(salt, emLen - hLen - 1 - sLen);

    const dbMask = mgf(H, DB.length, hash);
    for (let i = 0; i < DB.length; i++) DB[i] = (DB[i] as number) ^ (dbMask[i] as number);

    const bits = 8 * emLen - emBits;
    const mask = 0xff ^ (((0xff >> (8 - bits)) << (8 - bits)) & 0xff);
    DB[0] = (DB[0] as number) & mask;

    const EM = new Uint8Array(emLen);
    EM.set(DB, 0);
    EM.set(H, DB.length);
    EM[EM.length - 1] = 0xbc;
    return EM;
  }

  /**
   * EMSA-PSS-VERIFY per RFC 8017 §9.1.2. All input-dependent checks
   * (trailer byte, leftmost-bits zero, PS-zeros, separator 0x01, H == H')
   * accumulate into a single `bad` flag with one `return bad === 0` at the
   * end. PSS verify operates on public data, so this is hygiene rather
   * than a tight side-channel requirement — but RFC step 11 mandates
   * evaluating all checks before deciding.
   */
  private emsaPssVerify(mHash: Uint8Array, EM: Uint8Array, emBits: number): boolean {
    const hash = this.hash();
    const mgf = this.mgf();
    const sLen = this.saltLen();
    const hLen = DIGEST_LENGTH[hash];
    const emLen = Math.ceil(emBits / 8);

    // Geometry preconditions: configured by the caller, not derived from
    // attacker input — early return is safe.
    if (emLen < hLen + sLen + 2) return false;
    if (EM.length !== emLen) return false;

    let bad = 0;

    // RFC step 4: trailer byte must be 0xbc.
    bad |= (EM[EM.length - 1] as number) ^ 0xbc;

    const DB = EM.slice(0, emLen - hLen - 1);
    const bits = 8 * emLen - emBits;

    // RFC step 6: leftmost (8*emLen - emBits) bits of maskedDB[0] must be 0.
    let topMask = 0;
    for (let i = 0; i < bits; i++) topMask |= 1 << (7 - i);
    bad |= (DB[0] as number) & topMask;

    const H = EM.subarray(emLen - hLen - 1, emLen - 1);
    const dbMask = mgf(H, DB.length, hash);
    for (let i = 0; i < DB.length; i++) DB[i] = (DB[i] as number) ^ (dbMask[i] as number);

    // RFC step 9: zero the masked top bits of DB[0] after unmasking.
    const adjustedMask = 0xff ^ (((0xff >> (8 - bits)) << (8 - bits)) & 0xff);
    DB[0] = (DB[0] as number) & adjustedMask;

    // RFC step 10: DB = PS (all zeros) || 0x01 || salt, where
    // |PS| = emLen - hLen - sLen - 2, so 0x01 sits at index |PS| of DB.
    const sepIdx = emLen - hLen - sLen - 2;
    for (let i = 0; i < DB.length; i++) {
      const b = DB[i] as number;
      if (i < sepIdx) {
        bad |= b; // must be 0x00
      } else if (i === sepIdx) {
        bad |= b ^ 0x01; // must be 0x01
      }
      // i > sepIdx: salt, no check (validated via H' below)
    }

    // RFC steps 12-13: recompute H' = Hash(0x00⁸ || mHash || salt) and compare.
    const salt = DB.subarray(DB.length - sLen);
    const mPrime = new Uint8Array(8 + hLen + sLen);
    mPrime.set(mHash, 8);
    mPrime.set(salt, 8 + mHash.length);
    const HPrime = this.options.backend.digest(hash, mPrime);

    bad |= constantTimeEqual(H, HPrime) ? 0 : 1;

    return bad === 0;
  }
}

export const pssScheme = {
  isEncryption: false as const,
  isSignature: true as const,
  makeScheme(key: RSAKey, options: SchemeOptions): SignatureScheme {
    return new PssScheme(key, options);
  },
};
