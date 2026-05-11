import { concat, writeUInt32BE } from '../crypto/bytes.js';
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

  encUnPad(buffer: Uint8Array): Uint8Array | null {
    const hash = this.hash();
    const mgf = this.mgf();
    const label = this.options.encryptionSchemeOptions.label ?? new Uint8Array(0);
    const hLen = DIGEST_LENGTH[hash];

    if (buffer.length < 2 * hLen + 2) {
      throw new Error(
        'Error decoding message, the supplied message is not long enough to be a valid OAEP encoded message',
      );
    }

    // Copy because we XOR-mutate in place.
    const work = buffer.slice();
    const seed = work.subarray(1, hLen + 1);
    const DB = work.subarray(1 + hLen);

    const seedMask = mgf(DB, hLen, hash);
    for (let i = 0; i < seed.length; i++) seed[i] = (seed[i] as number) ^ (seedMask[i] as number);

    const dbMask = mgf(seed, DB.length, hash);
    for (let i = 0; i < DB.length; i++) DB[i] = (DB[i] as number) ^ (dbMask[i] as number);

    const lHash = this.options.backend.digest(hash, label);
    const lHashEM = DB.subarray(0, hLen);
    for (let i = 0; i < hLen; i++) {
      if (lHashEM[i] !== lHash[i]) {
        throw new Error(
          'Error decoding message, the lHash calculated from the label provided and the lHash in the encrypted data do not match.',
        );
      }
    }

    let i = hLen;
    while (i < DB.length && DB[i] === 0) i++;
    if (DB[i] !== 1) {
      throw new Error('Error decoding message, there is no padding message separator byte');
    }
    return DB.subarray(i + 1).slice();
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
