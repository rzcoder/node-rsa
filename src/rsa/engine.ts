import { concat } from '../crypto/bytes.js';
import { pkcs1Scheme as pkcs1Provider } from '../schemes/pkcs1.js';
import type { EncryptionSchemeImpl, SchemeOptions, SignatureScheme } from '../schemes/types.js';
import type { RSAKey } from './key.js';

/**
 * Engine handles full encrypt/decrypt for arbitrarily-long buffers by
 * chunking, applying the encryption scheme's padding, and invoking the
 * RSA primitive (key.$doPublic / $doPrivate).
 *
 * Type-1 path (encryptPrivate, decryptPublic) is *always* PKCS#1 v1.5,
 * even when the configured encryptionScheme is OAEP.
 */
export interface Engine {
  /**
   * Pad and encrypt `buffer`, splitting into key-size chunks as needed.
   * `usePrivate=true` selects the "sign-with-PKCS#1-type-1" path (always
   * PKCS#1 v1.5, regardless of the configured encryption scheme).
   */
  encrypt(buffer: Uint8Array, usePrivate?: boolean): Uint8Array;
  /**
   * Decrypt and unpad. `usePublic=true` mirrors `encrypt`'s type-1 path —
   * verifies a public-decryptable PKCS#1 v1.5 message. Throws on length
   * mismatch or invalid padding.
   */
  decrypt(buffer: Uint8Array, usePublic?: boolean): Uint8Array;
}

/** Pure-JS RSA encrypt/decrypt — runs the primitive via `RSAKey.$doPublic`/`$doPrivate`. */
export class JsEngine implements Engine {
  /** Always a PKCS#1 v1.5 scheme — used for usePrivate / usePublic paths. */
  private readonly pkcs1: EncryptionSchemeImpl;

  constructor(private readonly key: RSAKey) {
    this.pkcs1 = pkcs1Provider.makeScheme(key, key.options) as EncryptionSchemeImpl & SignatureScheme;
  }

  encrypt(buffer: Uint8Array, usePrivate = false): Uint8Array {
    const max = this.key.maxMessageLength;
    if (max <= 0) throw new Error('Engine: key not initialised');
    const buffersCount = Math.ceil(buffer.length / max) || 1;
    const dividedSize = Math.ceil(buffer.length / buffersCount) || 1;

    const chunks: Uint8Array[] = [];
    if (buffersCount === 1) {
      chunks.push(buffer);
    } else {
      for (let i = 0; i < buffersCount; i++) {
        chunks.push(buffer.subarray(i * dividedSize, (i + 1) * dividedSize));
      }
    }

    const out: Uint8Array[] = [];
    for (const chunk of chunks) {
      const padded = usePrivate
        ? this.pkcs1.encPad(chunk, { type: 1 })
        : this.key.encryptionScheme.encPad(chunk);
      const bi = new this.key.BI(padded);
      const result = usePrivate ? this.key.$doPrivate(bi) : this.key.$doPublic(bi);
      const bytes = result.toBuffer(this.key.encryptedDataLength);
      if (!bytes) throw new Error('Engine: RSA primitive returned oversize integer');
      out.push(bytes);
    }
    return concat(...out);
  }

  decrypt(buffer: Uint8Array, usePublic = false): Uint8Array {
    const chunkLen = this.key.encryptedDataLength;
    if (buffer.length % chunkLen !== 0) {
      throw new Error('Incorrect data or key');
    }
    const count = buffer.length / chunkLen;
    const parts: Uint8Array[] = [];
    let bad = 0;

    for (let i = 0; i < count; i++) {
      const off = i * chunkLen;
      const ct = buffer.subarray(off, off + chunkLen);
      const bi = new this.key.BI(ct);
      const result = usePublic ? this.key.$doPublic(bi) : this.key.$doPrivate(bi);
      const padded = result.toBuffer(chunkLen);
      if (!padded) throw new Error('Engine: RSA primitive returned oversize integer');
      const unpadded = usePublic
        ? this.pkcs1.encUnPad(padded, { type: 1 })
        : this.key.encryptionScheme.encUnPad(padded);
      // Always perform equivalent work regardless of padding validity
      // to prevent timing side-channels (Bleichenbacher-style attacks).
      parts.push(unpadded ?? padded.subarray(0, 0));
      bad |= unpadded ? 0 : 1;
    }
    if (bad) throw new Error('Decryption failed');
    return concat(...parts);
  }
}

// Re-export type for the SchemeOptions import that's used elsewhere
export type { SchemeOptions };
