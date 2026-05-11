import { BigInteger } from '../bigint/big-integer.js';
import { concat } from '../crypto/bytes.js';
import { pkcs1Scheme as pkcs1Provider } from '../schemes/pkcs1.js';
import type { EncryptionScheme, SchemeOptions, SignatureScheme } from '../schemes/types.js';
import type { RSAKey } from './key.js';

/**
 * Engine handles full encrypt/decrypt for arbitrarily-long buffers by
 * chunking, applying the encryption scheme's padding, and invoking the
 * RSA primitive (key.$doPublic / $doPrivate).
 *
 * Type-1 path (encryptPrivate, decryptPublic) is *always* PKCS#1 v1.5,
 * even when the configured encryptionScheme is OAEP — matches legacy
 * v1's encryptEngines/js.js behaviour (it instantiated a dedicated
 * pkcs1Scheme for the type-1 path).
 *
 * Implementations:
 *  - JsEngine: always-available pure-JS path. Used in the browser bundle
 *    and as a fallback on Node when no native fast-path is wired (or when
 *    setOptions({environment:'browser'}) forces it).
 *  - NodeNativeEngine: uses node:crypto.publicEncrypt / privateDecrypt /
 *    privateEncrypt / publicDecrypt for speed.
 */
export interface Engine {
  encrypt(buffer: Uint8Array, usePrivate?: boolean): Uint8Array;
  decrypt(buffer: Uint8Array, usePublic?: boolean): Uint8Array;
}

export class JsEngine implements Engine {
  /** Always a PKCS#1 v1.5 scheme — used for usePrivate / usePublic paths. */
  private readonly pkcs1: EncryptionScheme;

  constructor(private readonly key: RSAKey) {
    this.pkcs1 = pkcs1Provider.makeScheme(key, key.options) as EncryptionScheme & SignatureScheme;
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
      const bi = new BigInteger(padded);
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

    for (let i = 0; i < count; i++) {
      const off = i * chunkLen;
      const ct = buffer.subarray(off, off + chunkLen);
      const bi = new BigInteger(ct);
      const result = usePublic ? this.key.$doPublic(bi) : this.key.$doPrivate(bi);
      const padded = result.toBuffer(chunkLen);
      if (!padded) throw new Error('Engine: RSA primitive returned oversize integer');
      const unpadded = usePublic
        ? this.pkcs1.encUnPad(padded, { type: 1 })
        : this.key.encryptionScheme.encUnPad(padded);
      if (!unpadded) throw new Error('Decryption failed (invalid padding)');
      parts.push(unpadded);
    }
    return concat(...parts);
  }
}

// Re-export type for the SchemeOptions import that's used elsewhere
export type { SchemeOptions };
