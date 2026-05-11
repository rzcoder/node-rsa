import {
  constants as nodeConstants,
  privateDecrypt as nodePrivateDecrypt,
  privateEncrypt as nodePrivateEncrypt,
  publicDecrypt as nodePublicDecrypt,
  publicEncrypt as nodePublicEncrypt,
} from 'node:crypto';
import { detectAndExport } from '../formats/index.js';
import { RSA_NO_PADDING } from '../schemes/index.js';
import type { ResolvedOptions } from '../types.js';
import { type Engine, JsEngine } from './engine.js';
import type { RSAKey } from './key.js';

/**
 * NodeNativeEngine — uses node:crypto.{publicEncrypt, privateDecrypt,
 * privateEncrypt, publicDecrypt} when the scheme is one of:
 *   - pkcs1 (RSA_PKCS1_PADDING)
 *   - pkcs1_oaep (RSA_PKCS1_OAEP_PADDING)
 *   - RSA_NO_PADDING (when set in encryptionSchemeOptions.padding)
 *
 * Falls back to the JS engine for unsupported combinations.
 */
export class NodeNativeEngine implements Engine {
  private readonly fallback: JsEngine;
  constructor(
    private readonly key: RSAKey,
    private readonly options: ResolvedOptions,
  ) {
    this.fallback = new JsEngine(key);
  }

  /**
   * Routes back to the JS engine for combinations OpenSSL doesn't accept:
   *  - `privateEncrypt` + OAEP padding ("illegal or unsupported padding mode")
   *  - any RSA_NO_PADDING operation (Node would require pre-padded fixed-size
   *    chunks; the JS engine handles padding/unpadding internally).
   *  - PKCS#1 v1.5 privateDecrypt on modern Node (security-deprecated since
   *    CVE-2024-PEND — Node throws unless --security-revert is set).
   *
   * `decrypt` is the parameter "reversed" for `usePublic=true` callers and
   * "not reversed" for the canonical `privateDecrypt` path. The arg name in
   * encrypt() means usePrivate; in decrypt() it means usePublic.
   */
  private nativeAvailableForEncrypt(usePrivate: boolean): boolean {
    if (this.options.encryptionSchemeOptions.padding === RSA_NO_PADDING) return false;
    if (usePrivate && this.options.encryptionScheme === 'pkcs1_oaep') return false;
    return true;
  }

  private nativeAvailableForDecrypt(usePublic: boolean): boolean {
    if (this.options.encryptionSchemeOptions.padding === RSA_NO_PADDING) return false;
    if (usePublic && this.options.encryptionScheme === 'pkcs1_oaep') return false;
    // PKCS#1 v1.5 privateDecrypt has been disabled in modern Node by default.
    if (!usePublic && this.options.encryptionScheme === 'pkcs1') return false;
    return true;
  }

  private padding(): number {
    const p = this.options.encryptionSchemeOptions.padding;
    if (p === RSA_NO_PADDING) return nodeConstants.RSA_NO_PADDING;
    if (this.options.encryptionScheme === 'pkcs1_oaep') return nodeConstants.RSA_PKCS1_OAEP_PADDING;
    return nodeConstants.RSA_PKCS1_PADDING;
  }

  private oaepHashOption(): { oaepHash?: string } {
    if (this.options.encryptionScheme === 'pkcs1_oaep') {
      const h = this.options.encryptionSchemeOptions.hash;
      if (h) return { oaepHash: h };
    }
    return {};
  }

  encrypt(buffer: Uint8Array, usePrivate = false): Uint8Array {
    if (!this.nativeAvailableForEncrypt(usePrivate))
      return this.fallback.encrypt(buffer, usePrivate);
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

    const exportFormat = usePrivate ? 'pkcs1-private-pem' : 'pkcs8-public-pem';
    const keyPem = detectAndExport(this.key, exportFormat) as string;
    const oaep = this.oaepHashOption();
    const padding = this.padding();

    const out: Uint8Array[] = [];
    for (const chunk of chunks) {
      const ct = usePrivate
        ? nodePrivateEncrypt({ key: keyPem, padding, ...oaep }, Buffer.from(chunk))
        : nodePublicEncrypt({ key: keyPem, padding, ...oaep }, Buffer.from(chunk));
      out.push(new Uint8Array(ct.buffer, ct.byteOffset, ct.byteLength));
    }

    return concatU8(out);
  }

  decrypt(buffer: Uint8Array, usePublic = false): Uint8Array {
    if (!this.nativeAvailableForDecrypt(usePublic)) return this.fallback.decrypt(buffer, usePublic);
    const chunkLen = this.key.encryptedDataLength;
    if (buffer.length % chunkLen !== 0) throw new Error('Incorrect data or key');
    const count = buffer.length / chunkLen;

    const exportFormat = usePublic ? 'pkcs8-public-pem' : 'pkcs1-private-pem';
    const keyPem = detectAndExport(this.key, exportFormat) as string;
    const oaep = this.oaepHashOption();
    const padding = this.padding();

    const out: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
      const slice = Buffer.from(buffer.subarray(i * chunkLen, (i + 1) * chunkLen));
      const pt = usePublic
        ? nodePublicDecrypt({ key: keyPem, padding, ...oaep }, slice)
        : nodePrivateDecrypt({ key: keyPem, padding, ...oaep }, slice);
      out.push(new Uint8Array(pt.buffer, pt.byteOffset, pt.byteLength));
    }
    return concatU8(out);
  }
}

function concatU8(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
