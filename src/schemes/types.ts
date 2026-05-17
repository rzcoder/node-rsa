import type { CryptoBackend, HashingAlgorithm } from '../crypto/types.js';

export type MaskGenerationFunction = (
  seed: Uint8Array,
  maskLength: number,
  hash: HashingAlgorithm,
) => Uint8Array;

export interface EncryptionSchemeOptions {
  /** RSA padding constant (PKCS#1 = 1, OAEP = 4, RSA_NO_PADDING = 3). */
  padding?: number;
  /** Hash to use for OAEP (default sha1). */
  hash?: HashingAlgorithm;
  /** Label byte string for OAEP (default empty). */
  label?: Uint8Array;
  /** Custom MGF (default MGF1). */
  mgf?: MaskGenerationFunction;
}

export interface SigningSchemeOptions {
  /** Hash to use (default sha256 for PKCS#1, sha1 for PSS). */
  hash?: HashingAlgorithm;
  /** Salt length for PSS (default 20). */
  saltLength?: number;
  /** Custom MGF for PSS (default MGF1). */
  mgf?: MaskGenerationFunction;
}

export interface SchemeOptions {
  signingScheme: 'pkcs1' | 'pss';
  encryptionScheme: 'pkcs1' | 'pkcs1_oaep';
  signingSchemeOptions: SigningSchemeOptions;
  encryptionSchemeOptions: EncryptionSchemeOptions;
  environment: 'node' | 'browser';
  backend: CryptoBackend;
}

/** Encryption-padding side of a scheme (PKCS#1 v1.5 type 2, or OAEP). */
export interface EncryptionSchemeImpl {
  maxMessageLength(): number;
  encPad(buffer: Uint8Array, opts?: { type?: number }): Uint8Array;
  encUnPad(buffer: Uint8Array, opts?: { type?: number }): Uint8Array | null;
}

/** Signing side of a scheme (PKCS#1 v1.5 type 1 with DigestInfo, or PSS). */
export interface SignatureScheme {
  sign(buffer: Uint8Array): Uint8Array;
  verify(buffer: Uint8Array, signature: Uint8Array): boolean;
}
