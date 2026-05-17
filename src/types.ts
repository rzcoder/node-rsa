import type { HashAlg } from './crypto/types.js';
import type {
  EncryptionSchemeOptions,
  MaskGenerationFunction,
  SigningSchemeOptions,
} from './schemes/types.js';

export type Environment = 'node' | 'browser';

export type EncryptionSchemeName = 'pkcs1' | 'pkcs1_oaep';
export type SigningSchemeName = 'pkcs1' | 'pss';

export type Encoding = 'buffer' | 'binary' | 'hex' | 'base64' | 'utf8' | 'json' | string;

export type KeyDataInput = Uint8Array | string | NodeRSAOptions['key'];

export interface NodeRSAGenerateOptions {
  /** Bits in the modulus. */
  b?: number;
  /** Public exponent. */
  e?: number;
}

/** Which BigInteger implementation NodeRSA should use under the hood. */
export type BigIntegerImpl = 'jsbn' | 'native';

export interface NodeRSAOptions {
  signingScheme?: string | (SigningSchemeOptions & { scheme?: SigningSchemeName });
  encryptionScheme?: string | (EncryptionSchemeOptions & { scheme?: EncryptionSchemeName });
  environment?: Environment;
  /**
   * Switch the BigInteger backend. Browser bundle defaults to `'native'`,
   * Node bundle defaults to `'jsbn'`. `'native'` silently falls back to
   * `'jsbn'` on runtimes without `globalThis.BigInt`.
   *
   * Must be set BEFORE the key is imported/generated — i.e. as part of the
   * constructor's options or before any importKey/generateKeyPair call.
   * Calling `setOptions({ bigIntImpl })` on a NodeRSA whose `keyPair`
   * already has components throws, because the existing BigInteger objects
   * carry the old implementation's class identity and can't interoperate.
   */
  bigIntImpl?: BigIntegerImpl;
  /** Used for tests; not part of the public API surface. */
  key?: unknown;
}

export type { EncryptionSchemeOptions, HashAlg, MaskGenerationFunction, SigningSchemeOptions };

export interface ResolvedOptions {
  signingScheme: SigningSchemeName;
  signingSchemeOptions: SigningSchemeOptions;
  encryptionScheme: EncryptionSchemeName;
  encryptionSchemeOptions: EncryptionSchemeOptions;
  environment: Environment;
  bigIntImpl: BigIntegerImpl;
}
