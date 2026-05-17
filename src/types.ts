import type { HashingAlgorithm } from './crypto/types.js';
import type {
  EncryptionSchemeOptions,
  MaskGenerationFunction,
  SigningSchemeOptions,
} from './schemes/types.js';

export type Environment = 'node' | 'browser';

export type EncryptionScheme = 'pkcs1' | 'pkcs1_oaep';
export type SigningScheme = 'pkcs1' | 'pss';

/**
 * Shorthand scheme-hash combinations accepted by `signingScheme`.
 * Parsed at runtime as `<scheme>-<hash>`.
 */
export type SigningSchemeHash =
  | 'pkcs1-ripemd160'
  | 'pkcs1-md4'
  | 'pkcs1-md5'
  | 'pkcs1-sha'
  | 'pkcs1-sha1'
  | 'pkcs1-sha224'
  | 'pkcs1-sha256'
  | 'pkcs1-sha384'
  | 'pkcs1-sha512'
  | 'pss-ripemd160'
  | 'pss-md4'
  | 'pss-md5'
  | 'pss-sha'
  | 'pss-sha1'
  | 'pss-sha224'
  | 'pss-sha256'
  | 'pss-sha384'
  | 'pss-sha512';

/** PEM-encoded key format identifiers (string output / input). */
export type FormatPem =
  | 'private'
  | 'public'
  | 'pkcs1'
  | 'pkcs1-pem'
  | 'pkcs1-private'
  | 'pkcs1-private-pem'
  | 'pkcs1-public'
  | 'pkcs1-public-pem'
  | 'pkcs8'
  | 'pkcs8-pem'
  | 'pkcs8-private'
  | 'pkcs8-private-pem'
  | 'pkcs8-public'
  | 'pkcs8-public-pem'
  | 'openssh-public'
  | 'openssh-private';

/** DER-encoded key format identifiers (Uint8Array output / input). */
export type FormatDer =
  | 'pkcs1-der'
  | 'pkcs1-private-der'
  | 'pkcs1-public-der'
  | 'pkcs8-der'
  | 'pkcs8-private-der'
  | 'pkcs8-public-der';

/** Raw private components format identifiers. */
export type FormatComponentsPrivate =
  | 'components'
  | 'components-pem'
  | 'components-der'
  | 'components-private'
  | 'components-private-pem'
  | 'components-private-der';

/** Raw public components format identifiers. */
export type FormatComponentsPublic =
  | 'components-public'
  | 'components-public-pem'
  | 'components-public-der';

/** Any supported key format identifier. */
export type Format = FormatPem | FormatDer | FormatComponentsPrivate | FormatComponentsPublic;

export interface KeyComponentsPrivate {
  n: Uint8Array;
  e: Uint8Array | number;
  d: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  dmp1: Uint8Array;
  dmq1: Uint8Array;
  coeff: Uint8Array;
}

export interface KeyComponentsPublic {
  n: Uint8Array;
  e: Uint8Array | number;
}

/** Key material accepted by `importKey` / the constructor. */
export type Key = string | Uint8Array | KeyComponentsPrivate | KeyComponentsPublic;

/** Plaintext data accepted by `encrypt` / `sign`. */
export type Data = string | object | unknown[];

/** `{ b: bits }` shorthand for `new NodeRSA({ b: 2048 })`. */
export interface KeyBits {
  b: number;
}

/**
 * Encoding tags accepted by encrypt/decrypt/sign/verify for converting
 * between strings and bytes. `'json'` is a decrypt-only sentinel and is
 * declared separately on `decrypt` / `decryptPublic` overloads, not here.
 *
 * Note: legacy v1 accepted `'ascii'`, `'utf16le'`, `'ucs2'` by name but
 * routed them through `Buffer.from` aliases that v2 no longer wires; only
 * the encodings below are implemented end-to-end.
 */
export type Encoding = 'buffer' | 'binary' | 'latin1' | 'hex' | 'base64' | 'utf8';

export interface AdvancedEncryptionSchemePKCS1 {
  scheme: 'pkcs1';
  /** OpenSSL RSA padding constant (currently informational; runtime uses scheme name). */
  padding?: number;
}

export interface AdvancedEncryptionSchemePKCS1OAEP {
  scheme: 'pkcs1_oaep';
  hash?: HashingAlgorithm;
  label?: Uint8Array;
  mgf?: MaskGenerationFunction;
}

export type AdvancedEncryptionScheme =
  | AdvancedEncryptionSchemePKCS1
  | AdvancedEncryptionSchemePKCS1OAEP;

export interface AdvancedSigningSchemePSS {
  scheme: 'pss';
  hash?: HashingAlgorithm;
  saltLength?: number;
  mgf?: MaskGenerationFunction;
}

export interface AdvancedSigningSchemePKCS1 {
  scheme: 'pkcs1';
  hash?: HashingAlgorithm;
}

export type AdvancedSigningScheme = AdvancedSigningSchemePSS | AdvancedSigningSchemePKCS1;

export interface NodeRSAGenerateOptions {
  /** Bits in the modulus. */
  b?: number;
  /** Public exponent. */
  e?: number;
}

/** Which BigInteger implementation NodeRSA should use under the hood. */
export type BigIntegerImpl = 'jsbn' | 'native';

export interface NodeRSAOptions {
  signingScheme?:
    | SigningScheme
    | SigningSchemeHash
    | AdvancedSigningScheme
    | (SigningSchemeOptions & { scheme?: SigningScheme });
  encryptionScheme?:
    | EncryptionScheme
    | AdvancedEncryptionScheme
    | (EncryptionSchemeOptions & { scheme?: EncryptionScheme });
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

export type {
  EncryptionSchemeOptions,
  HashingAlgorithm,
  MaskGenerationFunction,
  SigningSchemeOptions,
};

export interface ResolvedOptions {
  signingScheme: SigningScheme;
  signingSchemeOptions: SigningSchemeOptions;
  encryptionScheme: EncryptionScheme;
  encryptionSchemeOptions: EncryptionSchemeOptions;
  environment: Environment;
  bigIntImpl: BigIntegerImpl;
}
