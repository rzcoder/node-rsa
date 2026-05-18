import type { RSAKey } from '../rsa/key.js';

export interface ExportOptions {
  /** "pem" (default) or "der". */
  type?: 'pem' | 'der' | 'default';
}

export interface ImportOptions {
  type?: 'pem' | 'der' | 'default';
}

/**
 * One key-encoding format (PKCS#1, PKCS#8, OpenSSH, components).
 * `components` returns a plain object; the rest return PEM string or DER bytes.
 */
export interface FormatProvider {
  /** Serialize the private half. Throws if the key lacks private components. */
  privateExport(key: RSAKey, options?: ExportOptions): Uint8Array | string | object;
  /** Parse `data` into `key` as a private key. */
  privateImport(key: RSAKey, data: unknown, options?: ImportOptions): void;
  /** Serialize the public half. */
  publicExport(key: RSAKey, options?: ExportOptions): Uint8Array | string | object;
  /** Parse `data` into `key` as a public key. */
  publicImport(key: RSAKey, data: unknown, options?: ImportOptions): void;
  /** Sniff `data` and route to private/public import if the format matches. Returns false if not recognised. */
  autoImport(key: RSAKey, data: unknown): boolean;
}
