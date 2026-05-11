import type { RSAKey } from '../rsa/key.js';

export interface ExportOptions {
  /** "pem" (default) or "der". */
  type?: 'pem' | 'der' | 'default';
}

export interface ImportOptions {
  type?: 'pem' | 'der' | 'default';
}

export interface FormatProvider {
  privateExport(key: RSAKey, options?: ExportOptions): Uint8Array | string | object;
  privateImport(key: RSAKey, data: unknown, options?: ImportOptions): void;
  publicExport(key: RSAKey, options?: ExportOptions): Uint8Array | string | object;
  publicImport(key: RSAKey, data: unknown, options?: ImportOptions): void;
  autoImport(key: RSAKey, data: unknown): boolean;
}
