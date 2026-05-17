import type { RSAKey } from '../rsa/key.js';
import { componentsFormat } from './components.js';
import { opensshFormat } from './openssh.js';
import { pkcs1Format } from './pkcs1.js';
import { pkcs8Format } from './pkcs8.js';
import type { FormatProvider, ImportOptions } from './types.js';

/** Registry of built-in format providers, keyed by scheme name. */
export const FORMATS: Record<string, FormatProvider> = {
  pkcs1: pkcs1Format,
  pkcs8: pkcs8Format,
  components: componentsFormat,
  openssh: opensshFormat,
};

interface ParsedFormat {
  scheme: string;
  keyType: 'private' | 'public';
  keyOpt: ImportOptions;
}

function formatParse(format: string): ParsedFormat {
  const parts = format.split('-');
  let keyType: 'private' | 'public' = 'private';
  const keyOpt: ImportOptions = { type: 'default' };
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    if (p === 'public' || p === 'private') keyType = p;
    else if (p === 'pem' || p === 'der') keyOpt.type = p;
  }
  return { scheme: parts[0] ?? '', keyType, keyOpt };
}

/**
 * Import `data` into `key`. If `format` is omitted, each provider's
 * `autoImport` is tried in registration order. Returns false only on
 * the no-format auto path when nothing matched; the explicit-format path
 * throws on unknown scheme or missing provider method.
 *
 * Format string is `<scheme>[-public|-private][-pem|-der]`, e.g.
 * `"pkcs1-private-pem"`. Defaults: keyType=private, type=default.
 */
export function detectAndImport(key: RSAKey, data: unknown, format?: string): boolean {
  if (!format) {
    for (const scheme of Object.values(FORMATS)) {
      if (scheme.autoImport?.(key, data)) return true;
    }
    return false;
  }
  const fmt = formatParse(format);
  const provider = FORMATS[fmt.scheme];
  if (!provider) throw new Error('Unsupported key format');
  if (fmt.keyType === 'private') {
    if (!provider.privateImport) throw new Error(`Format ${fmt.scheme} has no privateImport`);
    provider.privateImport(key, data, fmt.keyOpt);
  } else {
    if (!provider.publicImport) throw new Error(`Format ${fmt.scheme} has no publicImport`);
    provider.publicImport(key, data, fmt.keyOpt);
  }
  return true;
}

/**
 * Export `key` in the given format. Returns undefined if `format` is omitted.
 * Throws if the scheme is unknown, the key lacks the requested half
 * (private/public), or the provider doesn't implement that direction.
 * Format string syntax matches {@link detectAndImport}.
 */
export function detectAndExport(
  key: RSAKey,
  format?: string,
): Uint8Array | string | object | undefined {
  if (!format) return undefined;
  const fmt = formatParse(format);
  const provider = FORMATS[fmt.scheme];
  if (!provider) throw new Error('Unsupported key format');
  if (fmt.keyType === 'private') {
    if (!key.isPrivate()) throw new Error('This is not private key');
    if (!provider.privateExport) throw new Error(`Format ${fmt.scheme} has no privateExport`);
    return provider.privateExport(key, fmt.keyOpt);
  }
  if (!key.isPublic()) throw new Error('This is not public key');
  if (!provider.publicExport) throw new Error(`Format ${fmt.scheme} has no publicExport`);
  return provider.publicExport(key, fmt.keyOpt);
}

export { componentsFormat, opensshFormat, pkcs1Format, pkcs8Format };
export type { ExportOptions, FormatProvider, ImportOptions } from './types.js';
export type { PrivateComponents, PublicComponents } from './components.js';
