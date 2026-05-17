import type { RSAKey } from '../rsa/key.js';
import type { ExportOptions, FormatProvider, ImportOptions } from './types.js';

export interface PrivateComponents {
  n: Uint8Array;
  e: number | Uint8Array;
  d: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  dmp1: Uint8Array;
  dmq1: Uint8Array;
  coeff: Uint8Array;
}

export interface PublicComponents {
  n: Uint8Array;
  e: number | Uint8Array;
}

/**
 * Raw component object — plain JS object with `n`, `e`, `d`, `p`, `q`,
 * `dmp1`, `dmq1`, `coeff` (private) or just `n`, `e` (public).
 * No encoding step; intended for direct programmatic input.
 */
export const componentsFormat: FormatProvider = {
  privateExport(key: RSAKey, _options: ExportOptions = {}): PrivateComponents {
    if (!key.n || !key.d || !key.p || !key.q || !key.dmp1 || !key.dmq1 || !key.coeff) {
      throw new Error('components export: incomplete private key');
    }
    return {
      n: key.n.toBuffer() as Uint8Array,
      e: key.e,
      d: key.d.toBuffer() as Uint8Array,
      p: key.p.toBuffer() as Uint8Array,
      q: key.q.toBuffer() as Uint8Array,
      dmp1: key.dmp1.toBuffer() as Uint8Array,
      dmq1: key.dmq1.toBuffer() as Uint8Array,
      coeff: key.coeff.toBuffer() as Uint8Array,
    };
  },

  privateImport(key: RSAKey, data: unknown, _options: ImportOptions = {}): void {
    const d = data as Partial<PrivateComponents>;
    if (!d.n || !d.e || !d.d || !d.p || !d.q || !d.dmp1 || !d.dmq1 || !d.coeff) {
      throw new Error('Invalid key data');
    }
    key.setPrivate(d.n, d.e, d.d, d.p, d.q, d.dmp1, d.dmq1, d.coeff);
  },

  publicExport(key: RSAKey, _options: ExportOptions = {}): PublicComponents {
    if (!key.n) throw new Error('components export: missing modulus');
    return { n: key.n.toBuffer() as Uint8Array, e: key.e };
  },

  publicImport(key: RSAKey, data: unknown, _options: ImportOptions = {}): void {
    const d = data as Partial<PublicComponents>;
    if (!d.n || d.e == null) throw new Error('Invalid key data');
    key.setPublic(d.n, d.e);
  },

  autoImport(key: RSAKey, data: unknown): boolean {
    if (typeof data !== 'object' || data === null) return false;
    const d = data as Partial<PrivateComponents>;
    if (!d.n || d.e == null) return false;
    if (d.d && d.p && d.q && d.dmp1 && d.dmq1 && d.coeff) {
      componentsFormat.privateImport?.(key, data);
      return true;
    }
    componentsFormat.publicImport?.(key, data);
    return true;
  },
};
