import type { HashAlg } from './crypto/types.js';
import { SCHEMES } from './schemes/index.js';
import type { EncryptionSchemeOptions, SigningSchemeOptions } from './schemes/types.js';
import type {
  EncryptionSchemeName,
  Environment,
  NodeRSAOptions,
  ResolvedOptions,
  SigningSchemeName,
} from './types.js';

const NODE_HASHES: ReadonlyArray<HashAlg> = [
  'md4',
  'md5',
  'ripemd160',
  'sha1',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
];

// Legacy v1 exposed four environment values: 'node', 'browser', plus
// 'node10' and 'iojs' as Node aliases (each retaining the same hash list).
// v2 treats 'node10' and 'iojs' as 'node'-equivalents for the hash whitelist
// so that any user setOptions({environment:'iojs'}) keeps working.
export const SUPPORTED_HASH_ALGORITHMS: Record<string, ReadonlyArray<HashAlg>> = {
  node: NODE_HASHES,
  node10: NODE_HASHES,
  iojs: NODE_HASHES,
  browser: ['md5', 'ripemd160', 'sha1', 'sha256', 'sha512'],
};

function allowedHashes(env: string): ReadonlyArray<HashAlg> {
  return SUPPORTED_HASH_ALGORITHMS[env] ?? NODE_HASHES;
}

export const DEFAULT_ENCRYPTION_SCHEME: EncryptionSchemeName = 'pkcs1_oaep';
// v2.1: switched from 'pkcs1' (PKCS#1 v1.5) to 'pss' (RSASSA-PSS). PSS is
// the modern best-practice signing scheme — probabilistic, with provable
// security reduction. Callers wanting the legacy default should set
// `signingScheme: 'pkcs1'` explicitly.
export const DEFAULT_SIGNING_SCHEME: SigningSchemeName = 'pss';

export const EXPORT_FORMAT_ALIASES: Record<string, string> = {
  private: 'pkcs1-private-pem',
  'private-der': 'pkcs1-private-der',
  public: 'pkcs8-public-pem',
  'public-der': 'pkcs8-public-der',
};

export function makeDefaultOptions(environment: Environment): ResolvedOptions {
  return {
    signingScheme: DEFAULT_SIGNING_SCHEME,
    signingSchemeOptions: { hash: 'sha256' },
    encryptionScheme: DEFAULT_ENCRYPTION_SCHEME,
    encryptionSchemeOptions: { hash: 'sha1' },
    environment,
  };
}

let warnedEnvironment = false;

/**
 * Apply user-supplied options on top of the resolved defaults, mutating
 * `target` in-place. Mirrors v1's setOptions string-parsing rules:
 *
 *  - "pkcs1" → scheme = pkcs1, no hash override
 *  - "sha256" → scheme = default (pkcs1), hash = sha256
 *  - "pss-sha512" → scheme = pss, hash = sha512
 *  - { scheme, hash, ... } → object form, scheme defaults to default
 */
export function applyOptions(target: ResolvedOptions, options: NodeRSAOptions): void {
  if (options.environment) {
    if (options.environment !== target.environment && !warnedEnvironment) {
      // eslint-disable-next-line no-console
      console.warn(
        'NodeRSA: setOptions({environment}) is deprecated. Build-time platform conditions decide the runtime; the option now only forces the pure-JS engine path.',
      );
      warnedEnvironment = true;
    }
    target.environment = options.environment;
  }

  if (options.signingScheme !== undefined) {
    if (typeof options.signingScheme === 'string') {
      const parts = options.signingScheme.toLowerCase().split('-');
      if (parts.length === 1) {
        if (NODE_HASHES.includes(parts[0] as HashAlg)) {
          target.signingSchemeOptions = { hash: parts[0] as HashAlg };
          target.signingScheme = DEFAULT_SIGNING_SCHEME;
        } else {
          target.signingScheme = parts[0] as SigningSchemeName;
          target.signingSchemeOptions = {};
        }
      } else {
        target.signingScheme = parts[0] as SigningSchemeName;
        target.signingSchemeOptions = { hash: parts[1] as HashAlg };
      }
    } else {
      const obj = options.signingScheme;
      target.signingScheme = (obj.scheme ?? DEFAULT_SIGNING_SCHEME) as SigningSchemeName;
      const { scheme: _scheme, ...rest } = obj;
      target.signingSchemeOptions = rest as SigningSchemeOptions;
    }

    if (!SCHEMES[target.signingScheme]?.isSignature) {
      throw new Error('Unsupported signing scheme');
    }
    if (
      target.signingSchemeOptions.hash &&
      !allowedHashes(target.environment).includes(target.signingSchemeOptions.hash)
    ) {
      throw new Error(`Unsupported hashing algorithm for ${target.environment} environment`);
    }
  }

  if (options.encryptionScheme !== undefined) {
    if (typeof options.encryptionScheme === 'string') {
      target.encryptionScheme = options.encryptionScheme.toLowerCase() as EncryptionSchemeName;
      target.encryptionSchemeOptions = {};
    } else {
      const obj = options.encryptionScheme;
      target.encryptionScheme = (obj.scheme ?? DEFAULT_ENCRYPTION_SCHEME) as EncryptionSchemeName;
      const { scheme: _scheme, ...rest } = obj;
      target.encryptionSchemeOptions = rest as EncryptionSchemeOptions;
    }

    if (!SCHEMES[target.encryptionScheme]?.isEncryption) {
      throw new Error('Unsupported encryption scheme');
    }
    if (
      target.encryptionSchemeOptions.hash &&
      !allowedHashes(target.environment).includes(target.encryptionSchemeOptions.hash)
    ) {
      throw new Error(`Unsupported hashing algorithm for ${target.environment} environment`);
    }
  }
}
