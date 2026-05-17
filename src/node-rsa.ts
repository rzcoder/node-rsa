import { setBigIntegerBackend } from './bigint/big-integer.js';
import { fromBase64, fromUtf8, toBase64, toHex, toUtf8 } from './crypto/bytes.js';
import type { CryptoBackend } from './crypto/types.js';
import { detectAndExport, detectAndImport } from './formats/index.js';
import { EXPORT_FORMAT_ALIASES, applyOptions, makeDefaultOptions } from './options.js';
import { type Engine, JsEngine } from './rsa/engine.js';
import { RSAKey } from './rsa/key.js';
import { SCHEMES } from './schemes/index.js';
import type { SchemeOptions } from './schemes/types.js';
import type {
  Encoding,
  Environment,
  NodeRSAGenerateOptions,
  NodeRSAOptions,
  ResolvedOptions,
} from './types.js';

interface SchemeProviderLike {
  isEncryption: boolean;
  isSignature: boolean;
  makeScheme(key: RSAKey, options: SchemeOptions): unknown;
}

interface NodeRSAInternal {
  environment: Environment;
  backend: CryptoBackend;
  /** Optional engine factory (e.g. NodeNativeEngine). Falls back to JsEngine. */
  engineFor?: (key: RSAKey, options: ResolvedOptions) => Engine;
  /**
   * Optional native key generator (e.g. node:crypto.generateKeyPairSync).
   * If absent, NodeRSA.generateKeyPair falls back to the pure-JS
   * RSAKey.generate path.
   */
  keygenFor?: (key: RSAKey, bits: number, expHex: string) => void;
  /**
   * Optional override of the default SCHEMES registry. The node bundle
   * passes a map with PKCS1 + PSS replaced by node:crypto-backed wrappers.
   * Bypassed when the user forces environment:'browser' at runtime so
   * setOptions can route back to the JS implementations.
   */
  schemes?: Record<string, SchemeProviderLike>;
}

let internal: NodeRSAInternal | undefined;

/** Called by the platform entry (src/index.node.ts or .browser.ts) at module load. */
export function bootstrap(config: NodeRSAInternal): void {
  internal = config;
  setBigIntegerBackend(config.backend);
}

function getInternal(): NodeRSAInternal {
  if (!internal) {
    throw new Error(
      'NodeRSA: backend not initialized. Import the package via its main entry, not by deep-importing internals.',
    );
  }
  return internal;
}

export class NodeRSA {
  $options: ResolvedOptions;
  keyPair: RSAKey;
  private engine: Engine | null = null;
  private $cache: Record<string, Uint8Array | string | object> = {};

  constructor(
    key?: Uint8Array | string | NodeRSAGenerateOptions | null,
    format?: string | NodeRSAOptions,
    options?: NodeRSAOptions,
  ) {
    // normalise overloads
    let opts: NodeRSAOptions | undefined;
    let fmt: string | undefined;
    if (typeof format === 'object' && format !== null) {
      opts = format;
      fmt = undefined;
    } else {
      fmt = format as string | undefined;
      opts = options;
    }

    const env = getInternal().environment;
    this.$options = makeDefaultOptions(env);
    this.keyPair = new RSAKey();

    // Apply user options BEFORE touching BigInteger so settings like
    // `bigIntImpl` take effect during importKey/generateKeyPair. The keyPair
    // is still empty here, so rewireScheme is a no-op-ish wire-up and safe.
    if (opts) {
      applyOptions(this.$options, opts);
      this.rewireScheme();
    }

    if (key instanceof Uint8Array || typeof key === 'string') {
      this.importKey(key, fmt);
    } else if (key && typeof key === 'object') {
      const gen = key as NodeRSAGenerateOptions;
      this.generateKeyPair(gen.b, gen.e);
    }

    if (!opts && !key) this.rewireScheme();
  }

  setOptions(options: NodeRSAOptions): this {
    if (
      options.bigIntImpl &&
      options.bigIntImpl !== this.$options.bigIntImpl &&
      this.keyPair.n != null
    ) {
      // Existing BigInteger components carry the old impl's class identity.
      // Switching now would mix impls inside one key — broken arithmetic.
      throw new Error(
        'NodeRSA: bigIntImpl can only be set on a fresh instance (before importKey / generateKeyPair). Pass it in the constructor options, or set it before importing.',
      );
    }
    applyOptions(this.$options, options);
    this.rewireScheme();
    return this;
  }

  generateKeyPair(bits = 2048, exp = 65537): this {
    if (bits % 8 !== 0) throw new Error('Key size must be a multiple of 8.');
    const cfg = getInternal();
    const expHex = exp.toString(16);
    // Native fast-path (node bundle wires keygenFor → node:crypto.generateKeyPairSync,
    // ~20–50× faster than RSAKey.generate for keys ≥ 2048 bits). The browser bundle
    // doesn't wire it and falls back to the pure-JS path.
    if (cfg.keygenFor && this.$options.environment !== 'browser') {
      cfg.keygenFor(this.keyPair, bits, expHex);
    } else {
      this.keyPair.generate(bits, expHex);
    }
    this.$cache = {};
    this.rewireScheme();
    return this;
  }

  importKey(keyData: Uint8Array | string | object, format?: string): this {
    if (keyData == null || (typeof keyData === 'string' && keyData.length === 0)) {
      throw new Error('Empty key given');
    }
    const resolvedFormat = format ? (EXPORT_FORMAT_ALIASES[format] ?? format) : format;
    const imported = detectAndImport(this.keyPair, keyData, resolvedFormat);
    if (!imported && resolvedFormat === undefined) {
      throw new Error('Key format must be specified');
    }
    this.$cache = {};
    this.rewireScheme();
    return this;
  }

  exportKey(format = 'private'): Uint8Array | string | object {
    const resolved = EXPORT_FORMAT_ALIASES[format] ?? format;
    if (!this.$cache[resolved]) {
      const exported = detectAndExport(this.keyPair, resolved);
      if (exported === undefined) throw new Error('Export failed');
      this.$cache[resolved] = exported;
    }
    return this.$cache[resolved] as Uint8Array | string | object;
  }

  isPrivate(): boolean {
    return this.keyPair.isPrivate();
  }

  isPublic(strict?: boolean): boolean {
    return this.keyPair.isPublic(strict);
  }

  isEmpty(): boolean {
    return !(this.keyPair.n || this.keyPair.e || this.keyPair.d);
  }

  getKeySize(): number {
    return this.keyPair.keySize;
  }

  getMaxMessageSize(): number {
    return this.keyPair.maxMessageLength;
  }

  encrypt(buffer: unknown, encoding?: Encoding, sourceEncoding?: string): Uint8Array | string {
    return this.$$encryptKey(false, buffer, encoding, sourceEncoding);
  }

  decrypt(buffer: Uint8Array | string, encoding?: Encoding): Uint8Array | string | object {
    return this.$$decryptKey(false, buffer, encoding);
  }

  encryptPrivate(
    buffer: unknown,
    encoding?: Encoding,
    sourceEncoding?: string,
  ): Uint8Array | string {
    return this.$$encryptKey(true, buffer, encoding, sourceEncoding);
  }

  decryptPublic(buffer: Uint8Array | string, encoding?: Encoding): Uint8Array | string | object {
    return this.$$decryptKey(true, buffer, encoding);
  }

  sign(buffer: unknown, encoding?: Encoding, sourceEncoding?: string): Uint8Array | string {
    if (!this.isPrivate()) throw new Error('This is not private key');
    const data = this.$getDataForEncrypt(buffer, sourceEncoding);
    const res = this.keyPair.signingScheme.sign(data);
    return encoding && encoding !== 'buffer' ? encodeBytes(res, encoding) : res;
  }

  verify(
    buffer: unknown,
    signature: Uint8Array | string,
    sourceEncoding?: string,
    signatureEncoding?: string,
  ): boolean {
    if (!this.isPublic()) throw new Error('This is not public key');
    const data = this.$getDataForEncrypt(buffer, sourceEncoding);
    const sig =
      typeof signature === 'string' ? decodeBytes(signature, signatureEncoding) : signature;
    return this.keyPair.signingScheme.verify(data, sig);
  }

  // ───── internals ──────────────────────────────────────────────────────────
  $$encryptKey(
    usePrivate: boolean,
    buffer: unknown,
    encoding?: Encoding,
    sourceEncoding?: string,
  ): Uint8Array | string {
    try {
      const data = this.$getDataForEncrypt(buffer, sourceEncoding);
      const res = this.ensureEngine().encrypt(data, usePrivate);
      return encoding && encoding !== 'buffer' ? encodeBytes(res, encoding) : res;
    } catch (e) {
      throw new Error(`Error during encryption. Original error: ${(e as Error).message}`);
    }
  }

  $$decryptKey(
    usePublic: boolean,
    buffer: Uint8Array | string,
    encoding?: Encoding,
  ): Uint8Array | string | object {
    try {
      const bytes = typeof buffer === 'string' ? fromBase64(buffer) : buffer;
      const res = this.ensureEngine().decrypt(bytes, usePublic);
      return this.$getDecryptedData(res, encoding);
    } catch (e) {
      throw new Error(
        `Error during decryption (probably incorrect key). Original error: ${(e as Error).message}`,
      );
    }
  }

  $getDataForEncrypt(buffer: unknown, encoding?: string): Uint8Array {
    if (typeof buffer === 'string') {
      return encoding && encoding !== 'utf8' ? decodeBytes(buffer, encoding) : fromUtf8(buffer);
    }
    if (typeof buffer === 'number') return fromUtf8(String(buffer));
    if (buffer instanceof Uint8Array) return buffer;
    if (buffer !== null && typeof buffer === 'object') return fromUtf8(JSON.stringify(buffer));
    throw new Error('Unexpected data type');
  }

  $getDecryptedData(bytes: Uint8Array, encoding?: Encoding): Uint8Array | string | object {
    const enc = encoding ?? 'buffer';
    if (enc === 'buffer') return bytes;
    if (enc === 'json') return JSON.parse(toUtf8(bytes));
    return encodeBytes(bytes, enc);
  }

  private rewireScheme(): void {
    const cfg = getInternal();
    const opts: SchemeOptions = {
      signingScheme: this.$options.signingScheme,
      encryptionScheme: this.$options.encryptionScheme,
      signingSchemeOptions: this.$options.signingSchemeOptions,
      encryptionSchemeOptions: this.$options.encryptionSchemeOptions,
      environment: this.$options.environment,
      backend: cfg.backend,
    };
    // When the user forces environment:'browser' on the node bundle, revert
    // to the pure-JS SCHEMES so signing also goes through the JS path —
    // otherwise sign/verify would still use node:crypto while the engine
    // uses JsEngine, defeating the override.
    const forcedJs = this.$options.environment === 'browser';
    const schemes = forcedJs ? SCHEMES : (cfg.schemes ?? SCHEMES);
    this.keyPair.setOptions(opts, schemes);
    this.engine = null;
  }

  private ensureEngine(): Engine {
    if (this.engine) return this.engine;
    const cfg = getInternal();
    const forcedJs = this.$options.environment === 'browser';
    if (!forcedJs && cfg.engineFor) {
      this.engine = cfg.engineFor(this.keyPair, this.$options);
    } else {
      this.engine = new JsEngine(this.keyPair);
    }
    return this.engine;
  }
}

function encodeBytes(bytes: Uint8Array, encoding: string): string {
  switch (encoding) {
    case 'hex':
      return toHex(bytes);
    case 'base64':
      return toBase64(bytes);
    case 'utf8':
    case 'binary':
      return toUtf8(bytes);
    default:
      // Best-effort: treat as base64 fallback to match v1 behaviour for unknown encodings
      return toBase64(bytes);
  }
}

function decodeBytes(s: string, encoding?: string): Uint8Array {
  switch (encoding) {
    case 'hex': {
      if (s.length % 2 !== 0) throw new Error('Invalid hex string');
      const out = new Uint8Array(s.length / 2);
      for (let i = 0; i < out.length; i++)
        out[i] = Number.parseInt(s.substring(i * 2, i * 2 + 2), 16);
      return out;
    }
    case 'utf8':
    case 'binary':
      return fromUtf8(s);
    case undefined:
    case null:
    case 'buffer':
    case 'base64':
      return fromBase64(s);
    default:
      return fromBase64(s);
  }
}
