import {
  type KeyObject,
  createPrivateKey,
  createPublicKey,
  constants as nodeConstants,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import type { HashingAlgorithm } from '../crypto/types.js';
import { pkcs1Format } from '../formats/pkcs1.js';
import type { SchemeProvider } from '../schemes/index.js';
import { oaepScheme } from '../schemes/oaep.js';
import { pkcs1Scheme } from '../schemes/pkcs1.js';
import type { EncryptionSchemeImpl, SchemeOptions, SignatureScheme } from '../schemes/types.js';
import type { RSAKey } from './key.js';

const DEFAULT_PKCS1_HASH: HashingAlgorithm = 'sha256';
const DEFAULT_PSS_HASH: HashingAlgorithm = 'sha1';
const DEFAULT_PSS_SALT = 20;

function bufferToU8(buf: Buffer): Uint8Array {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function privateKeyObjectFor(key: RSAKey): KeyObject {
  if (!key.isPrivate()) throw new Error('Native signing requires a private key');
  const pem = pkcs1Format.privateExport?.(key, { type: 'pem' }) as string;
  return createPrivateKey({ key: pem, format: 'pem', type: 'pkcs1' });
}

function publicKeyObjectFor(key: RSAKey): KeyObject {
  if (!key.isPublic()) throw new Error('Native verifying requires a public key');
  const pem = pkcs1Format.publicExport?.(key, { type: 'pem' }) as string;
  return createPublicKey({ key: pem, format: 'pem', type: 'pkcs1' });
}

function assertHashSupported(backend: SchemeOptions['backend'], hash: HashingAlgorithm): void {
  if (!backend.supportsHash(hash)) {
    throw new Error(
      `node-rsa: hash "${hash}" not available in node:crypto on this build (OpenSSL 3 may need the legacy provider for md4/ripemd160). Use setOptions({environment:"browser"}) to force the pure-JS path.`,
    );
  }
}

/**
 * PKCS#1 v1.5 — keeps the JS scheme for encryption padding (encPad/encUnPad),
 * delegates sign/verify to node:crypto. NodeNativeEngine handles the
 * encryption RSA primitive separately, so the JS scheme's sign/verify path
 * (which is what we override here) is the only thing still going through
 * BigInteger.modPow today.
 */
class NodeNativePkcs1Scheme implements EncryptionSchemeImpl, SignatureScheme {
  private privateKeyObj?: KeyObject;
  private publicKeyObj?: KeyObject;

  constructor(
    private readonly inner: EncryptionSchemeImpl & SignatureScheme,
    private readonly key: RSAKey,
    private readonly options: SchemeOptions,
  ) {}

  maxMessageLength(): number {
    return this.inner.maxMessageLength();
  }
  encPad(buf: Uint8Array, opts?: { type?: number }): Uint8Array {
    return this.inner.encPad(buf, opts);
  }
  encUnPad(buf: Uint8Array, opts?: { type?: number }): Uint8Array | null {
    return this.inner.encUnPad(buf, opts);
  }

  sign(buffer: Uint8Array): Uint8Array {
    const hash = this.options.signingSchemeOptions.hash ?? DEFAULT_PKCS1_HASH;
    assertHashSupported(this.options.backend, hash);
    if (!this.privateKeyObj) this.privateKeyObj = privateKeyObjectFor(this.key);
    const sig = nodeSign(hash, buffer, {
      key: this.privateKeyObj,
      padding: nodeConstants.RSA_PKCS1_PADDING,
    });
    return bufferToU8(sig);
  }

  verify(buffer: Uint8Array, signature: Uint8Array): boolean {
    const hash = this.options.signingSchemeOptions.hash ?? DEFAULT_PKCS1_HASH;
    assertHashSupported(this.options.backend, hash);
    if (!this.publicKeyObj) this.publicKeyObj = publicKeyObjectFor(this.key);
    // RFC 8017 §8.2.2 step 2.b: out-of-range signature representative
    // (or any other RSA-primitive failure) yields "invalid signature",
    // not a thrown error.
    try {
      return nodeVerify(
        hash,
        buffer,
        {
          key: this.publicKeyObj,
          padding: nodeConstants.RSA_PKCS1_PADDING,
        },
        signature,
      );
    } catch {
      return false;
    }
  }
}

/**
 * PSS — node:crypto only supports MGF1 with the same hash as the message
 * digest. A custom MGF or a different MGF-hash configuration cannot be
 * expressed natively; we throw at scheme construction so the failure is
 * loud and early rather than silent at sign time.
 */
class NodeNativePssScheme implements SignatureScheme {
  private privateKeyObj?: KeyObject;
  private publicKeyObj?: KeyObject;

  constructor(
    private readonly key: RSAKey,
    private readonly options: SchemeOptions,
  ) {
    if (options.signingSchemeOptions.mgf) {
      throw new Error(
        'node-rsa: custom MGF for PSS is not supported in the node-native engine ' +
          '(node:crypto only does MGF1 with hash = signing hash). ' +
          'Use setOptions({environment:"browser"}) to force the pure-JS path.',
      );
    }
  }

  sign(buffer: Uint8Array): Uint8Array {
    const hash = this.options.signingSchemeOptions.hash ?? DEFAULT_PSS_HASH;
    assertHashSupported(this.options.backend, hash);
    const saltLength = this.options.signingSchemeOptions.saltLength ?? DEFAULT_PSS_SALT;
    if (!this.privateKeyObj) this.privateKeyObj = privateKeyObjectFor(this.key);
    const sig = nodeSign(hash, buffer, {
      key: this.privateKeyObj,
      padding: nodeConstants.RSA_PKCS1_PSS_PADDING,
      saltLength,
    });
    return bufferToU8(sig);
  }

  verify(buffer: Uint8Array, signature: Uint8Array): boolean {
    const hash = this.options.signingSchemeOptions.hash ?? DEFAULT_PSS_HASH;
    assertHashSupported(this.options.backend, hash);
    const saltLength = this.options.signingSchemeOptions.saltLength ?? DEFAULT_PSS_SALT;
    if (!this.publicKeyObj) this.publicKeyObj = publicKeyObjectFor(this.key);
    try {
      return nodeVerify(
        hash,
        buffer,
        {
          key: this.publicKeyObj,
          padding: nodeConstants.RSA_PKCS1_PSS_PADDING,
          saltLength,
        },
        signature,
      );
    } catch {
      return false;
    }
  }
}

/**
 * Drop-in replacement for the default `SCHEMES` map used by the Node bundle:
 * pkcs1 + pss sign/verify go through `node:crypto` (faster, FIPS-friendly);
 * pkcs1_oaep is unchanged because OAEP encryption already routes through
 * NodeNativeEngine. Constructing a PSS scheme with a custom MGF throws —
 * see `NodeNativePssScheme`.
 */
export const nodeNativeSchemes: Record<string, SchemeProvider> = {
  pkcs1: {
    isEncryption: true,
    isSignature: true,
    makeScheme(key: RSAKey, options: SchemeOptions): EncryptionSchemeImpl & SignatureScheme {
      const inner = pkcs1Scheme.makeScheme(key, options) as EncryptionSchemeImpl & SignatureScheme;
      return new NodeNativePkcs1Scheme(inner, key, options);
    },
  },
  pss: {
    isEncryption: false,
    isSignature: true,
    makeScheme(key: RSAKey, options: SchemeOptions): SignatureScheme {
      return new NodeNativePssScheme(key, options);
    },
  },
  pkcs1_oaep: oaepScheme,
};
