import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assert } from 'chai';
import { beforeAll, describe, it } from 'vitest';
import { nodeBackend } from '../src/crypto/backend.node.js';
import { fromBase64, toHex } from '../src/crypto/bytes.js';
import { DIGEST_LENGTH } from '../src/crypto/digest-length.js';
import NodeRSA from '../src/index.node.js';
import type { HashAlg } from '../src/types.js';

// ============================================================================
// 1-to-1 port of v1's test/tests.js (mocha+chai → vitest+chai). Structure,
// describe/it titles, and assertions match the legacy file. Buffer-specific
// uses are translated to Uint8Array equivalents; deprecated environment
// "iojs" is removed (v2 supports only "node" and "browser").
// ============================================================================

const here = dirname(fileURLToPath(import.meta.url));
const keysFolder = resolve(here, 'keys');
const RSA_NO_PADDING = 3;

function readFile(name: string): Uint8Array {
  const buf = readFileSync(resolve(keysFolder, name));
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function readStr(name: string): string {
  return readFileSync(resolve(keysFolder, name), 'utf8');
}

function bytesFromBase64(s: string): Uint8Array {
  return fromBase64(s);
}

function asHex(x: unknown): string {
  if (x instanceof Uint8Array) return toHex(x);
  if (typeof x === 'string') return toHex(new TextEncoder().encode(x));
  throw new Error(`Cannot toHex: ${typeof x}`);
}

describe('NodeRSA', () => {
  const keySizes = [
    { b: 512, e: 3 },
    { b: 512, e: 5 },
    { b: 512, e: 257 },
    { b: 512, e: 65537 },
    { b: 768 },
    { b: 1024 },
    { b: 2048 }, // exercises PSS-SHA512 with max salt length
  ];

  const environments = ['browser', 'node'] as const;
  const encryptSchemes: Array<string | { scheme: string; padding?: number; toString(): string }> = [
    'pkcs1',
    'pkcs1_oaep',
    {
      scheme: 'pkcs1',
      padding: RSA_NO_PADDING,
      toString() {
        return 'pkcs1-nopadding';
      },
    },
  ];
  const signingSchemes = ['pkcs1', 'pss'] as const;
  const signHashAlgorithms: Record<'node' | 'browser', string[]> = {
    node: ['MD4', 'MD5', 'RIPEMD160', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
    browser: ['MD5', 'RIPEMD160', 'SHA1', 'SHA256', 'SHA512'],
  };

  // MD4 lives in OpenSSL's legacy provider, not loaded by default in
  // OpenSSL 3 (Node 17+). Skip MD4-specific cases when unsupported.
  function shouldSkip(alg: string): boolean {
    return alg.toLowerCase() === 'md4' && !nodeBackend.supportsHash('md4');
  }

  type DataKey =
    | 'string'
    | 'unicode string'
    | 'empty string'
    | 'long string'
    | 'buffer'
    | 'json object'
    | 'json array';
  const dataBundle: Record<DataKey, { data: unknown; encoding: string | string[] }> = {
    string: { data: 'ascii + 12345678', encoding: 'utf8' },
    'unicode string': { data: 'ascii + юникод スラ ⑨', encoding: 'utf8' },
    'empty string': { data: '', encoding: ['utf8', 'ascii', 'hex', 'base64'] },
    'long string': {
      data: 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
      encoding: ['utf8', 'ascii'],
    },
    buffer: { data: new TextEncoder().encode('ascii + юникод スラ ⑨'), encoding: 'buffer' },
    'json object': {
      data: {
        str: 'string',
        arr: ['a', 'r', 'r', 'a', 'y', true, '⑨'],
        int: 42,
        nested: { key: { key: 1 } },
      },
      encoding: 'json',
    },
    'json array': {
      data: [1, 2, 3, 4, 5, 6, 7, 8, 9, [10, 11, 12, [13], 14, 15, [16, 17, [18]]]],
      encoding: 'json',
    },
  };

  const privateKeyPKCS1 = readStr('private_pkcs1.pem').trim();
  const publicKeyPKCS8 = readStr('public_pkcs8.pem').trim();

  const generatedKeys: NodeRSA[] = [];
  let privateNodeRSA: NodeRSA;
  let publicNodeRSA: NodeRSA;

  beforeAll(() => {
    // Generate the matrix once. Used by encrypt/decrypt and sign/verify suites.
    for (const size of keySizes) {
      const key = new NodeRSA({ b: size.b, e: size.e }, { encryptionScheme: 'pkcs1' });
      generatedKeys.push(key);
    }
  }, 60_000);

  describe('Setup options', () => {
    it('should use browser environment', () => {
      assert.equal(new NodeRSA(null, { environment: 'browser' }).$options.environment, 'browser');
    });

    it('should use io.js environment', () => {
      // v2 doesn't support "iojs"; behaviour is to leave it as-set (no validation).
      assert.equal(
        new NodeRSA(null, { environment: 'iojs' as 'node' }).$options.environment as string,
        'iojs',
      );
    });

    it('should make empty key pair with default options', () => {
      const key = new NodeRSA(null);
      assert.equal(key.isEmpty(), true);
      // v2.1: default signing scheme switched from 'pkcs1' to 'pss'.
      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, 'sha256');
      assert.equal(key.$options.signingSchemeOptions.saltLength, undefined);

      assert.equal(key.$options.encryptionScheme, 'pkcs1_oaep');
      assert.equal(key.$options.encryptionSchemeOptions.hash, 'sha1');
      assert.equal(key.$options.encryptionSchemeOptions.label, undefined);
    });

    it('should make key pair with pss-md5 signing scheme via bare-hash shorthand', () => {
      // Bare `'md5'` parses as "default scheme + md5 hash"; default switched
      // from 'pkcs1' to 'pss' in v2.1.
      const key = new NodeRSA(null, { signingScheme: 'md5' });
      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, 'md5');
    });

    it('should make key pair with pss-sha512 signing scheme', () => {
      const key = new NodeRSA(null, { signingScheme: 'pss-sha512' });
      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, 'sha512');
    });

    it('should make key pair with pkcs1 encryption scheme, and pss-sha1 signing scheme', () => {
      const key = new NodeRSA(null, { encryptionScheme: 'pkcs1', signingScheme: 'pss' });
      assert.equal(key.$options.encryptionScheme, 'pkcs1');
      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, undefined);
    });

    it('change options', () => {
      const key = new NodeRSA(null, { signingScheme: 'pss-sha1' });
      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, 'sha1');
      key.setOptions({ signingScheme: 'pkcs1' });
      assert.equal(key.$options.signingScheme, 'pkcs1');
      assert.equal(key.$options.signingSchemeOptions.hash, undefined);
      key.setOptions({ signingScheme: 'pkcs1-sha256' });
      assert.equal(key.$options.signingScheme, 'pkcs1');
      assert.equal(key.$options.signingSchemeOptions.hash, 'sha256');
    });

    it('advanced options change', () => {
      const key = new NodeRSA(null);
      key.setOptions({
        encryptionScheme: {
          scheme: 'pkcs1_oaep',
          hash: 'sha512',
          label: new TextEncoder().encode('horay'),
        },
        signingScheme: { scheme: 'pss', hash: 'md5', saltLength: 15 },
      });

      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, 'md5');
      assert.equal(key.$options.signingSchemeOptions.saltLength, 15);
      assert.equal(key.$options.encryptionScheme, 'pkcs1_oaep');
      assert.equal(key.$options.encryptionSchemeOptions.hash, 'sha512');
      assert.deepEqual(
        key.$options.encryptionSchemeOptions.label,
        new TextEncoder().encode('horay'),
      );
    });

    it("should throw 'unsupported hashing algorithm' exception", () => {
      const key = new NodeRSA(null);
      assert.equal(key.isEmpty(), true);
      assert.equal(key.$options.signingScheme, 'pss');
      assert.equal(key.$options.signingSchemeOptions.hash, 'sha256');
      assert.throws(() => {
        key.setOptions({ environment: 'browser', signingScheme: 'md4' });
      }, /Unsupported hashing algorithm/);
    });
  });

  describe('Base methods', () => {
    it('importKey() should throw exception if key data not specified', () => {
      const key = new NodeRSA(null);
      assert.throws(() => {
        (key as { importKey: (k?: unknown) => void }).importKey();
      }, /Empty key given/);
    });

    it('importKey() should return this', () => {
      const key = new NodeRSA(null);
      assert.equal(key.importKey(publicKeyPKCS8), key);
    });
  });

  describe('Work with keys', () => {
    describe('Generating keys', () => {
      for (const size of keySizes) {
        it(`should make key pair ${size.b}-bit length and public exponent is ${size.e ?? `${size.e} and should be 65537`}`, () => {
          const key = generatedKeys[keySizes.indexOf(size)];
          assert.isObject(key?.keyPair);
          assert.equal(key?.isEmpty(), false);
          assert.equal(key?.getKeySize(), size.b);
          assert.equal(key?.getMaxMessageSize(), size.b / 8 - 11);
          assert.equal(key?.keyPair.e, size.e ?? 65537);
        }, 35_000);
      }
    });

    describe('Import/Export keys', () => {
      const privateKeyPEMNotTrimmed = `random     \n\n data    \n\n ${privateKeyPKCS1}\n \n  \n\n random data `;
      const publicKeyPEMNotTrimmed = `\n\n\n\nrandom     \n\n data\n ${publicKeyPKCS8}\n \n random data\n\n  `;

      const fileKeyPKCS1 = readStr('private_pkcs1.pem').trim();
      const keys_formats: Record<string, { public: boolean; der: boolean; file: string }> = {
        'pkcs1-private-der': { public: false, der: true, file: 'private_pkcs1.der' },
        'pkcs1-private-pem': { public: false, der: false, file: 'private_pkcs1.pem' },
        'pkcs8-private-der': { public: false, der: true, file: 'private_pkcs8.der' },
        'pkcs8-private-pem': { public: false, der: false, file: 'private_pkcs8.pem' },
        'pkcs1-public-der': { public: true, der: true, file: 'public_pkcs1.der' },
        'pkcs1-public-pem': { public: true, der: false, file: 'public_pkcs1.pem' },
        'pkcs8-public-der': { public: true, der: true, file: 'public_pkcs8.der' },
        'pkcs8-public-pem': { public: true, der: false, file: 'public_pkcs8.pem' },
        private: { public: false, der: false, file: 'private_pkcs1.pem' },
        public: { public: true, der: false, file: 'public_pkcs8.pem' },
        'private-der': { public: false, der: true, file: 'private_pkcs1.der' },
        'public-der': { public: true, der: true, file: 'public_pkcs8.der' },
        pkcs1: { public: false, der: false, file: 'private_pkcs1.pem' },
        'pkcs1-private': { public: false, der: false, file: 'private_pkcs1.pem' },
        'pkcs1-der': { public: false, der: true, file: 'private_pkcs1.der' },
        pkcs8: { public: false, der: false, file: 'private_pkcs8.pem' },
        'pkcs8-private': { public: false, der: false, file: 'private_pkcs8.pem' },
        'pkcs8-der': { public: false, der: true, file: 'private_pkcs8.der' },
        'pkcs1-public': { public: true, der: false, file: 'public_pkcs1.pem' },
        'pkcs8-public': { public: true, der: false, file: 'public_pkcs8.pem' },
        'openssh-public': { public: true, der: false, file: 'id_rsa.pub' },
        'openssh-private': { public: false, der: false, file: 'id_rsa' },
      };

      describe('Good cases', () => {
        describe('Common cases', () => {
          it('should load private key from (not trimmed) PKCS1-PEM string', () => {
            privateNodeRSA = new NodeRSA(privateKeyPEMNotTrimmed);
            assert.isObject(privateNodeRSA.keyPair);
            assert(privateNodeRSA.isPrivate());
            assert(privateNodeRSA.isPublic());
            assert(!privateNodeRSA.isPublic(true));
          });

          it('should load public key from (not trimmed) PKCS8-PEM string', () => {
            publicNodeRSA = new NodeRSA(publicKeyPEMNotTrimmed);
            assert.isObject(publicNodeRSA.keyPair);
            assert(publicNodeRSA.isPublic());
            assert(publicNodeRSA.isPublic(true));
            assert(!publicNodeRSA.isPrivate());
          });

          it('.exportKey() should return private PEM string', () => {
            const exported = privateNodeRSA.exportKey('private') as string;
            assert.equal(stripWs(exported), stripWs(privateKeyPKCS1));
            const exportedDefault = privateNodeRSA.exportKey() as string;
            assert.equal(stripWs(exportedDefault), stripWs(privateKeyPKCS1));
          });

          it('.exportKey() from public key should return pkcs8 public PEM string', () => {
            assert.equal(
              stripWs(publicNodeRSA.exportKey('public') as string),
              stripWs(publicKeyPKCS8),
            );
          });

          it('.exportKey() from private key should return pkcs8 public PEM string', () => {
            assert.equal(
              stripWs(privateNodeRSA.exportKey('public') as string),
              stripWs(publicKeyPKCS8),
            );
          });

          it('should create and load key from buffer/fs.readFileSync output', () => {
            const buf = readFile('private_pkcs1.pem');
            const key1 = new NodeRSA(buf);
            assert.equal(stripWs(key1.exportKey() as string), stripWs(fileKeyPKCS1));
            const key2 = new NodeRSA();
            key2.importKey(buf);
            assert.equal(stripWs(key2.exportKey() as string), stripWs(fileKeyPKCS1));
          });

          it('should gracefully handle data outside of encapsulation boundaries for pkcs1 private keys', () => {
            const noisy = `Lorem ipsum${readStr('private_pkcs1.pem')}dulce et decorum`;
            const key = new NodeRSA(noisy);
            assert.equal(stripWs(key.exportKey() as string), stripWs(fileKeyPKCS1));
          });

          it('should gracefully handle data outside of encapsulation boundaries for pkcs1 public keys', () => {
            const noisy = `Lorem ipsum${readStr('public_pkcs1.pem')}dulce et decorum`;
            const pub = new NodeRSA(noisy);
            assert.isObject(pub.keyPair);
            assert(pub.isPublic());
            assert(pub.isPublic(true));
            assert(!pub.isPrivate());
          });

          it('should gracefully handle data outside of encapsulation boundaries for pkcs8 private keys', () => {
            const noisy = `Lorem ipsum${readStr('private_pkcs8.pem')}dulce et decorum`;
            const key = new NodeRSA(noisy);
            assert.equal(stripWs(key.exportKey() as string), stripWs(fileKeyPKCS1));
          });

          it('should gracefully handle data outside of encapsulation boundaries for pkcs8 public keys', () => {
            const noisy = `Lorem ipsum${readStr('public_pkcs8.pem')}dulce et decorum`;
            const pub = new NodeRSA(noisy);
            assert.isObject(pub.keyPair);
            assert(pub.isPublic());
            assert(pub.isPublic(true));
            assert(!pub.isPrivate());
          });

          it('should handle data without begin/end encapsulation boundaries for pkcs1 private keys', () => {
            const file = readStr('private_pkcs1.pem');
            const inner = file.substring(
              '-----BEGIN RSA PRIVATE KEY-----'.length,
              file.indexOf('-----END RSA PRIVATE KEY-----'),
            );
            const key = new NodeRSA(inner, 'pkcs1-private-pem');
            assert.equal(stripWs(key.exportKey() as string), stripWs(fileKeyPKCS1));
          });

          it('should handle data without begin/end encapsulation boundaries for pkcs1 public keys', () => {
            const file = readStr('public_pkcs1.pem');
            const inner = file.substring(
              '-----BEGIN RSA PUBLIC KEY-----'.length,
              file.indexOf('-----END RSA PUBLIC KEY-----'),
            );
            const pub = new NodeRSA(inner, 'pkcs1-public-pem');
            assert.isObject(pub.keyPair);
            assert(pub.isPublic());
            assert(pub.isPublic(true));
            assert(!pub.isPrivate());
          });

          it('should handle data without begin/end encapsulation boundaries for pkcs8 private keys', () => {
            const file = readStr('private_pkcs8.pem');
            const inner = file.substring(
              '-----BEGIN PRIVATE KEY-----'.length,
              file.indexOf('-----END PRIVATE KEY-----'),
            );
            const key = new NodeRSA(inner, 'pkcs8-private-pem');
            assert.equal(stripWs(key.exportKey() as string), stripWs(fileKeyPKCS1));
          });

          it('should handle data without begin/end encapsulation boundaries for pkcs8 public keys', () => {
            const file = readStr('public_pkcs8.pem');
            const inner = file.substring(
              '-----BEGIN PUBLIC KEY-----'.length,
              file.indexOf('-----END PUBLIC KEY-----'),
            );
            const pub = new NodeRSA(inner, 'pkcs8-public-pem');
            assert.isObject(pub.keyPair);
            assert(pub.isPublic());
            assert(pub.isPublic(true));
            assert(!pub.isPrivate());
          });

          it('.importKey() from private components', () => {
            const components = privateNodeRSA.exportKey('components') as Record<
              string,
              Uint8Array | number
            >;
            const key = new NodeRSA();
            key.importKey(components as unknown as object, 'components');
            assert(key.isPrivate());
            assert.equal(
              stripWs(key.exportKey('pkcs1-private') as string),
              stripWs(privateKeyPKCS1),
            );
            assert.equal(stripWs(key.exportKey('pkcs8-public') as string), stripWs(publicKeyPKCS8));
          });

          it('.importKey() from public components', () => {
            const components = publicNodeRSA.exportKey('components-public') as Record<
              string,
              Uint8Array | number
            >;
            const key = new NodeRSA();
            key.importKey(components as unknown as object, 'components-public');
            assert(key.isPublic(true));
            assert.equal(stripWs(key.exportKey('pkcs8-public') as string), stripWs(publicKeyPKCS8));
          });

          it('.exportKey() private components', () => {
            const key = new NodeRSA(privateKeyPKCS1);
            const c = key.exportKey('components') as { n: Uint8Array; e: number; d: Uint8Array };
            assert(c.n instanceof Uint8Array);
            assert.equal(c.e, 65537);
            assert(c.d instanceof Uint8Array);
          });

          it('.exportKey() public components', () => {
            const key = new NodeRSA(publicKeyPKCS8);
            const c = key.exportKey('components-public') as { n: Uint8Array; e: number };
            assert(c.n instanceof Uint8Array);
            assert.equal(c.e, 65537);
          });
        });

        describe('Different key formats', () => {
          const sampleKey = new NodeRSA(fileKeyPKCS1);
          for (const [format, options] of Object.entries(keys_formats)) {
            it(`should load from ${options.file} (${format})`, () => {
              const key = new NodeRSA(readFile(options.file), format);
              if (options.public) {
                assert.equal(
                  stripWs(key.exportKey('public') as string),
                  stripWs(sampleKey.exportKey('public') as string),
                );
              } else {
                assert.equal(
                  stripWs(key.exportKey() as string),
                  stripWs(sampleKey.exportKey() as string),
                );
              }
            });

            it(`should export to '${format}' format`, () => {
              const keyData = readFile(options.file);
              const exported = sampleKey.exportKey(format);
              if (options.der) {
                assert(exported instanceof Uint8Array);
                assert.equal(toHex(exported as Uint8Array), toHex(keyData));
              } else {
                assert(typeof exported === 'string');
                assert.equal(
                  (exported as string).replace(/\s+|\n\r|\n|\r$/gm, ''),
                  new TextDecoder().decode(keyData).replace(/\s+|\n\r|\n|\r$/gm, ''),
                );
              }
            });
          }
        });

        describe('OpenSSH keys', () => {
          it('key export should preserve key data including comment', () => {
            const opensshPrivateKey = readStr('id_rsa_comment');
            const opensshPublicKey = readStr('id_rsa_comment.pub');
            const opensshPriv = new NodeRSA(opensshPrivateKey);
            const opensshPub = new NodeRSA(opensshPublicKey);

            assert.equal(
              stripWs(opensshPriv.exportKey('openssh-private') as string),
              stripWs(opensshPrivateKey),
            );
            assert.equal(
              stripWs(opensshPriv.exportKey('openssh-public') as string),
              stripWs(opensshPublicKey),
            );
            assert.equal(
              stripWs(opensshPub.exportKey('openssh-public') as string),
              stripWs(opensshPublicKey),
            );
          });
        });
      });

      describe('Bad cases', () => {
        it('not public key', () => {
          const key = new NodeRSA();
          assert.throws(() => key.exportKey(), /This is not private key/);
          assert.throws(() => key.exportKey('public'), /This is not public key/);
        });

        it('not private key', () => {
          const key = new NodeRSA(publicKeyPKCS8);
          assert.throws(() => key.exportKey(), /This is not private key/);
          assert.doesNotThrow(() => key.exportKey('public'));
        });
      });
    });
  });

  describe('Encrypting & decrypting', () => {
    for (const env of environments) {
      for (const scheme of encryptSchemes) {
        const schemeLabel = typeof scheme === 'string' ? scheme : scheme.toString();
        describe(`Environment: ${env}. Encryption scheme: ${schemeLabel}`, () => {
          describe('Good cases', () => {
            const encrypted: Record<string, Uint8Array> = {};
            for (const [name, suit] of Object.entries(dataBundle)) {
              it(`\`encrypt()\` should encrypt ${name}`, () => {
                const idx = Math.floor(Math.random() * generatedKeys.length);
                const sourceKey = generatedKeys[idx] as NodeRSA;
                const key = new NodeRSA(sourceKey.exportKey(), {
                  environment: env,
                  encryptionScheme: scheme as 'pkcs1',
                });
                const result = key.encrypt(suit.data);
                assert(result instanceof Uint8Array);
                assert((result as Uint8Array).length > 0);
                encrypted[name] = result as Uint8Array;
              });

              it(`\`decrypt()\` should decrypt ${name}`, () => {
                const idx = Math.floor(Math.random() * generatedKeys.length);
                const sourceKey = generatedKeys[idx] as NodeRSA;
                const key = new NodeRSA(sourceKey.exportKey(), {
                  environment: env,
                  encryptionScheme: scheme as 'pkcs1',
                });
                const reEncrypted = key.encrypt(suit.data) as Uint8Array;
                const enc = Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding;
                const dec = key.decrypt(reEncrypted, enc);
                if (dec instanceof Uint8Array) {
                  assert.equal(asHex(suit.data), asHex(dec));
                } else {
                  assert.deepEqual(suit.data, dec);
                }
              });
            }
          });

          describe('Bad cases', () => {
            it('unsupported data types', () => {
              const key = generatedKeys[0] as NodeRSA;
              assert.throws(
                () => key.encrypt(null as unknown as string),
                /Error during encryption/,
              );
              assert.throws(
                () => key.encrypt(undefined as unknown as string),
                /Error during encryption/,
              );
              assert.throws(
                () => key.encrypt(true as unknown as string),
                /Error during encryption/,
              );
            });

            it('incorrect key for decrypting', () => {
              const k0 = generatedKeys[0] as NodeRSA;
              const k1 = generatedKeys[1] as NodeRSA;
              const encrypted = k0.encrypt('data') as Uint8Array;
              assert.throws(() => k1.decrypt(encrypted), /Error during decryption/);
            });
          });
        });
      }

      describe(`Environment: ${env}. encryptPrivate & decryptPublic`, () => {
        for (const [name, suit] of Object.entries(dataBundle)) {
          it(`\`encryptPrivate()\` should encrypt ${name}`, () => {
            const idx = Math.floor(Math.random() * generatedKeys.length);
            const src = generatedKeys[idx] as NodeRSA;
            const key = new NodeRSA(src.exportKey(), { environment: env });
            const result = key.encryptPrivate(suit.data);
            assert(result instanceof Uint8Array);
            assert((result as Uint8Array).length > 0);
          });

          it(`\`decryptPublic()\` should decrypt ${name}`, () => {
            const idx = Math.floor(Math.random() * generatedKeys.length);
            const src = generatedKeys[idx] as NodeRSA;
            const key = new NodeRSA(src.exportKey(), { environment: env });
            const enc = key.encryptPrivate(suit.data) as Uint8Array;
            const encStr = Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding;
            const dec = key.decryptPublic(enc, encStr);
            if (dec instanceof Uint8Array) {
              assert.equal(asHex(suit.data), asHex(dec));
            } else {
              assert.deepEqual(suit.data, dec);
            }
          });
        }
      });
    }

    // ── Cross-environment compatibility ────────────────────────────────────
    // JsEngine (forced when env='browser') and NodeNativeEngine (env='node')
    // must produce interoperable ciphertexts for the same key.
    //
    // The legacy used `(function (i) { var key1, key2; it(...); it(...); })(i)`
    // — an IIFE per data-bundle iteration — so each (encrypt, decrypt) pair
    // had its own key1/key2. We get the same effect by declaring `let` bindings
    // *inside* the for-of body: ES6 block scoping gives each iteration fresh
    // bindings, and the encrypt/decrypt it() callbacks both close over the
    // iteration-local pair. Without this, random key picking across iterations
    // overwrites the shared variables and the decrypt test reads a key that
    // doesn't match the ciphertext.
    describe('Compatibility of different environments', () => {
      for (const scheme of encryptSchemes) {
        const schemeLabel = typeof scheme === 'string' ? scheme : scheme.toString();

        // browser-encrypt → node-decrypt
        for (const [name, suit] of Object.entries(dataBundle)) {
          let key2A: NodeRSA;
          let encryptedA: Uint8Array;
          it(`Encryption scheme: ${schemeLabel} \`encrypt()\` by browser ${name}`, () => {
            const idx = Math.floor(Math.random() * generatedKeys.length);
            const sourceKey = (generatedKeys[idx] as NodeRSA).exportKey();
            const key1 = new NodeRSA(sourceKey, {
              environment: 'browser',
              encryptionScheme: scheme as 'pkcs1',
            });
            key2A = new NodeRSA(sourceKey, {
              environment: 'node',
              encryptionScheme: scheme as 'pkcs1',
            });
            encryptedA = key1.encrypt(suit.data) as Uint8Array;
            assert(encryptedA instanceof Uint8Array);
            assert(encryptedA.length > 0);
          });

          it(`Encryption scheme: ${schemeLabel} \`decrypt()\` by node ${name}`, () => {
            const enc = Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding;
            const dec = key2A.decrypt(encryptedA, enc);
            if (dec instanceof Uint8Array) {
              assert.equal(asHex(suit.data), asHex(dec));
            } else {
              assert.deepEqual(suit.data, dec);
            }
          });
        }

        // node-encrypt → browser-decrypt
        for (const [name, suit] of Object.entries(dataBundle)) {
          let key2B: NodeRSA;
          let encryptedB: Uint8Array;
          it(`Encryption scheme: ${schemeLabel} \`encrypt()\` by node ${name}. Scheme`, () => {
            const idx = Math.floor(Math.random() * generatedKeys.length);
            const sourceKey = (generatedKeys[idx] as NodeRSA).exportKey();
            const key1 = new NodeRSA(sourceKey, {
              environment: 'node',
              encryptionScheme: scheme as 'pkcs1',
            });
            key2B = new NodeRSA(sourceKey, {
              environment: 'browser',
              encryptionScheme: scheme as 'pkcs1',
            });
            encryptedB = key1.encrypt(suit.data) as Uint8Array;
            assert(encryptedB instanceof Uint8Array);
            assert(encryptedB.length > 0);
          });

          it(`Encryption scheme: ${schemeLabel} \`decrypt()\` by browser ${name}`, () => {
            const enc = Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding;
            const dec = key2B.decrypt(encryptedB, enc);
            if (dec instanceof Uint8Array) {
              assert.equal(asHex(suit.data), asHex(dec));
            } else {
              assert.deepEqual(suit.data, dec);
            }
          });
        }
      }

      describe('encryptPrivate & decryptPublic', () => {
        // browser-encryptPrivate → node-decryptPublic
        for (const [name, suit] of Object.entries(dataBundle)) {
          let key2C: NodeRSA;
          let encryptedC: Uint8Array;
          it(`\`encryptPrivate()\` by browser ${name}`, () => {
            const idx = Math.floor(Math.random() * generatedKeys.length);
            const sourceKey = (generatedKeys[idx] as NodeRSA).exportKey();
            const key1 = new NodeRSA(sourceKey, { environment: 'browser' });
            key2C = new NodeRSA(sourceKey, { environment: 'node' });
            encryptedC = key1.encryptPrivate(suit.data) as Uint8Array;
            assert(encryptedC instanceof Uint8Array);
            assert(encryptedC.length > 0);
          });

          it(`\`decryptPublic()\` by node ${name}`, () => {
            const enc = Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding;
            const dec = key2C.decryptPublic(encryptedC, enc);
            if (dec instanceof Uint8Array) {
              assert.equal(asHex(suit.data), asHex(dec));
            } else {
              assert.deepEqual(suit.data, dec);
            }
          });
        }

        // node-encryptPrivate → browser-decryptPublic
        for (const [name, suit] of Object.entries(dataBundle)) {
          let key2D: NodeRSA;
          let encryptedD: Uint8Array;
          it(`\`encryptPrivate()\` by node ${name}`, () => {
            const idx = Math.floor(Math.random() * generatedKeys.length);
            const sourceKey = (generatedKeys[idx] as NodeRSA).exportKey();
            // Note: legacy uses environment:'browser' for key1 in this loop
            // too — looks like a v1 test bug; porting verbatim.
            const key1 = new NodeRSA(sourceKey, { environment: 'browser' });
            key2D = new NodeRSA(sourceKey, { environment: 'node' });
            encryptedD = key1.encryptPrivate(suit.data) as Uint8Array;
            assert(encryptedD instanceof Uint8Array);
            assert(encryptedD.length > 0);
          });

          it(`\`decryptPublic()\` by browser ${name}`, () => {
            const enc = Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding;
            const dec = key2D.decryptPublic(encryptedD, enc);
            if (dec instanceof Uint8Array) {
              assert.equal(asHex(suit.data), asHex(dec));
            } else {
              assert.deepEqual(suit.data, dec);
            }
          });
        }
      });
    });
  });

  describe('Signing & verifying', () => {
    for (const scheme of signingSchemes) {
      describe(`Signing scheme: ${scheme}`, () => {
        const envs: Array<'node' | 'browser'> = scheme === 'pkcs1' ? ['node', 'browser'] : ['node'];

        for (const env of envs) {
          describe(`Good cases${envs.length > 1 ? ` in ${env} environment` : ''}`, () => {
            for (const [name, suit] of Object.entries(dataBundle)) {
              it(`should sign ${name}`, () => {
                const sourceKey = generatedKeys[generatedKeys.length - 1] as NodeRSA;
                const key = new NodeRSA(sourceKey.exportKey(), {
                  signingScheme: `${scheme}-sha256`,
                  environment: env,
                });
                const signed = key.sign(suit.data);
                assert(signed instanceof Uint8Array);
                assert((signed as Uint8Array).length > 0);
              });

              it(`should verify ${name}`, () => {
                const sourceKey = generatedKeys[generatedKeys.length - 1] as NodeRSA;
                const key = new NodeRSA(sourceKey.exportKey(), {
                  signingScheme: `${scheme}-sha256`,
                  environment: env,
                });
                const signed = key.sign(suit.data) as Uint8Array;
                assert(key.verify(suit.data, signed));
              });
            }

            for (const alg of signHashAlgorithms[env]) {
              it.skipIf(shouldSkip(alg))(`signing with custom algorithm (${alg})`, () => {
                const sourceKey = generatedKeys[generatedKeys.length - 1] as NodeRSA;
                const key = new NodeRSA(sourceKey.exportKey(), {
                  signingScheme: `${scheme}-${alg}`,
                  environment: env,
                });
                const signed = key.sign('data');
                assert(key.verify('data', signed as Uint8Array));
              });

              if (scheme === 'pss') {
                it.skipIf(shouldSkip(alg))(
                  `signing with custom algorithm (${alg}) with max salt length`,
                  () => {
                    const a = alg.toLowerCase() as HashAlg;
                    const sourceKey = generatedKeys[generatedKeys.length - 1] as NodeRSA;
                    const key = new NodeRSA(sourceKey.exportKey(), {
                      signingScheme: { scheme: scheme, hash: a, saltLength: DIGEST_LENGTH[a] },
                      environment: env,
                    });
                    const signed = key.sign('data');
                    assert(key.verify('data', signed as Uint8Array));
                  },
                );
              }
            }
          });

          describe(`Bad cases${envs.length > 1 ? ` in ${env} environment` : ''}`, () => {
            it('incorrect data for verifying', () => {
              const src = generatedKeys[0] as NodeRSA;
              const key = new NodeRSA(src.exportKey(), {
                signingScheme: `${scheme}-sha256`,
                environment: env,
              });
              const signed = key.sign('data1');
              assert(!key.verify('data2', signed as Uint8Array));
            });

            it('incorrect key for signing', () => {
              const src = generatedKeys[0] as NodeRSA;
              const key = new NodeRSA(src.exportKey('pkcs8-public'), {
                signingScheme: `${scheme}-sha256`,
                environment: env,
              });
              assert.throws(() => key.sign('data'), /This is not private key/);
            });

            it('incorrect key for verifying', () => {
              const src0 = generatedKeys[0] as NodeRSA;
              const src1 = generatedKeys[1] as NodeRSA;
              const key1 = new NodeRSA(src0.exportKey(), {
                signingScheme: `${scheme}-sha256`,
                environment: env,
              });
              const key2 = new NodeRSA(src1.exportKey('pkcs8-public'), {
                signingScheme: `${scheme}-sha256`,
                environment: env,
              });
              const signed = key1.sign('data');
              assert(!key2.verify('data', signed as Uint8Array));
            });

            it('incorrect key for verifying (empty)', () => {
              const key = new NodeRSA(null, { environment: env });
              assert.throws(() => key.verify('data', 'somesignature'), /This is not public key/);
            });

            it('different algorithms', () => {
              const src = generatedKeys[0] as NodeRSA;
              const signKey = new NodeRSA(src.exportKey(), {
                signingScheme: `${scheme}-md5`,
                environment: env,
              });
              const verifyKey = new NodeRSA(src.exportKey(), {
                signingScheme: `${scheme}-sha1`,
                environment: env,
              });
              const signed = signKey.sign('data');
              assert(!verifyKey.verify('data', signed as Uint8Array));
            });
          });
        }

        // ── Cross-environment compatibility ────────────────────────────────
        // PSS uses a random salt, so cross-env signature bytes don't match.
        // Only PKCS#1 v1.5 (deterministic) gets cross-env equality testing.
        if (scheme !== 'pkcs1') return;

        describe('Compatibility of different environments', () => {
          for (const alg of signHashAlgorithms.browser) {
            it.skipIf(shouldSkip(alg))(
              `signing with custom algorithm (${alg}) (equal test)`,
              () => {
                const sourceKey = (generatedKeys[5] as NodeRSA).exportKey();
                const nodeKey = new NodeRSA(sourceKey, {
                  signingScheme: `${scheme}-${alg}`,
                  environment: 'node',
                });
                const browserKey = new NodeRSA(sourceKey, {
                  signingScheme: `${scheme}-${alg}`,
                  environment: 'browser',
                });
                assert.equal(nodeKey.sign('data', 'hex'), browserKey.sign('data', 'hex'));
              },
            );

            it.skipIf(shouldSkip(alg))(`sign in node & verify in browser (${alg})`, () => {
              const sourceKey = (generatedKeys[5] as NodeRSA).exportKey();
              const nodeKey = new NodeRSA(sourceKey, {
                signingScheme: `${scheme}-${alg}`,
                environment: 'node',
              });
              const browserKey = new NodeRSA(sourceKey, {
                signingScheme: `${scheme}-${alg}`,
                environment: 'browser',
              });
              assert(browserKey.verify('data', nodeKey.sign('data') as Uint8Array));
            });

            it.skipIf(shouldSkip(alg))(`sign in browser & verify in node (${alg})`, () => {
              const sourceKey = (generatedKeys[5] as NodeRSA).exportKey();
              const nodeKey = new NodeRSA(sourceKey, {
                signingScheme: `${scheme}-${alg}`,
                environment: 'node',
              });
              const browserKey = new NodeRSA(sourceKey, {
                signingScheme: `${scheme}-${alg}`,
                environment: 'browser',
              });
              assert(nodeKey.verify('data', browserKey.sign('data') as Uint8Array));
            });
          }
        });
      });
    }
  });
});

function stripWs(s: string): string {
  return s.replace(/\s+/g, '');
}

// Suppress unused import warning
void bytesFromBase64;
