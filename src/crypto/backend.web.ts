import { md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import type { CryptoBackend, HashingAlgorithm } from './types.js';

type HashFn = (data: Uint8Array) => Uint8Array;

const HASHES: Readonly<Record<Exclude<HashingAlgorithm, 'md4'>, HashFn>> = {
  md5: (d) => md5(d),
  ripemd160: (d) => ripemd160(d),
  sha1: (d) => sha1(d),
  sha224: (d) => sha224(d),
  sha256: (d) => sha256(d),
  sha384: (d) => sha384(d),
  sha512: (d) => sha512(d),
};

function getWebCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error(
      'Web Crypto getRandomValues unavailable. Are you running in an environment without secure RNG?',
    );
  }
  return c;
}

export const webBackend: CryptoBackend = {
  name: 'web',

  randomBytes(n) {
    const out = new Uint8Array(n);
    let off = 0;
    const c = getWebCrypto();
    while (off < n) {
      const chunk = Math.min(n - off, 65536);
      c.getRandomValues(out.subarray(off, off + chunk));
      off += chunk;
    }
    return out;
  },

  digest(alg, data) {
    if (alg === 'md4') {
      throw new Error('MD4 is not supported in the browser backend (Node-only)');
    }
    const fn = HASHES[alg];
    if (!fn) throw new Error(`Unsupported hash algorithm: ${alg}`);
    return fn(data);
  },

  supportsHash(alg) {
    return alg !== 'md4' && alg in HASHES;
  },
};
