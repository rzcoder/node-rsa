import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import type { CryptoBackend, HashingAlgorithm } from './types.js';

// MD4 lives in OpenSSL's legacy provider, which is not loaded by default in
// OpenSSL 3 (Node 17+). Probe once at module load to decide if it's usable.
const CANDIDATE: readonly HashingAlgorithm[] = [
  'md4',
  'md5',
  'ripemd160',
  'sha1',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
];

const SUPPORTED: ReadonlySet<HashingAlgorithm> = (() => {
  const set = new Set<HashingAlgorithm>();
  for (const alg of CANDIDATE) {
    try {
      createHash(alg);
      set.add(alg);
    } catch {
      // Skip: provider not loaded (e.g., MD4 in OpenSSL 3).
    }
  }
  return set;
})();

function bufferToU8(buf: Uint8Array): Uint8Array {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export const nodeBackend: CryptoBackend = {
  name: 'node',

  randomBytes(n) {
    return bufferToU8(nodeRandomBytes(n));
  },

  digest(alg, data) {
    if (!SUPPORTED.has(alg)) {
      throw new Error(`Unsupported hash algorithm: ${alg}`);
    }
    const h = createHash(alg);
    h.update(data);
    return bufferToU8(h.digest());
  },

  supportsHash(alg) {
    return SUPPORTED.has(alg);
  },
};
