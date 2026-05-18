import type { HashingAlgorithm } from './types.js';

export const DIGEST_LENGTH: Readonly<Record<HashingAlgorithm, number>> = Object.freeze({
  md4: 16,
  md5: 16,
  ripemd160: 20,
  sha1: 20,
  sha224: 28,
  sha256: 32,
  sha384: 48,
  sha512: 64,
});
