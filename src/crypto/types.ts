export type HashingAlgorithm =
  | 'md4'
  | 'md5'
  | 'ripemd160'
  | 'sha1'
  | 'sha224'
  | 'sha256'
  | 'sha384'
  | 'sha512';

export interface CryptoBackend {
  readonly name: 'node' | 'web';

  randomBytes(n: number): Uint8Array;

  digest(alg: HashingAlgorithm, data: Uint8Array): Uint8Array;

  supportsHash(alg: HashingAlgorithm): boolean;
}
