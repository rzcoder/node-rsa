import type { RSAKey } from '../rsa/key.js';
import { oaepScheme } from './oaep.js';
import { RSA_NO_PADDING, pkcs1Scheme } from './pkcs1.js';
import { pssScheme } from './pss.js';
import type { SchemeOptions } from './types.js';

export interface SchemeProvider {
  isEncryption: boolean;
  isSignature: boolean;
  makeScheme(key: RSAKey, options: SchemeOptions): unknown;
}

export const SCHEMES: Record<string, SchemeProvider> = {
  pkcs1: pkcs1Scheme,
  pkcs1_oaep: oaepScheme,
  pss: pssScheme,
};

export { RSA_NO_PADDING };
export { oaepScheme, pkcs1Scheme, pssScheme };
export type {
  EncryptionSchemeImpl,
  EncryptionSchemeOptions,
  MaskGenerationFunction,
  SchemeOptions,
  SignatureScheme,
  SigningSchemeOptions,
} from './types.js';
