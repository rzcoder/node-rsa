import type { RSAKey } from '../rsa/key.js';
import { oaepScheme } from './oaep.js';
import { pkcs1Scheme, RSA_NO_PADDING } from './pkcs1.js';
import { pssScheme } from './pss.js';
import type { EncryptionSchemeImpl, SchemeOptions, SignatureScheme } from './types.js';

export interface SchemeProvider {
  isEncryption: boolean;
  isSignature: boolean;
  makeScheme(key: RSAKey, options: SchemeOptions): EncryptionSchemeImpl | SignatureScheme;
}

export const SCHEMES: Record<string, SchemeProvider> = {
  pkcs1: pkcs1Scheme,
  pkcs1_oaep: oaepScheme,
  pss: pssScheme,
};

export type {
  EncryptionSchemeImpl,
  EncryptionSchemeOptions,
  MaskGenerationFunction,
  SchemeOptions,
  SignatureScheme,
  SigningSchemeOptions,
} from './types.js';
export { oaepScheme, pkcs1Scheme, pssScheme, RSA_NO_PADDING };
