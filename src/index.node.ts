import { nodeBackend } from './crypto/backend.node.js';
import { NodeRSA, bootstrap } from './node-rsa.js';
import { JsEngine } from './rsa/engine.js';
import { NodeNativeEngine } from './rsa/native-engine.js';
import { nodeNativeKeygen } from './rsa/native-keygen.js';
import { nodeNativeSchemes } from './rsa/native-signatures.js';
import type { ResolvedOptions } from './types.js';

bootstrap({
  environment: 'node',
  backend: nodeBackend,
  // node:crypto.generateKeyPairSync — ~50× faster than RSAKey.generate
  // for 2048-bit keys, used unless the caller forces environment:'browser'.
  keygenFor: nodeNativeKeygen,
  // PKCS#1 v1.5 and PSS sign/verify go through node:crypto.sign / verify.
  // OAEP is unchanged here — the encrypt side is already handled by
  // NodeNativeEngine below.
  schemes: nodeNativeSchemes,
  engineFor: (key, options: ResolvedOptions) => {
    // Native path supports the two padding schemes node:crypto knows about.
    // For everything else (and for setOptions({environment:'browser'}) which
    // is checked at the call site), fall back to the JS engine.
    if (options.encryptionScheme === 'pkcs1' || options.encryptionScheme === 'pkcs1_oaep') {
      return new NodeNativeEngine(key, options);
    }
    return new JsEngine(key);
  },
});

export { NodeRSA };
export default NodeRSA;
// Node bundle defaults to the jsbn BigInteger impl. Users who want native
// BigInt instead pass `{ bigIntImpl: 'native' }` to the NodeRSA constructor
// or to setOptions BEFORE the key is imported/generated.
export * from './types.js';
