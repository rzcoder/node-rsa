import { nodeBackend } from './crypto/backend.node.js';
import { NodeRSA, bootstrap } from './node-rsa.js';
import { JsEngine } from './rsa/engine.js';
import { NodeNativeEngine } from './rsa/native-engine.js';
import type { ResolvedOptions } from './types.js';

bootstrap({
  environment: 'node',
  backend: nodeBackend,
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
export * from './types.js';
