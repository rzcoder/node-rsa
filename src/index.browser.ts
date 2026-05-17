import { setBigIntegerImpl } from './bigint/big-integer.js';
import { webBackend } from './crypto/backend.web.js';
import { NodeRSA, bootstrap } from './node-rsa.js';

// Modern browsers (Chrome 67+, Firefox 68+, Safari 14+, Edge 79+) support
// native BigInt. The selector falls back to jsbn silently if `BigInt` is
// missing, so this is safe everywhere. Callers can flip back via
// `setBigIntegerImpl('jsbn')` before constructing any NodeRSA instance.
setBigIntegerImpl('native');

bootstrap({
  environment: 'browser',
  backend: webBackend,
  // Browser bundle ships only the pure-JS engine — there is no node:crypto.
});

export { NodeRSA };
export default NodeRSA;
// Browser bundle defaults to native BigInt (with silent jsbn fallback on
// runtimes without globalThis.BigInt). Users who need to force one or the
// other pass `{ bigIntImpl: 'jsbn' | 'native' }` to the NodeRSA constructor
// or to setOptions BEFORE the key is imported/generated.
export * from './types.js';
