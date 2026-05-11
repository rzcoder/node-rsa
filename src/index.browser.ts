import { webBackend } from './crypto/backend.web.js';
import { NodeRSA, bootstrap } from './node-rsa.js';

bootstrap({
  environment: 'browser',
  backend: webBackend,
  // Browser bundle ships only the pure-JS engine — there is no node:crypto.
});

export { NodeRSA };
export default NodeRSA;
export * from './types.js';
