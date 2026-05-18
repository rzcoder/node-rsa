import { bench, describe } from 'vitest';
import { buildKey, ctorOptionsFor, MODES, NodeRSA, PAYLOAD } from './fixtures.js';

// One canonical configuration — 2048-bit RSA, SHA-256, 32B input — so the
// matrix is "environment vs typical operation" and nothing else:
//
//   keygen / encrypt / decrypt / sign / verify
//
// Each `describe` is one operation. The benches inside are the modes that
// run in this workspace project (node project: node-native + node-js;
// browser project: browser). Vitest's per-describe summary then compares
// modes against each other for the SAME operation — which is the only
// comparison worth printing.
describe('keygen 2048-bit', () => {
  for (const mode of MODES) {
    const pin = ctorOptionsFor(mode);
    bench(
      mode,
      () => {
        // Pin the impl via constructor options BEFORE generateKeyPair — the
        // BigInteger swap must happen before any prime-search arithmetic.
        const k = pin ? new NodeRSA(null, pin) : new NodeRSA();
        k.generateKeyPair(2048);
      },
      { iterations: 5, time: 60_000, warmupIterations: 0, warmupTime: 0 },
    );
  }
});

describe('encrypt OAEP-SHA256 2048-bit', () => {
  for (const mode of MODES) {
    const key = buildKey(mode, { kind: 'enc', scheme: 'pkcs1_oaep', hash: 'sha256' });
    bench(mode, () => {
      key.encrypt(PAYLOAD);
    });
  }
});

describe('decrypt OAEP-SHA256 2048-bit', () => {
  for (const mode of MODES) {
    const key = buildKey(mode, { kind: 'enc', scheme: 'pkcs1_oaep', hash: 'sha256' });
    const ct = key.encrypt(PAYLOAD) as Uint8Array;
    bench(mode, () => {
      key.decrypt(ct);
    });
  }
});

describe('sign PSS-SHA256 2048-bit', () => {
  for (const mode of MODES) {
    const key = buildKey(mode, { kind: 'sign', scheme: 'pss', hash: 'sha256' });
    bench(mode, () => {
      key.sign(PAYLOAD);
    });
  }
});

describe('verify PSS-SHA256 2048-bit', () => {
  for (const mode of MODES) {
    const key = buildKey(mode, { kind: 'sign', scheme: 'pss', hash: 'sha256' });
    const sig = key.sign(PAYLOAD) as Uint8Array;
    bench(mode, () => {
      key.verify(PAYLOAD, sig);
    });
  }
});
