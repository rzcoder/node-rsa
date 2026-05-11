import { describe, expect, it } from 'vitest';
import { nodeBackend } from '../../src/crypto/backend.node.js';

// `nodeBackend` is aliased to webBackend in the browser-emulated project.
// Tests below exercise the active backend's randomBytes regardless.

describe('randomBytes', () => {
  it('returns a Uint8Array of the requested size', () => {
    for (const n of [0, 1, 16, 32, 100, 1024]) {
      const bytes = nodeBackend.randomBytes(n);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(n);
    }
  });

  it('produces different outputs across calls (sanity check)', () => {
    const a = nodeBackend.randomBytes(32);
    const b = nodeBackend.randomBytes(32);
    // 256-bit collision probability is negligible
    let same = true;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        same = false;
        break;
      }
    }
    expect(same).toBe(false);
  });

  it('handles requests larger than a single getRandomValues chunk', () => {
    // Web Crypto getRandomValues caps at 65536 bytes per call; backend chunks.
    const big = nodeBackend.randomBytes(200_000);
    expect(big.length).toBe(200_000);
    // First and last byte are independent samples; should generally differ across runs.
    const big2 = nodeBackend.randomBytes(200_000);
    expect(big[0] === big2[0] && big[big.length - 1] === big2[big2.length - 1]).toBe(false);
  });
});
