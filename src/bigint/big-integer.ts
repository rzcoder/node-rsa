import type { CryptoBackend } from '../crypto/types.js';
import {
  BigInteger as JsbnBigInteger,
  setBigIntegerBackend as setJsbnBackend,
} from './big-integer-jsbn.js';
import {
  BigInteger as NativeBigInteger,
  setBigIntegerBackend as setNativeBackend,
} from './big-integer-native.js';

// ============================================================================
// BigInteger implementation selector.
//
// ESM live-binding pattern: `export let BigInteger` updates everywhere
// importers reference it once we call `setBigIntegerImpl(...)`. Importers do
// `new BigInteger(...)` and `BigInteger.ONE`; both honour the latest value
// because property access happens at call site, not import.
//
// Per-bundle defaults (set at module-load time of the entry):
//   - src/index.node.ts      → leaves jsbn (proven, audited)
//   - src/index.browser.ts   → setBigIntegerImpl('native') (native BigInt
//                              is universally supported in modern browsers;
//                              silently falls back to jsbn on runtimes
//                              without BigInt)
//
// End-user override: `setBigIntegerImpl('jsbn' | 'native')` is re-exported
// from the package entries. Must be called BEFORE constructing any NodeRSA
// instance — once `new BigInteger(...)` has run, subsequent instances built
// after a swap will use the new impl, but already-built numbers keep their
// old class identity.
// ============================================================================

export type BigIntegerImpl = 'jsbn' | 'native';

// The instance type stays jsbn-shaped at the type level (both impls satisfy
// the same public surface); a single `BigInteger` identifier serves as both
// value (live binding to the active class) and type alias for instances.
export type BigInteger = JsbnBigInteger;
export let BigInteger: typeof JsbnBigInteger = JsbnBigInteger;

let _currentImpl: BigIntegerImpl = 'jsbn';
let _currentBackend: CryptoBackend | undefined;

/**
 * Switch the active BigInteger implementation. `'native'` falls back to
 * `'jsbn'` silently if `globalThis.BigInt` is unavailable.
 */
export function setBigIntegerImpl(impl: BigIntegerImpl): BigIntegerImpl {
  if (impl === 'native' && typeof BigInt === 'function') {
    BigInteger = NativeBigInteger as unknown as typeof JsbnBigInteger;
    _currentImpl = 'native';
  } else {
    BigInteger = JsbnBigInteger;
    _currentImpl = 'jsbn';
  }
  // Re-apply the most recent backend to both impls so the next prime search
  // works regardless of which one the user just flipped to.
  if (_currentBackend) {
    setJsbnBackend(_currentBackend);
    setNativeBackend(_currentBackend);
  }
  return _currentImpl;
}

export function getBigIntegerImpl(): BigIntegerImpl {
  return _currentImpl;
}

/**
 * Inject the crypto backend that BigInteger uses for RNG (primality
 * testing). Applied to both impls so a later `setBigIntegerImpl` doesn't
 * lose the binding.
 */
export function setBigIntegerBackend(backend: CryptoBackend): void {
  _currentBackend = backend;
  setJsbnBackend(backend);
  setNativeBackend(backend);
}
