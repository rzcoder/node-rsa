import type { CryptoBackend } from '../crypto/types.js';
import {
  BigInteger as JsbnBigInteger,
  setBigIntegerBackend as setJsbnBackend,
} from './big-integer-jsbn.js';
import {
  BigInteger as NativeBigInteger,
  setBigIntegerBackend as setNativeBackend,
} from './big-integer-native.js';

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
