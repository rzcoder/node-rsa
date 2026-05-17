import NodeRSA from 'node-rsa-bench-entry';

// Three distinct math implementations:
//
//   node      → node:crypto everywhere (OpenSSL primitives; BigInteger unused).
//   js-jsbn   → JS engine + JS schemes + jsbn BigInteger (28-bit digits).
//   js-native → JS engine + JS schemes + native ES2020 BigInt.
//
// Digest/RNG backend is always native to the runtime (node:crypto in Node,
// crypto.getRandomValues + @noble/hashes in browser), so it isn't a separate
// comparison axis here.
export type Mode = 'node' | 'js-jsbn' | 'js-native';

const RAW_MODES = process.env.NODE_RSA_BENCH_MODES ?? 'node';
export const MODES: ReadonlyArray<Mode> = RAW_MODES.split(',').map((s) => s.trim()) as Mode[];

// One canonical payload (32B) — typical RSA input (digest, symmetric key,
// short message). Larger payloads / chunking aren't the comparison the
// suite is for.
export const PAYLOAD = new Uint8Array(32).map((_, i) => i & 0xff);

// One canonical key size — 2048-bit is the industry baseline. Fresh per
// process, memoized so the bench measures crypto ops, not keygen.
let _key2048: NodeRSA | undefined;
export function key2048(): NodeRSA {
  if (!_key2048) _key2048 = new NodeRSA({ b: 2048 });
  return _key2048;
}

/** Constructor options that pin a NodeRSA instance to the requested mode. */
export function ctorOptionsFor(
  mode: Mode,
): { environment: 'browser'; bigIntImpl: 'jsbn' | 'native' } | undefined {
  if (mode === 'js-jsbn') return { environment: 'browser', bigIntImpl: 'jsbn' };
  if (mode === 'js-native') return { environment: 'browser', bigIntImpl: 'native' };
  // 'node': node bundle defaults (no override needed).
  return undefined;
}

/**
 * Build a configured NodeRSA for the given (mode, scheme). Re-imports the
 * shared 2048-bit key as PKCS1-PEM with the mode's pinning options applied
 * via the constructor — bigIntImpl must be set BEFORE key components are
 * built, so setOptions on a populated key would throw.
 */
export function buildKey(
  mode: Mode,
  opts: { scheme: 'pkcs1' | 'pkcs1_oaep' | 'pss'; hash: string; kind: 'enc' | 'sign' },
): NodeRSA {
  const pem = key2048().exportKey('pkcs1-private-pem') as string;
  const pin = ctorOptionsFor(mode);
  const key = pin
    ? new NodeRSA(pem, 'pkcs1-private-pem', pin)
    : new NodeRSA(pem, 'pkcs1-private-pem');
  if (opts.kind === 'enc') {
    key.setOptions({
      encryptionScheme: { scheme: opts.scheme as 'pkcs1' | 'pkcs1_oaep', hash: opts.hash as never },
    });
  } else {
    key.setOptions({
      signingScheme: { scheme: opts.scheme as 'pkcs1' | 'pss', hash: opts.hash as never },
    });
  }
  return key;
}

export { NodeRSA };
