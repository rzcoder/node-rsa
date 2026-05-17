import { fromBase64, toBase64 } from '../crypto/bytes.js';
import { linebrk, trimSurroundingText } from '../utils/text-utils.js';
import type { ImportOptions } from './types.js';

/** Wrap raw DER bytes in a PEM container (base64 body line-wrapped at `lineLength`, default 64). */
export function encodePem(
  body: Uint8Array,
  opening: string,
  closing: string,
  lineLength = 64,
): string {
  return `${opening}\n${linebrk(toBase64(body), lineLength)}\n${closing}`;
}

/**
 * Decode a PEM-wrapped block into raw bytes. Tolerates leading and
 * trailing noise around the boundaries (matches v1 behaviour).
 */
export function decodePem(text: string, opening: string, closing: string): Uint8Array {
  const trimmed = trimSurroundingText(text, opening, closing).replace(/\s+/g, '');
  return fromBase64(trimmed);
}

/**
 * Normalize import input to raw bytes. `options.type === 'der'` requires
 * a `Uint8Array`; otherwise the input is treated as PEM text (string or
 * UTF-8-decoded bytes) and routed through {@link decodePem}.
 */
export function resolveBytes(
  data: Uint8Array | string,
  options: ImportOptions,
  opening: string,
  closing: string,
): Uint8Array {
  if (options.type === 'der') {
    if (data instanceof Uint8Array) return data;
    throw new Error('Unsupported key format');
  }
  if (data instanceof Uint8Array) {
    return decodePem(new TextDecoder().decode(data), opening, closing);
  }
  if (typeof data === 'string') {
    return decodePem(data, opening, closing);
  }
  throw new Error('Unsupported key format');
}
