import { fromBase64, fromUtf8, toBase64, toUtf8 } from '../crypto/bytes.js';

export function linebrk(str: string, maxLen: number): string {
  let out = '';
  let i = 0;
  while (i + maxLen < str.length) {
    out += `${str.substring(i, i + maxLen)}\n`;
    i += maxLen;
  }
  return out + str.substring(i);
}

export function trimSurroundingText(data: string, opening: string, closing: string): string {
  let start = 0;
  let end = data.length;
  const openIdx = data.indexOf(opening);
  if (openIdx >= 0) start = openIdx + opening.length;
  const closeIdx = data.indexOf(closing, openIdx);
  if (closeIdx >= 0) end = closeIdx;
  return data.substring(start, end);
}

/** Wrap raw DER bytes in a PEM container. */
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

export function bytesToUtf8(bytes: Uint8Array): string {
  return toUtf8(bytes);
}

export function utf8ToBytes(s: string): Uint8Array {
  return fromUtf8(s);
}
