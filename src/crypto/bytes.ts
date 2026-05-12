const HEX_CHARS = '0123456789abcdef';
const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export function alloc(n: number, fill = 0): Uint8Array {
  const out = new Uint8Array(n);
  if (fill !== 0) out.fill(fill);
  return out;
}

export function concat(...arrays: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] as number;
    out += HEX_CHARS[b >>> 4];
    out += HEX_CHARS[b & 0x0f];
  }
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex: odd length ${clean.length}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = parseHexNibble(clean.charCodeAt(i * 2));
    const lo = parseHexNibble(clean.charCodeAt(i * 2 + 1));
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function parseHexNibble(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  throw new Error(`Invalid hex character: 0x${c.toString(16).padStart(2, '0')}`);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function fromUtf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

export function toUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

export function readUInt32BE(bytes: Uint8Array, offset = 0): number {
  if (offset + 4 > bytes.length) {
    throw new RangeError(`readUInt32BE: out of range (offset=${offset}, length=${bytes.length})`);
  }
  return (
    (((bytes[offset] as number) << 24) |
      ((bytes[offset + 1] as number) << 16) |
      ((bytes[offset + 2] as number) << 8) |
      (bytes[offset + 3] as number)) >>>
    0
  );
}

export function writeUInt32BE(value: number, target: Uint8Array, offset = 0): void {
  if (offset + 4 > target.length) {
    throw new RangeError(`writeUInt32BE: out of range (offset=${offset}, length=${target.length})`);
  }
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

export function asUint8Array(buf: Uint8Array | ArrayBuffer): Uint8Array {
  return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
}
