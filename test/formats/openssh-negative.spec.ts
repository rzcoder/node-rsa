import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { fromBase64, toBase64 } from '../../src/crypto/bytes.js';
import NodeRSA from '../../src/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

const OPEN = '-----BEGIN OPENSSH PRIVATE KEY-----';
const CLOSE = '-----END OPENSSH PRIVATE KEY-----';

/** Decode an OpenSSH-PEM string into its raw binary body. */
function decodeOpenSshPem(pem: string): Uint8Array {
  const body = pem.substring(pem.indexOf(OPEN) + OPEN.length, pem.indexOf(CLOSE));
  return fromBase64(body.replace(/\s+/g, ''));
}

/** Re-wrap raw binary back into an OpenSSH PEM container. */
function encodeOpenSshPem(bytes: Uint8Array): string {
  const b64 = toBase64(bytes);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 70) lines.push(b64.slice(i, i + 70));
  return `${OPEN}\n${lines.join('\n')}\n${CLOSE}\n`;
}

/**
 * Find the byte offset of the SECOND occurrence of the OpenSSH `ssh-rsa`
 * string TLV (length-prefix `00 00 00 07` + `ssh-rsa`). The first
 * occurrence is in the public-key block; the second sits in the private
 * section immediately after checkint1 and checkint2. The 4 bytes
 * preceding the match are checkint2.
 */
function findSecondSshRsa(bytes: Uint8Array): number {
  const pattern = new Uint8Array([
    0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2d, 0x72, 0x73, 0x61,
  ]);
  let count = 0;
  outer: for (let i = 0; i <= bytes.length - pattern.length; i++) {
    for (let j = 0; j < pattern.length; j++) {
      if (bytes[i + j] !== pattern[j]) continue outer;
    }
    count++;
    if (count === 2) return i;
  }
  throw new Error('OpenSSH private section marker not found');
}

describe('OpenSSH — M5 checkint validation', () => {
  it('rejects checkint2 with a single-byte flip', () => {
    const validPem = readStr('id_rsa');
    const bytes = decodeOpenSshPem(validPem);
    const sshRsaPos = findSecondSshRsa(bytes);
    const mutated = new Uint8Array(bytes);
    // checkint2 occupies bytes [sshRsaPos - 4 .. sshRsaPos]. Flip the LSB.
    mutated[sshRsaPos - 1] = (mutated[sshRsaPos - 1] as number) ^ 0x01;
    const badPem = encodeOpenSshPem(mutated);
    expect(() => new NodeRSA(badPem)).toThrow(/checksum mismatch/);
  });

  it('rejects checkint2 wholly replaced with a different value', () => {
    const validPem = readStr('id_rsa');
    const bytes = decodeOpenSshPem(validPem);
    const sshRsaPos = findSecondSshRsa(bytes);
    const mutated = new Uint8Array(bytes);
    // Replace all 4 bytes of checkint2 — confirms the comparison covers the
    // whole field, not just one byte.
    for (let i = 0; i < 4; i++) {
      mutated[sshRsaPos - 4 + i] = (mutated[sshRsaPos - 4 + i] as number) ^ 0xff;
    }
    const badPem = encodeOpenSshPem(mutated);
    expect(() => new NodeRSA(badPem)).toThrow(/checksum mismatch/);
  });

  it('accepts the unmodified valid OpenSSH key', () => {
    const validPem = readStr('id_rsa');
    expect(() => new NodeRSA(validPem)).not.toThrow();
  });
});

describe('OpenSSH — M4 SshReader bounds-check', () => {
  it('rejects OpenSSH private key with a forged oversized string length', () => {
    const validPem = readStr('id_rsa');
    const bytes = decodeOpenSshPem(validPem);
    // The first string in the file is "openssh-key-v1\0" (15 bytes, not
    // length-prefixed — it's a magic), followed by the 4-byte length of
    // "none" (cipher name). Offset 15 is where the first length-prefixed
    // string begins. Forge it to a length larger than the buffer.
    const mutated = new Uint8Array(bytes);
    mutated[15] = 0xff;
    mutated[16] = 0xff;
    mutated[17] = 0xff;
    mutated[18] = 0xff;
    const badPem = encodeOpenSshPem(mutated);
    expect(() => new NodeRSA(badPem)).toThrow(/exceeds buffer/);
  });

  it('rejects OpenSSH key truncated mid-string with a bounds-check error', () => {
    const validPem = readStr('id_rsa');
    const bytes = decodeOpenSshPem(validPem);
    // Truncate to first 100 bytes — the next length-prefixed read will see
    // a length that exceeds the remaining buffer. The bounds check in
    // SshReader.readString surfaces an "exceeds buffer" error.
    const truncated = bytes.subarray(0, 100);
    const badPem = encodeOpenSshPem(truncated);
    expect(() => new NodeRSA(badPem)).toThrow(/exceeds buffer/);
  });
});

describe('OpenSSH — magic and cipher header', () => {
  it('rejects file with wrong magic prefix', () => {
    const validPem = readStr('id_rsa');
    const bytes = decodeOpenSshPem(validPem);
    const mutated = new Uint8Array(bytes);
    mutated[0] = 0x58; // 'X' instead of 'o'
    const badPem = encodeOpenSshPem(mutated);
    expect(() => new NodeRSA(badPem)).toThrow(/Invalid file format/);
  });

  it('rejects file declaring a non-"none" cipher', () => {
    const validPem = readStr('id_rsa');
    const bytes = decodeOpenSshPem(validPem);
    // After 15-byte magic, the cipher-name string starts.
    // "none" is 4 bytes; replace one of them with 'X' to make "Xone".
    const mutated = new Uint8Array(bytes);
    mutated[19] = 0x58; // first char of cipher name
    const badPem = encodeOpenSshPem(mutated);
    expect(() => new NodeRSA(badPem)).toThrow(/Unsupported key type/);
  });
});
