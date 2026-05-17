import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { decodePem, trimSurroundingText } from '../../src/formats/pem.js';
import NodeRSAClass from '../../src/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

const OPEN = '-----BEGIN RSA PRIVATE KEY-----';
const CLOSE = '-----END RSA PRIVATE KEY-----';

describe('PEM — multi-block input is rejected (L2)', () => {
  it('rejects two RSA PRIVATE KEY blocks concatenated', () => {
    const single = readStr('private_pkcs1.pem').trim();
    const dup = `${single}\n${single}\n`;
    expect(() => decodePem(dup, OPEN, CLOSE)).toThrow(/multiple .* blocks/);
  });

  it('rejects two blocks even with garbage between them', () => {
    const single = readStr('private_pkcs1.pem').trim();
    const dup = `${single}\n# random comment\n\n${single}\n`;
    expect(() => decodePem(dup, OPEN, CLOSE)).toThrow(/multiple .* blocks/);
  });

  it('accepts a single block with surrounding text', () => {
    const single = readStr('private_pkcs1.pem').trim();
    const noisy = `header line\n${single}\nfooter line\n`;
    expect(() => decodePem(noisy, OPEN, CLOSE)).not.toThrow();
  });

  it('accepts mixed-marker files (different opening strings coexist)', () => {
    // L2 only rejects duplicate *same-opening* blocks. A file with both an
    // RSA PRIVATE KEY block and (say) a CERTIFICATE block is unambiguous —
    // each decodePem call sees only its own opening marker.
    const key = readStr('private_pkcs1.pem').trim();
    const mixed = `-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n${key}\n`;
    expect(() => decodePem(mixed, OPEN, CLOSE)).not.toThrow();
  });
});

describe('PEM — robustness against malformed input', () => {
  it('throws on bad base64 inside an otherwise well-formed block', () => {
    const body = '!!!not base64!!!';
    const bad = `${OPEN}\n${body}\n${CLOSE}\n`;
    expect(() => decodePem(bad, OPEN, CLOSE)).toThrow();
  });

  it('trims leading and trailing whitespace around the body', () => {
    const single = readStr('private_pkcs1.pem');
    // Add tab/CR noise around the body — the \s+ replace should strip them.
    const padded = single.replace(/\n/g, '\t \r\n  ');
    expect(() => decodePem(padded, OPEN, CLOSE)).not.toThrow();
  });

  it('decodes raw base64 when no PEM markers are present', () => {
    // trimSurroundingText returns the input verbatim when no markers exist;
    // the fallback fromBase64 either succeeds (raw base64 mode) or throws
    // on garbage. Document the success branch.
    expect(decodePem('AAAA', OPEN, CLOSE)).toEqual(new Uint8Array([0, 0, 0]));
  });
});

describe('PEM — header / footer mismatches', () => {
  // decodePem uses trimSurroundingText with the caller's `opening`/`closing`
  // strings — if the closing marker isn't present, trimSurroundingText
  // falls back to the entire remainder of the input. That's normally
  // fine because pkcs1/pkcs8 importers pin their own marker pairs, but
  // we should pin the behaviour for swap-on-input cases so a future
  // refactor that loosens the pair doesn't silently accept a corrupted
  // file.
  it('rejects body when BEGIN/END markers swapped or replaced with a different pair', () => {
    const body = readStr('private_pkcs1.pem').trim();
    // BEGIN matches RSA PRIVATE KEY, but END is PUBLIC KEY → closing not
    // found at the caller's expected position. Everything from BEGIN onward
    // (including the "END PUBLIC KEY" line) is fed to fromBase64, which
    // bails out on the dashes / words. Either failure is acceptable as
    // long as the call throws (rather than returning a truncated key).
    const swapped = body.replace('-----END RSA PRIVATE KEY-----', '-----END RSA PUBLIC KEY-----');
    expect(() => decodePem(swapped, OPEN, CLOSE)).toThrow();
  });

  it('importing a PKCS#1 PEM where the body says PUBLIC fails through NodeRSA', () => {
    // End-to-end: the high-level importer should reject obvious
    // header-tampering rather than half-parse a body. Uses the public
    // surface (NodeRSA constructor) so a regression that loosened the
    // PEM detector would be caught here too.
    const body = readStr('private_pkcs1.pem')
      .trim()
      .replace('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN RSA PUBLIC KEY-----');
    // Importing private fixture with a public BEGIN: detectors prefer
    // public route → eventually the body fails to parse as a SubjectPublicKeyInfo.
    expect(() => new NodeRSAClass(body)).toThrow();
  });
});

describe('trimSurroundingText — boundary conditions', () => {
  it('extracts content between first BEGIN and first END', () => {
    const text = `prefix${OPEN}body${CLOSE}suffix`;
    expect(trimSurroundingText(text, OPEN, CLOSE)).toBe('body');
  });

  it('extracts entire content when neither marker present', () => {
    expect(trimSurroundingText('no markers here', OPEN, CLOSE)).toBe('no markers here');
  });

  it('extracts trailing content when only BEGIN is present', () => {
    expect(trimSurroundingText(`prefix${OPEN}tail`, OPEN, CLOSE)).toBe('tail');
  });

  it('extracts leading content when only END is present', () => {
    expect(trimSurroundingText(`head${CLOSE}suffix`, OPEN, CLOSE)).toBe(`head${CLOSE}suffix`);
  });
});
