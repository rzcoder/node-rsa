import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DerWriter, OID } from '../../src/asn1/index.js';
import { BigInteger, setBigIntegerBackend } from '../../src/bigint/big-integer.js';
import { nodeBackend } from '../../src/crypto/backend.node.js';
import { encodePem } from '../../src/formats/pem.js';
import NodeRSA from '../../src/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = resolve(here, '../keys');

function readStr(name: string): string {
  return readFileSync(resolve(keysDir, name), 'utf8');
}

function toBytes(b: BigInteger): Uint8Array {
  return b.toBuffer() as Uint8Array;
}

beforeAll(() => {
  setBigIntegerBackend(nodeBackend);
});

/**
 * Build a PKCS#8 private-key PEM with caller-chosen `version`, algorithm
 * `oid`, and `innerVersion`. Components are taken from a valid fixture
 * so the only thing wrong with the resulting file is the chosen header.
 */
function buildPkcs8Private(opts: {
  version: number;
  oid: string;
  innerVersion: number;
}): string {
  const k = new NodeRSA(readStr('private_pkcs1.pem'));
  const kp = k.keyPair;

  const body = new DerWriter();
  body.startSequence();
  body.writeInteger(opts.innerVersion);
  body.writeInteger(toBytes(kp.n!));
  body.writeInteger(kp.e);
  body.writeInteger(toBytes(kp.d!));
  body.writeInteger(toBytes(kp.p!));
  body.writeInteger(toBytes(kp.q!));
  body.writeInteger(toBytes(kp.dmp1!));
  body.writeInteger(toBytes(kp.dmq1!));
  body.writeInteger(toBytes(kp.coeff!));
  body.endSequence();

  const w = new DerWriter();
  w.startSequence();
  w.writeInteger(opts.version);
  w.startSequence();
  w.writeOid(opts.oid);
  w.writeNull();
  w.endSequence();
  w.writeOctetString(body.toBytes());
  w.endSequence();

  return encodePem(w.toBytes(), '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----');
}

describe('PKCS#8 — H8 algorithm OID allowlist with clear diagnostics', () => {
  it('rejects RSASSA-PSS-only OID (1.2.840.113549.1.1.10)', () => {
    const pem = buildPkcs8Private({
      version: 0,
      oid: '1.2.840.113549.1.1.10',
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).toThrow(/RSASSA-PSS-only/);
  });

  it('rejects RSAES-OAEP-only OID (1.2.840.113549.1.1.7)', () => {
    const pem = buildPkcs8Private({
      version: 0,
      oid: '1.2.840.113549.1.1.7',
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).toThrow(/RSAES-OAEP-only/);
  });

  it('rejects unknown algorithm OID with generic diagnostic', () => {
    const pem = buildPkcs8Private({
      version: 0,
      oid: '1.2.3.4.5',
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).toThrow(/unsupported algorithm OID/);
  });

  it('accepts the canonical rsaEncryption OID', () => {
    const pem = buildPkcs8Private({
      version: 0,
      oid: OID.RSA_ENCRYPTION,
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).not.toThrow();
  });
});

describe('PKCS#8 — M7 version validation', () => {
  it('rejects outer version = 2 (out of RFC 5958 set {0, 1})', () => {
    const pem = buildPkcs8Private({
      version: 2,
      oid: OID.RSA_ENCRYPTION,
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).toThrow(/unsupported version 2/);
  });

  it('rejects outer version = 42', () => {
    const pem = buildPkcs8Private({
      version: 42,
      oid: OID.RSA_ENCRYPTION,
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).toThrow(/unsupported version 42/);
  });

  it('rejects PKCS#1 multi-prime keys (inner version = 1)', () => {
    const pem = buildPkcs8Private({
      version: 0,
      oid: OID.RSA_ENCRYPTION,
      innerVersion: 1,
    });
    expect(() => new NodeRSA(pem)).toThrow(/multi-prime keys/);
  });

  it('accepts outer version = 0 (PrivateKeyInfo)', () => {
    const pem = buildPkcs8Private({
      version: 0,
      oid: OID.RSA_ENCRYPTION,
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).not.toThrow();
  });

  it('accepts outer version = 1 (OneAsymmetricKey)', () => {
    // Note: import treats v1 like v0 — we don't actually consume the
    // optional public key field. RFC 5958 §2 permits version 1 for keys
    // without a public-key component.
    const pem = buildPkcs8Private({
      version: 1,
      oid: OID.RSA_ENCRYPTION,
      innerVersion: 0,
    });
    expect(() => new NodeRSA(pem)).not.toThrow();
  });
});
