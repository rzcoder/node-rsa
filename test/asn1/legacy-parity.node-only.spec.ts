import asn1 from 'asn1';
import { describe, expect, it } from 'vitest';
import { DerReader, DerWriter, OID } from '../../src/asn1/index.js';
import { fromHex, toHex } from '../../src/crypto/bytes.js';

const ber = asn1.Ber;

/**
 * Cross-check the in-tree DER reader/writer against the npm `asn1` package
 * used by node-rsa v1. Runs only in the `node` workspace project.
 */
describe('parity with npm asn1 package', () => {
  it('INTEGER (small): in-tree writer matches asn1.Ber.Writer', () => {
    const legacy = new ber.Writer({ size: 32 });
    legacy.writeInt(65537);
    const ours = new DerWriter();
    ours.writeInteger(65537);
    expect(toHex(new Uint8Array(legacy.buffer))).toBe(toHex(ours.toBytes()));
  });

  it('SEQUENCE { INTEGER, OID, NULL }: byte-identical', () => {
    const legacy = new ber.Writer({ size: 64 });
    legacy.startSequence();
    legacy.writeInt(0);
    legacy.writeOID(OID.RSA_ENCRYPTION);
    legacy.writeNull();
    legacy.endSequence();

    const ours = new DerWriter();
    ours.startSequence();
    ours.writeInteger(0);
    ours.writeOid(OID.RSA_ENCRYPTION);
    ours.writeNull();
    ours.endSequence();

    expect(toHex(new Uint8Array(legacy.buffer))).toBe(toHex(ours.toBytes()));
  });

  it('writeBuffer(buf, 2) — INTEGER from raw bytes — matches', () => {
    // The legacy formats code uses writeBuffer(b, 2) to wrap arbitrary bytes
    // as an INTEGER TLV. Our writeInteger(Uint8Array) should produce the same
    // bytes when the input has no MSB-set first byte.
    const value = fromHex('00deadbeef');
    const legacy = new ber.Writer({ size: 32 });
    legacy.writeBuffer(Buffer.from(value), 2);
    const ours = new DerWriter();
    ours.writeInteger(value);
    expect(toHex(new Uint8Array(legacy.buffer))).toBe(toHex(ours.toBytes()));
  });

  it('our reader matches asn1.Ber.Reader on a constructed SEQUENCE', () => {
    const legacyW = new ber.Writer({ size: 128 });
    legacyW.startSequence();
    legacyW.writeInt(0);
    legacyW.startSequence();
    legacyW.writeOID(OID.RSA_ENCRYPTION);
    legacyW.writeNull();
    legacyW.endSequence();
    legacyW.endSequence();
    const bytes = new Uint8Array(legacyW.buffer);

    const ourR = new DerReader(bytes).readSequence();
    expect(ourR.readSmallInteger()).toBe(0);
    const inner = ourR.readSequence();
    expect(inner.readOid()).toBe(OID.RSA_ENCRYPTION);
    inner.readNull();

    const legacyR = new ber.Reader(Buffer.from(bytes));
    legacyR.readSequence();
    expect(legacyR.readInt()).toBe(0);
    const innerLegacy = new ber.Reader(legacyR.readString(0x30, true));
    expect(innerLegacy.readOID(0x06, true)).toBe(OID.RSA_ENCRYPTION);
  });

  it('OIDs with multibyte arcs match', () => {
    // npm `asn1` requires arc1 < 40 (limitation of the package), so the test
    // matrix here excludes 2.999.* — that case is covered against ourselves in
    // the primitives spec.
    const oids = ['1.3.6.1.4.1.311.2.1.4', '1.2.840.113549', '1.2.840.113549.1.1.11'];
    for (const oid of oids) {
      const legacy = new ber.Writer({ size: 64 });
      legacy.writeOID(oid);
      const ours = new DerWriter();
      ours.writeOid(oid);
      expect(toHex(new Uint8Array(legacy.buffer))).toBe(toHex(ours.toBytes()));
    }
  });
});
