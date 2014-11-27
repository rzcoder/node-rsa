var ber = require('asn1').Ber;
var _ = require('lodash');
var PUBLIC_RSA_OID = '1.2.840.113549.1.1.1';
var utils = require('../utils');

module.exports = {
    publicExport: function(key, options) {
        options = options || {};

        var n = key.n.toBuffer();
        var length = n.length + 512; // magic

        var bodyWriter = new ber.Writer({size: length});
        bodyWriter.writeByte(0);
        bodyWriter.startSequence();
        bodyWriter.writeBuffer(n, 2);
        bodyWriter.writeInt(key.e);
        bodyWriter.endSequence();
        var body = bodyWriter.buffer;

        var writer = new ber.Writer({size: length});
        writer.startSequence();
        writer.startSequence();
        writer.writeOID(PUBLIC_RSA_OID);
        writer.writeNull();
        writer.endSequence();
        writer.writeBuffer(body, 3);
        writer.endSequence();

        if (options.binary) {
            return writer.buffer;
        } else {
            return '-----BEGIN PUBLIC KEY-----\n' + utils.linebrk(writer.buffer.toString('base64'), 64) + '\n-----END PUBLIC KEY-----';
        }
    },

    publicImport: function(key, data) {
        var buffer;

        if (_.isString(data)) {
            var pem = data.replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\s+|\n\r|\n|\r$/gm, '');
            buffer = new Buffer(pem, 'base64');
        } else if (Buffer.isBuffer(data)) {
            buffer = data;
        } else {
            throw Error('Unsupported key format');
        }

        var reader = new ber.Reader(buffer);
        reader.readSequence();
        var header = new ber.Reader(reader.readString(0x30, true));
        if (header.readOID(0x06, true) !== PUBLIC_RSA_OID) {
            throw Error('Invalid Public key format');
        }

        var body = new ber.Reader(reader.readString(0x03, true));
        body.readByte();
        body.readSequence();
        key.setPublic(
            body.readString(0x02, true), // modulus
            body.readString(0x02, true)  // publicExponent
        );
    },

    /**
     * Trying autodetect and import key
     * @param key
     * @param data
     */
    autoImport: function (key, data) {
        if (/^\s*-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END PRIVATE KEY-----\s*$/g.test(data)) {
            module.exports.privateImport(key, data);
            return true;
        }

        if (/^\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END PUBLIC KEY-----\s*$/g.test(data)) {
            module.exports.publicImport(key, data);
            return true;
        }

        return false;
    }
};
