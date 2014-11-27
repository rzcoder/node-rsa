var ber = require('asn1').Ber;
var _ = require('lodash');
var utils = require('../utils');

module.exports = {
    privateExport: function (key, options) {
        options = options || {};

        var n = key.n.toBuffer();
        var d = key.d.toBuffer();
        var p = key.p.toBuffer();
        var q = key.q.toBuffer();
        var dmp1 = key.dmp1.toBuffer();
        var dmq1 = key.dmq1.toBuffer();
        var coeff = key.coeff.toBuffer();

        var length = n.length + d.length + p.length + q.length + dmp1.length + dmq1.length + coeff.length + 512; // magic
        var writer = new ber.Writer({size: length});

        writer.startSequence();
        writer.writeInt(0);
        writer.writeBuffer(n, 2);
        writer.writeInt(key.e);
        writer.writeBuffer(d, 2);
        writer.writeBuffer(p, 2);
        writer.writeBuffer(q, 2);
        writer.writeBuffer(dmp1, 2);
        writer.writeBuffer(dmq1, 2);
        writer.writeBuffer(coeff, 2);
        writer.endSequence();

        if (options.binary) {
            return writer.buffer;
        } else {
            return '-----BEGIN RSA PRIVATE KEY-----\n' + utils.linebrk(writer.buffer.toString('base64'), 64) + '\n-----END RSA PRIVATE KEY-----';
        }
    },

    privateImport: function (key, data) {
        var buffer;

        if (_.isString(data)) {
            var pem = data.replace('-----BEGIN RSA PRIVATE KEY-----', '')
                .replace('-----END RSA PRIVATE KEY-----', '')
                .replace(/\s+|\n\r|\n|\r$/gm, '');
            buffer = new Buffer(pem, 'base64');
        } else if (Buffer.isBuffer(data)) {
            buffer = data;
        } else {
            throw Error('Unsupported key format');
        }

        var reader = new ber.Reader(buffer);
        reader.readSequence();
        reader.readString(2, true); // just zero
        key.setPrivate(
            reader.readString(2, true),  // modulus
            reader.readString(2, true),  // publicExponent
            reader.readString(2, true),  // privateExponent
            reader.readString(2, true),  // prime1
            reader.readString(2, true),  // prime2
            reader.readString(2, true),  // exponent1 -- d mod (p1)
            reader.readString(2, true),  // exponent2 -- d mod (q-1)
            reader.readString(2, true)   // coefficient -- (inverse of q) mod p
        );
    },

    publicExport: function (key, options) {
        options = options || {};

        var n = key.n.toBuffer();
        var length = n.length + 512; // magic

        var bodyWriter = new ber.Writer({size: length});
        bodyWriter.startSequence();
        bodyWriter.writeBuffer(n, 2);
        bodyWriter.writeInt(key.e);
        bodyWriter.endSequence();

        if (options.binary) {
            return bodyWriter.buffer;
        } else {
            return '-----BEGIN RSA PUBLIC KEY-----\n' + utils.linebrk(bodyWriter.buffer.toString('base64'), 64) + '\n-----END RSA PUBLIC KEY-----';
        }
    },

    /**
     * Trying autodetect and import key
     * @param key
     * @param data
     */
    autoImport: function (key, data) {
        if (/^\s*-----BEGIN RSA PRIVATE KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END RSA PRIVATE KEY-----\s*$/g.test(data)) {
            module.exports.privateImport(key, data);
            return true;
        }

        if (/^\s*-----BEGIN RSA PUBLIC KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END RSA PUBLIC KEY-----\s*$/g.test(data)) {
            module.exports.publicImport(key, data);
            return true;
        }

        return false;
    }
};