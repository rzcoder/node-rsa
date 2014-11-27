var ber = require('asn1').Ber;
var PUBLIC_RSA_OID = '1.2.840.113549.1.1.1';
var utils = require('../utils');

module.exports = {
    publicExport: function(key, options) {
        options = options || {};

        var der = module.exports.publicDerEncode(key);
        if (options.binary) {
            return der;
        } else {
            return '-----BEGIN PUBLIC KEY-----\n' + utils.linebrk(der.toString('base64'), 64) + '\n-----END PUBLIC KEY-----';
        }
    },

    publicImport: function(key) {

    },

    publicDerEncode: function (key) {
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

        return writer.buffer;
    }
};