var ber = require('asn1').Ber;
var utils = require('../utils');

module.exports = {
    privateExport: function(key, options) {
        options = options || {};

        var der = module.exports.privateDerEncode(key);
        if (options.binary) {
            return der;
        } else {
            return '-----BEGIN RSA PRIVATE KEY-----\n' + utils.linebrk(der.toString('base64'), 64) + '\n-----END RSA PRIVATE KEY-----';
        }
    },

    publicExport: function(key, options) {
        options = options || {};

        var der = module.exports.publicDerEncode(key);
        if (options.binary) {
            return der;
        } else {
            return '-----BEGIN RSA PUBLIC KEY-----\n' + utils.linebrk(der.toString('base64'), 64) + '\n-----END RSA PUBLIC KEY-----';
        }
    },

    privateDerEncode: function(key) {
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

        return writer.buffer;
    },

    publicDerEncode: function (key) {
        var n = key.n.toBuffer();
        var length = n.length + 512; // magic

        var bodyWriter = new ber.Writer({size: length});
        bodyWriter.startSequence();
        bodyWriter.writeBuffer(n, 2);
        bodyWriter.writeInt(key.e);
        bodyWriter.endSequence();
        return bodyWriter.buffer;
    }
};