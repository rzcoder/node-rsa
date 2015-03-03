var BigInteger = require('../libs/jsbn.js');
var schemes = require('../schemes/schemes.js');

module.exports = function (keyPair, options) {
    var pkcs1Scheme = schemes.pkcs1.makeScheme(keyPair, options);

    return {
        encrypt: function (buffer, usePrivate) {
            if (usePrivate) {
                var m = new BigInteger(pkcs1Scheme.encPad(buffer, {type: 1}));
                var c = keyPair.$doPrivate(m);
            } else {
                var m = new BigInteger(keyPair.encryptionScheme.encPad(buffer));
                var c = keyPair.$doPublic(m);
            }
            return c.toBuffer(keyPair.encryptedDataLength);
        },

        decrypt: function (buffer, usePublic) {
            var c = new BigInteger(buffer);

            if (usePublic) {
                var m = keyPair.$doPublic(c);
                return pkcs1Scheme.encUnPad(m.toBuffer(keyPair.encryptedDataLength), {type: 1});
            } else {
                var m = keyPair.$doPrivate(c);
                return keyPair.encryptionScheme.encUnPad(m.toBuffer(keyPair.encryptedDataLength));
            }
        }
    };
};