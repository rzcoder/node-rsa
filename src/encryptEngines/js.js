var BigInteger = require('../libs/jsbn.js');

module.exports = function (keyPair, options) {
    return {
        encrypt: function (buffer, usePrivate) {
            var m = new BigInteger(keyPair.encryptionScheme.encPad(buffer));
            var c = usePrivate ? keyPair.$doPrivate(m) : keyPair.$doPublic(m);
            return c.toBuffer(keyPair.encryptedDataLength);
        },

        decrypt: function (buffer, usePublic) {
            var c = new BigInteger(buffer);
            var m = usePublic ? keyPair.$doPublic(c) : keyPair.$doPrivate(c);
            return keyPair.encryptionScheme.encUnPad(m.toBuffer(keyPair.encryptedDataLength));
        }
    };
};