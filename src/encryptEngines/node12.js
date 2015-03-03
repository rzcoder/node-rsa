var crypto = require('crypto');
var constants = require('constants');

module.exports = function (keyPair, options) {
    var jsEngine = require('./js.js')(keyPair, options);

    return {
        encrypt: function (buffer, usePrivate) {
            if (usePrivate) {
                return jsEngine.encrypt(buffer, usePrivate);
            }
            var padding = constants.RSA_PKCS1_OAEP_PADDING;
            if (options.encryptionScheme === 'pkcs1') {
                padding = constants.RSA_PKCS1_PADDING;
            }

            return crypto.publicEncrypt({
                key: options.rsaUtils.exportKey('public'),
                padding: padding
            }, buffer);
        },

        decrypt: function (buffer, usePublic) {
            if (usePublic) {
                return jsEngine.decrypt(buffer, usePublic);
            }
            var padding = constants.RSA_PKCS1_OAEP_PADDING;
            if (options.encryptionScheme === 'pkcs1') {
                padding = constants.RSA_PKCS1_PADDING;
            }

            return crypto.privateDecrypt({
                key: options.rsaUtils.exportKey('private'),
                padding: padding
            }, buffer);
        }
    };
};