var crypto = require('crypto');
var constants = require('constants');

module.exports = function (keyPair, options) {
    var jsEngine = require('./js.js')(keyPair);

    return {
        encrypt: function (buffer, usePrivate) {
            var padding = constants.RSA_PKCS1_OAEP_PADDING;
            if (options.encryptionScheme === 'pkcs1') {
                padding = constants.RSA_PKCS1_PADDING;
            }
            if (usePrivate) {
                /* opennssl can't make it */
                if (padding === constants.RSA_PKCS1_OAEP_PADDING) {
                    return jsEngine.encrypt(buffer, usePrivate);
                }
                return crypto.privateEncrypt({
                    key: options.rsaUtils.exportKey('private'),
                    padding: padding
                }, buffer);
            } else {
                return crypto.publicEncrypt({
                    key: options.rsaUtils.exportKey('public'),
                    padding: padding
                }, buffer);
            }
        },

        decrypt: function (buffer, usePublic) {
            var padding = constants.RSA_PKCS1_OAEP_PADDING;
            if (options.encryptionScheme === 'pkcs1') {
                padding = constants.RSA_PKCS1_PADDING;
            }

            if (usePublic) {
                /* opennssl can't make it */
                if (padding === constants.RSA_PKCS1_OAEP_PADDING) {
                    return jsEngine.decrypt(buffer, usePublic);
                }
                return crypto.publicDecrypt({
                    key: options.rsaUtils.exportKey('public'),
                    padding: padding
                }, buffer);
            } else {
                return crypto.privateDecrypt({
                    key: options.rsaUtils.exportKey('private'),
                    padding: padding
                }, buffer);
            }
        }
    };
};