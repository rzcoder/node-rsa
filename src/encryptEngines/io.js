var crypto = require('crypto');
var constants = require('constants');

module.exports = function (keyPair, options) {
    var jsEngine = require('./js.js')(keyPair, options);

    return {
        encrypt: function (buffer, usePrivate) {
            if (usePrivate) {
                var padding = constants.RSA_PKCS1_PADDING;
                if (options.encryptionSchemeOptions && options.encryptionSchemeOptions.padding) {
                    padding = options.encryptionSchemeOptions.padding;
                }
                return crypto.privateEncrypt({
                    key: options.rsaUtils.exportKey('private'),
                    padding: padding
                }, buffer);
            } else {
                var padding = constants.RSA_PKCS1_OAEP_PADDING;
                if (options.encryptionScheme === 'pkcs1') {
                    padding = constants.RSA_PKCS1_PADDING;
                }
                if (options.encryptionSchemeOptions && options.encryptionSchemeOptions.padding) {
                    padding = options.encryptionSchemeOptions.padding;
                }
                return crypto.publicEncrypt({
                    key: options.rsaUtils.exportKey('public'),
                    padding: padding
                }, buffer);
            }
        },

        decrypt: function (buffer, usePublic) {
            if (usePublic) {
                var padding = constants.RSA_PKCS1_PADDING;
                if (options.encryptionSchemeOptions && options.encryptionSchemeOptions.padding) {
                    padding = options.encryptionSchemeOptions.padding;
                }
                return crypto.publicDecrypt({
                    key: options.rsaUtils.exportKey('public'),
                    padding: padding
                }, buffer);
            } else {
                var padding = constants.RSA_PKCS1_OAEP_PADDING;
                if (options.encryptionScheme === 'pkcs1') {
                    padding = constants.RSA_PKCS1_PADDING;
                }
                if (options.encryptionSchemeOptions && options.encryptionSchemeOptions.padding) {
                    padding = options.encryptionSchemeOptions.padding;
                }
                return crypto.privateDecrypt({
                    key: options.rsaUtils.exportKey('private'),
                    padding: padding
                }, buffer);
            }
        }
    };
};