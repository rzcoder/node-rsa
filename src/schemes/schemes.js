module.exports = schemes = {
    pkcs1: require('./pkcs1'),

    /**
     * Check if scheme has padding methods
     * @param scheme {string}
     * @returns {Boolean}
     */
    isEncryption: function (scheme) {
        return schemes[scheme] && schemes[scheme].isEncryption;
    },

    /**
     * Check if scheme has sign/verify methods
     * @param scheme {string}
     * @returns {Boolean}
     */
    isSignature: function (scheme) {
        return schemes[scheme] && schemes[scheme].isSignature;
    }
};
