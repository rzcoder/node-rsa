module.exports = schemes = {
    pkcs1: require('./pkcs1'),

    isEncryption: function (scheme) {
        return schemes[scheme] && schemes[scheme].isEncryption;
    },

    isSignature: function (scheme) {
        return schemes[scheme] && schemes[scheme].isSignature;
    }
};
