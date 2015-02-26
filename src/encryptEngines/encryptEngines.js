var crypt = require('crypto');

module.exports = {
    getEngine: function (keyPair, options) {
        var engine;
        if (options.environment === 'browser') {
            engine = require('./js.js');
        } else {
            if (typeof crypt.publicEncrypt === 'function' && typeof crypt.privateDecrypt === 'function') {
                if (typeof crypt.privateEncrypt === 'function' && typeof crypt.publicDecrypt === 'function') {
                    engine = require('./io.js');
                } else {
                    engine = require('./node12.js');
                }
            }
        }
        return engine(keyPair, options);
    }
};