var _ = require('lodash');
module.exports = {
    pkcs1: require('./pkcs1'),
    pkcs8: require('./pkcs8'),

    isPrivateExport: function (format) {
        return module.exports[format] && typeof module.exports[format].privateExport === 'function';
    },

    isPrivateImport: function (format) {
        return module.exports[format] && typeof module.exports[format].privateImport === 'function';
    },

    isPublicExport: function (format) {
        return module.exports[format] && typeof module.exports[format].publicExport === 'function';
    },

    isPublicImport: function (format) {
        return module.exports[format] && typeof module.exports[format].publicImport === 'function';
    },

    detectAndImport: function (key, data, format) {
        if (format === undefined) {
            for (var format in module.exports) {
                if (typeof module.exports[format].autoImport === 'function' && module.exports[format].autoImport(key, data)) {
                    return true;
                }
            }
        } else if (format) {
            var fmt = format.split('-');
            var keyType = 'private';
            var keyOpt = {type: 'default'};

            for(var i = 1; i < fmt.length; i++) {
                if (fmt[i]) {
                    switch (fmt[i]) {
                        case 'public':
                            keyType = fmt[i];
                            break;
                        case 'private':
                            keyType = fmt[i];
                            break;
                        case 'pem':
                            keyOpt.type = fmt[i];
                            break;
                        case 'der':
                            keyOpt.type = fmt[i];
                            break;
                    }
                }
            }

            if (module.exports[fmt[0]]) {
                if (keyType === 'private') {
                    module.exports[fmt[0]].privateImport(key, data, keyOpt);
                } else {
                    module.exports[fmt[0]].publicImport(key, data, keyOpt);
                }
            } else {
                throw Error('Unsupported key format');
            }
        }

        return false;
    },

    detectAndExport: function(key, format) {
        if (format) {
            var fmt = format.split('-');
            var keyType = 'private';
            var keyOpt = {type: 'default'};

            for(var i = 1; i < fmt.length; i++) {
                if (fmt[i]) {
                    switch (fmt[i]) {
                        case 'public':
                            keyType = fmt[i];
                            break;
                        case 'private':
                            keyType = fmt[i];
                            break;
                        case 'pem':
                            keyOpt.type = fmt[i];
                            break;
                        case 'der':
                            keyOpt.type = fmt[i];
                            break;
                    }
                }
            }

            if (module.exports[fmt[0]]) {
                if (keyType === 'private') {
                    if (!key.isPrivate()) {
                        throw Error("It is not private key");
                    }
                    return module.exports[fmt[0]].privateExport(key, keyOpt);
                } else {
                    if (!key.isPublic()) {
                        throw Error("It is not public key");
                    }
                    return module.exports[fmt[0]].publicExport(key, keyOpt);
                }
            } else {
                throw Error('Unsupported key format');
            }
        }
    }
};