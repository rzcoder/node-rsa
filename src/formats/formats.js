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
        if (format === undefined && _.isString(data)) {
            for (var format in module.exports) {
                if (typeof module.exports[format].autoImport === 'function' && module.exports[format].autoImport(key, data)) {
                    return true;
                }
            }
        } else if (format) {
            var fmt = format.split('-');
            var keyType = fmt[1] === 'private' || fmt[1] === 'public' ? fmt[1] : 'private';
            var keyOpt = fmt[2] === 'der' ? {binary: true} : null;
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
    }
};