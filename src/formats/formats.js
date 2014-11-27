module.exports = {
    pkcs1: require('./pkcs1'),
    pkcs8: require('./pkcs8'),

    isPrivateExport: function(format) {
        return module.exports[format] && typeof module.exports[format].privateExport === 'function';
    },

    isPrivateImport: function(format) {
        return module.exports[format] && typeof module.exports[format].privateImport === 'function';
    },

    isPublicExport: function(format) {
        return module.exports[format] && typeof module.exports[format].publicExport === 'function';
    },

    isPublicImport: function(format) {
        return module.exports[format] && typeof module.exports[format].publicImport === 'function';
    }
};