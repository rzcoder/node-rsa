/* 
    This file handles polyfilling when things like Buffer/crypto/constants are
    unavailable.

    When buffer, crypto, or constants are needed, import this file like so:
        let constants = require('./polyfillHandler.js').constants;
        let require('./polyfillHandler.js').crypto;
        let { Buffer } = require('./polyfillHandler.js').buffer
    and this file will intelligently pick between the Node version (if available)
    and the buffer, crypto-browserify, and constants packages, otherwise.
*/

/*
    The nodeRequire assigment is necessary because a downstream package
    might be using webpack, and since this module does NOT use webpack, there's
    no way to hook into Webpack's ignoreWarnings config option.

    Without this workaround, consumers of node-rsa will get the following
    errors, even though we are handling the case of a failed resolve manually:
    - "Module not found: Can't resolve 'crypto' in '/node_modules/node_rsa/src'"
    - "Module not found: Can't resolve 'constants' in '/node_modules/node_rsa/src'"

    Workaround simplified from https://github.com/webpack/webpack/issues/8826#issuecomment-660594260
*/
const nodeRequire = typeof process !== "undefined" && process.versions?.node
    ? typeof __webpack_require__ === "function"
        ? __non_webpack_require__
        : require
    : undefined;

let crypto, constants;

const buffer = (typeof Buffer !== 'undefined')
    ? { Buffer }
    : require('buffer/');

try {
    crypto = nodeRequire('crypto');
} catch (er) {
    crypto = require('crypto-browserify');
}

try {
    constants = nodeRequire('constants');
} catch (er) {
    constants = require('constants-browserify');
}

module.exports = {
    buffer,
    constants,
    crypto,
}