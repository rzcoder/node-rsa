/*!
 * RSA library for Node.js
 *
 * Copyright (c) 2014 rzcoder
 * All Rights Reserved.
 *
 * License BSD
 */

var rsa = require('./libs/rsa.js');
var crypt = require('crypto');
var ber = require('asn1').Ber;
var _ = require('lodash');
var utils = require('./utils');
var schemes = require('./schemes/schemes.js');
var formats = require('./formats/formats.js');

var PUBLIC_RSA_OID = '1.2.840.113549.1.1.1';

module.exports = (function () {
    var SUPPORTED_HASH_ALGORITHMS = {
        node: ['md4', 'md5', 'ripemd160', 'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
        browser: ['md5', 'ripemd160', 'sha1', 'sha256', 'sha512']
    };

    var DEFAULT_ENCRYPTION_SCHEME = 'pkcs1_oaep';
    var DEFAULT_SIGNING_SCHEME = 'pkcs1';

    var DEFAULT_EXPORT_PRIVATE_FORMAT = 'pkcs1';
    var DEFAULT_EXPORT_PUBLIC_FORMAT = 'pkcs8';

    /**
     * @param key {string|buffer|object} Key in PEM format, or data for generate key {b: bits, e: exponent}
     * @constructor
     */
    function NodeRSA(key, options) {
        if (!this instanceof NodeRSA) {
            return new NodeRSA(key, options);
        }

        this.$options = {
            signingScheme: DEFAULT_SIGNING_SCHEME,
            signingSchemeOptions: {
                hash: 'sha256',
                saltLength: null
            },
            encryptionScheme: DEFAULT_ENCRYPTION_SCHEME,
            encryptionSchemeOptions: {
                hash: 'sha1',
                label: null
            },
            environment: utils.detectEnvironment(),
            rsaUtils: this
        };
        this.keyPair = new rsa.Key();
        this.setOptions(options);
        this.$cache = {};

        if (Buffer.isBuffer(key) || _.isString(key)) {
            this.importKey(key);
        } else if (_.isObject(key)) {
            this.generateKeyPair(key.b, key.e);
        }
    }

    /**
     * Set and validate options for key instance
     * @param options
     */
    NodeRSA.prototype.setOptions = function (options) {
        options = options || {};
        if (options.environment) {
            this.$options.environment = options.environment;
        }

        if (options.signingScheme) {
            if (_.isString(options.signingScheme)) {
                var signingScheme = options.signingScheme.toLowerCase().split('-');
                if (signingScheme.length == 1) {
                    if (_.indexOf(SUPPORTED_HASH_ALGORITHMS.node, signingScheme[0]) > -1) {
                        this.$options.signingSchemeOptions = {
                            hash: signingScheme[0]
                        };
                        this.$options.signingScheme = DEFAULT_SIGNING_SCHEME;
                    } else {
                        this.$options.signingScheme = signingScheme[0];
                        this.$options.signingSchemeOptions = {
                            hash: null
                        };
                    }
                } else {
                    this.$options.signingSchemeOptions = {
                        hash: signingScheme[1]
                    };
                    this.$options.signingScheme = signingScheme[0];
                }
            } else if (_.isObject(options.signingScheme)) {
                this.$options.signingScheme = options.signingScheme.scheme || DEFAULT_SIGNING_SCHEME;
                this.$options.signingSchemeOptions = _.omit(options.signingScheme, 'scheme');
            }

            if (!schemes.isSignature(this.$options.signingScheme)) {
                throw Error('Unsupported signing scheme');
            }
            if (this.$options.signingSchemeOptions.hash &&
                _.indexOf(SUPPORTED_HASH_ALGORITHMS[this.$options.environment], this.$options.signingSchemeOptions.hash) == -1) {
                throw Error('Unsupported hashing algorithm for ' + this.$options.environment + ' environment');
            }
        }

        if (options.encryptionScheme) {
            if (_.isString(options.encryptionScheme)) {
                this.$options.encryptionScheme = options.encryptionScheme.toLowerCase();
                this.$options.encryptionSchemeOptions = {};
            } else if (_.isObject(options.encryptionScheme)) {
                this.$options.encryptionScheme = options.encryptionScheme.scheme || DEFAULT_ENCRYPTION_SCHEME;
                this.$options.encryptionSchemeOptions = _.omit(options.encryptionScheme, 'scheme');
            }

            if (!schemes.isEncryption(this.$options.encryptionScheme)) {
                throw Error('Unsupported encryption scheme');
            }

            if (this.$options.encryptionSchemeOptions.hash &&
                _.indexOf(SUPPORTED_HASH_ALGORITHMS[this.$options.environment], this.$options.encryptionSchemeOptions.hash) == -1) {
                throw Error('Unsupported hashing algorithm for ' + this.$options.environment + ' environment');
            }
        }

        this.keyPair.setOptions(this.$options);
    };

    /**
     * Generate private/public keys pair
     *
     * @param bits {int} length key in bits. Default 2048.
     * @param exp {int} public exponent. Default 65537.
     * @returns {NodeRSA}
     */
    NodeRSA.prototype.generateKeyPair = function (bits, exp) {
        bits = bits || 2048;
        exp = exp || 65537;

        if (bits % 8 !== 0) {
            throw Error('Key size must be a multiple of 8.');
        }

        this.keyPair.generate(bits, exp.toString(16));
        this.$cache = {};
        return this;
    };

    /**
     * Load key from PEM string
     * @param pem {string}
     */
    NodeRSA.prototype.importKey = function (pem) {
        if (Buffer.isBuffer(pem)) {
            pem = pem.toString('utf8');
        }

        if (/^\s*-----BEGIN RSA PRIVATE KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END RSA PRIVATE KEY-----\s*$/g.test(pem)) {
            this.$loadFromPrivatePEM(pem, 'base64');
        } else if (/^\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END PUBLIC KEY-----\s*$/g.test(pem)) {
            this.$loadFromPublicPEM(pem, 'base64');
        } else
            throw Error('Invalid PEM format');

        this.$cache = {};
    };

    /**
     * Make key form private PEM string
     *
     * @param privatePEM {string}
     */
    NodeRSA.prototype.$loadFromPrivatePEM = function (privatePEM, encoding) {
        var pem = privatePEM
            .replace('-----BEGIN RSA PRIVATE KEY-----', '')
            .replace('-----END RSA PRIVATE KEY-----', '')
            .replace(/\s+|\n\r|\n|\r$/gm, '');
        var reader = new ber.Reader(new Buffer(pem, 'base64'));

        reader.readSequence();
        reader.readString(2, true); // just zero
        this.keyPair.setPrivate(
            reader.readString(2, true),  // modulus
            reader.readString(2, true),  // publicExponent
            reader.readString(2, true),  // privateExponent
            reader.readString(2, true),  // prime1
            reader.readString(2, true),  // prime2
            reader.readString(2, true),  // exponent1 -- d mod (p1)
            reader.readString(2, true),  // exponent2 -- d mod (q-1)
            reader.readString(2, true)   // coefficient -- (inverse of q) mod p
        );

    };

    /**
     * Make key form public PEM string
     *
     * @param publicPEM {string}
     */
    NodeRSA.prototype.$loadFromPublicPEM = function (publicPEM, encoding) {
        var pem = publicPEM
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\s+|\n\r|\n|\r$/gm, '');
        var reader = new ber.Reader(new Buffer(pem, 'base64'));

        reader.readSequence();
        var header = new ber.Reader(reader.readString(0x30, true));
        if (header.readOID(0x06, true) !== PUBLIC_RSA_OID) {
            throw Error('Invalid Public key PEM format');
        }

        var body = new ber.Reader(reader.readString(0x03, true));
        body.readByte();
        body.readSequence();
        this.keyPair.setPublic(
            body.readString(0x02, true), // modulus
            body.readString(0x02, true)  // publicExponent
        );
    };

    /**
     * Check if key pair contains private key
     */
    NodeRSA.prototype.isPrivate = function () {
        return this.keyPair.n && this.keyPair.e && this.keyPair.d || false;
    };

    /**
     * Check if key pair contains public key
     * @param strict {boolean} - public key only, return false if have private exponent
     */
    NodeRSA.prototype.isPublic = function (strict) {
        return this.keyPair.n && this.keyPair.e && !(strict && this.keyPair.d) || false;
    };

    /**
     * Check if key pair doesn't contains any data
     */
    NodeRSA.prototype.isEmpty = function (strict) {
        return !(this.keyPair.n || this.keyPair.e || this.keyPair.d);
    };

    /**
     * Encrypting data method
     *
     * @param buffer {string|number|object|array|Buffer} - data for encrypting. Object and array will convert to JSON string.
     * @param encoding {string} - optional. Encoding for output result, may be 'buffer', 'binary', 'hex' or 'base64'. Default 'buffer'.
     * @param source_encoding {string} - optional. Encoding for given string. Default utf8.
     * @returns {string|Buffer}
     */
    NodeRSA.prototype.encrypt = function (buffer, encoding, source_encoding) {
        try {
            var res = this.keyPair.encrypt(this.$getDataForEncrypt(buffer, source_encoding));

            if (encoding == 'buffer' || !encoding) {
                return res;
            } else {
                return res.toString(encoding);
            }
        } catch (e) {
            throw Error('Error during encryption. Original error: ' + e);
        }
    };

    /**
     * Decrypting data method
     *
     * @param buffer {Buffer} - buffer for decrypting
     * @param encoding - encoding for result string, can also take 'json' or 'buffer' for the automatic conversion of this type
     * @returns {Buffer|object|string}
     */
    NodeRSA.prototype.decrypt = function (buffer, encoding) {
        try {
            buffer = _.isString(buffer) ? new Buffer(buffer, 'base64') : buffer;
            var res = this.keyPair.decrypt(buffer);
            if (res === null) {
                throw Error('Key decrypt method returns null.');
            }
            return this.$getDecryptedData(res, encoding);
        } catch (e) {
            throw Error('Error during decryption (probably incorrect key). Original error: ' + e);
        }
    };

    /**
     *  Signing data
     *
     * @param buffer {string|number|object|array|Buffer} - data for signing. Object and array will convert to JSON string.
     * @param encoding {string} - optional. Encoding for output result, may be 'buffer', 'binary', 'hex' or 'base64'. Default 'buffer'.
     * @param source_encoding {string} - optional. Encoding for given string. Default utf8.
     * @returns {string|Buffer}
     */
    NodeRSA.prototype.sign = function (buffer, encoding, source_encoding) {
        if (!this.isPrivate()) {
            throw Error("It is not private key");
        }
        var res = this.keyPair.sign(this.$getDataForEncrypt(buffer, source_encoding));

        if (encoding && encoding != 'buffer') {
            res = res.toString(encoding);
        }
        return res;
    };

    /**
     *  Verifying signed data
     *
     * @param buffer - signed data
     * @param signature
     * @param source_encoding {string} - optional. Encoding for given string. Default utf8.
     * @param signature_encoding - optional. Encoding of given signature. May be 'buffer', 'binary', 'hex' or 'base64'. Default 'buffer'.
     * @returns {*}
     */
    NodeRSA.prototype.verify = function (buffer, signature, source_encoding, signature_encoding) {
        if (!this.isPublic()) {
            throw Error("It is not public key");
        }
        signature_encoding = (!signature_encoding || signature_encoding == 'buffer' ? null : signature_encoding);
        return this.keyPair.verify(this.$getDataForEncrypt(buffer, source_encoding), signature, signature_encoding);
    };

    NodeRSA.prototype.exportPrivate = function (format) {
        if (!this.isPrivate()) {
            throw Error("It is not private key");
        }

        format = format || DEFAULT_EXPORT_PRIVATE_FORMAT;
        if (this.$cache.privateKey && this.$cache.privateKey[format]) {
            return this.$cache.privateKey[format];
        } else {
            var fmt = format.split('-');
            if (!formats.isPrivateExport(fmt[0])) {
                throw Error('Unsupported private key export format');
            }

            this.$cache.privateKey = this.$cache.privateKey || {};
            return this.$cache.privateKey[format] = formats[fmt[0]].privateExport(this.keyPair, fmt[1]);
        }
    };

    NodeRSA.prototype.exportPublic = function (format) {
        if (!this.isPublic()) {
            throw Error("It is not public key");
        }

        format = format || DEFAULT_EXPORT_PUBLIC_FORMAT;
        if (this.$cache.publicKey && this.$cache.publicKey[format]) {
            return this.$cache.publicKey[format];
        } else {
            var fmt = format.split('-');
            if (!formats.isPublicExport(fmt[0])) {
                throw Error('Unsupported public key export format');
            }

            this.$cache.publicKey = this.$cache.publicKey || {};
            return this.$cache.publicKey[format] = formats[fmt[0]].publicExport(this.keyPair, fmt[1]);
        }
    };

    NodeRSA.prototype.getKeySize = function () {
        return this.keyPair.keySize;
    };

    NodeRSA.prototype.getMaxMessageSize = function () {
        return this.keyPair.maxMessageLength;
    };

    /**
     * Preparing given data for encrypting/signing. Just make new/return Buffer object.
     *
     * @param buffer {string|number|object|array|Buffer} - data for encrypting. Object and array will convert to JSON string.
     * @param encoding {string} - optional. Encoding for given string. Default utf8.
     * @returns {Buffer}
     */
    NodeRSA.prototype.$getDataForEncrypt = function (buffer, encoding) {
        if (_.isString(buffer) || _.isNumber(buffer)) {
            return new Buffer('' + buffer, encoding || 'utf8');
        } else if (Buffer.isBuffer(buffer)) {
            return buffer;
        } else if (_.isObject(buffer)) {
            return new Buffer(JSON.stringify(buffer));
        } else {
            throw Error("Unexpected data type");
        }
    };

    /**
     *
     * @param buffer {Buffer} - decrypted data.
     * @param encoding - optional. Encoding for result output. May be 'buffer', 'json' or any of Node.js Buffer supported encoding.
     * @returns {*}
     */
    NodeRSA.prototype.$getDecryptedData = function (buffer, encoding) {
        encoding = encoding || 'buffer';

        if (encoding == 'buffer') {
            return buffer;
        } else if (encoding == 'json') {
            return JSON.parse(buffer.toString());
        } else {
            return buffer.toString(encoding);
        }
    };

    /**
     * private
     * Recalculating properties
     */
    /*NodeRSA.prototype.$recalculateCache = function () {
        this.$cache.privatePEM = this.$makePrivatePEM();
    };*/

    /**
     * private
     * @returns {string} private PEM string
     */
    /*NodeRSA.prototype.$makePrivatePEM = function () {
        if (!this.isPrivate()) {
            return null;
        }

        var n = this.keyPair.n.toBuffer();
        var d = this.keyPair.d.toBuffer();
        var p = this.keyPair.p.toBuffer();
        var q = this.keyPair.q.toBuffer();
        var dmp1 = this.keyPair.dmp1.toBuffer();
        var dmq1 = this.keyPair.dmq1.toBuffer();
        var coeff = this.keyPair.coeff.toBuffer();

        var length = n.length + d.length + p.length + q.length + dmp1.length + dmq1.length + coeff.length + 512; // magic
        var writer = new ber.Writer({size: length});

        writer.startSequence();
        writer.writeInt(0);
        writer.writeBuffer(n, 2);
        writer.writeInt(this.keyPair.e);
        writer.writeBuffer(d, 2);
        writer.writeBuffer(p, 2);
        writer.writeBuffer(q, 2);
        writer.writeBuffer(dmp1, 2);
        writer.writeBuffer(dmq1, 2);
        writer.writeBuffer(coeff, 2);
        writer.endSequence();

        return '-----BEGIN RSA PRIVATE KEY-----\n' +
            utils.linebrk(writer.buffer.toString('base64'), 64) +
            '\n-----END RSA PRIVATE KEY-----';
    };
*/

    return NodeRSA;
})();
