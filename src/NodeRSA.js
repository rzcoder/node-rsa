/*!
 * RSA library for Node.js
 *
 * Copyright (c) 2014 rzcoder
 * All Rights Reserved.
 *
 * License BSD
 */

var rsa = require('./libs/rsa.js');
var ber = require('asn1').Ber;
var _ = require('lodash');
var utils = require('./utils');

var PUBLIC_RSA_OID = '1.2.840.113549.1.1.1';

module.exports = (function() {
    /**
     * @param arg {string|object} Key in PEM format, or data for generate key {b: bits, e: exponent}
     * @constructor
     */
    function NodeRSA(arg) {
        this.keyPair = new rsa.Key();

        if (_.isObject(arg)) {
            this.generateKeyPair(arg.b, arg.e);
        } else if (_.isString(arg)) {
            this.loadFromPEM(arg);
        }
    }

    /**
     * Generate private/public keys pair
     *
     * @param bits {int} length key in bits. Default 2048.
     * @param exp {int} public exponent. Default 65537.
     * @returns {NodeRSA}
     */
    NodeRSA.prototype.generateKeyPair = function(bits, exp) {
        bits = bits || 2048;
        exp = 65537;

        this.keyPair.generate(bits, exp.toString(16));
        return this;
    };

    /**
     * Load key from PEM string
     * @param pem {string}
     */
    NodeRSA.prototype.loadFromPEM = function(pem) {
        if (/^-----BEGIN RSA PRIVATE KEY-----\s([A-Za-z0-9+/=]+\s)+-----END RSA PRIVATE KEY-----$/g.test(pem)) {
            this.loadFromPrivatePEM(pem, 'base64');
        } else if (/^-----BEGIN PUBLIC KEY-----\s([A-Za-z0-9+/=]+\s)+-----END PUBLIC KEY-----$/g.test(pem)) {
            this.loadFromPublicPEM(pem, 'base64');
        } else
            throw Error('Invalid PEM format');
    };

    /**
     * Make key form private PEM string
     *
     * @param publicPEM {string}
     */
    NodeRSA.prototype.loadFromPrivatePEM = function(privatePEM, encoding) {
        var pem = privatePEM.replace('-----BEGIN RSA PRIVATE KEY-----','').replace('-----END RSA PRIVATE KEY-----','');
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
     * @param privatePEM {string}
     */
    NodeRSA.prototype.loadFromPublicPEM = function(publicPEM, encoding) {
        var pem = publicPEM.replace('-----BEGIN PUBLIC KEY-----','').replace('-----END PUBLIC KEY-----','');
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
     * @returns {string} private PEM string
     */
    NodeRSA.prototype.toPrivatePEM = function() {
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

    /**
     * @returns {string} public PEM string
     */
    NodeRSA.prototype.toPublicPEM = function() {
        var n = this.keyPair.n.toBuffer();
        var length = n.length + 512; // magic

        var bodyWriter = new ber.Writer({size: length});
        bodyWriter.writeByte(0);
        bodyWriter.startSequence();
        bodyWriter.writeBuffer(n, 2);
        bodyWriter.writeInt(this.keyPair.e);
        bodyWriter.endSequence();
        var body = bodyWriter.buffer;

        var writer = new ber.Writer({size: length});
        writer.startSequence();
        writer.startSequence();
        writer.writeOID(PUBLIC_RSA_OID);
        writer.writeNull();
        writer.endSequence();
        writer.writeBuffer(body, 3);
        writer.endSequence();

        n = writer.buffer.toString('hex');

        return '-----BEGIN PUBLIC KEY-----\n' +
            utils.linebrk(writer.buffer.toString('base64'), 64) +
            '\n-----END PUBLIC KEY-----';
    };

    /**
     * Check if keypair contains private key
     */
    NodeRSA.prototype.isPrivate = function() {
        return this.keyPair.n && this.keyPair.e && this.keyPair.d;
    };

    /**
     * Check if keypair contains public key
     * @param strict {boolean} - public key only, return false if have private exponent
     */
    NodeRSA.prototype.isPublic = function(strict) {
        return this.keyPair.n && this.keyPair.e && !(strict && this.keyPair.d);
    };

    /**
     * Encrypting data method
     *
     * @param buffer {string|number|object|array|Buffer} - data for encrypting. Object and array will convert to JSON string.
     * @param source_encoding {string} - optional. Encoding for given string. Default utf8.
     * @param output_encoding {string} - optional. Encoding for output result, can also take 'buffer' to return Buffer object. Default base64.
     * @returns {string|Buffer}
     */
    NodeRSA.prototype.encrypt = function(buffer, source_encoding, output_encoding) {
        var res = null;

        if (_.isString(buffer) || _.isNumber(buffer)) {
            res = this.keyPair.encrypt(new Buffer('' + buffer, source_encoding || 'utf8'));
        } else if (Buffer.isBuffer(buffer)) {
            res = this.keyPair.encrypt(buffer);
        } else if (_.isObject(buffer)) {
            res = this.keyPair.encrypt(new Buffer(JSON.stringify(buffer)));
        }

        if (output_encoding == 'buffer') {
            return res;
        } else {
            return res.toString(output_encoding || 'base64');
        }
    };

    /**
     * Decrypting data method
     *
     * @param buffer {Buffer} - buffer for decrypting
     * @param encoding - encoding for result string, can also take 'json' or 'buffer' for the automatic conversion of this type
     * @returns {Buffer|object|string}
     */
    NodeRSA.prototype.decrypt = function(buffer, encoding) {
        encoding = encoding || 'utf8';

        buffer = _.isString(buffer) ? new Buffer(buffer, 'base64') : buffer;
        var res = this.keyPair.decrypt(buffer);

        if (encoding == 'buffer') {
            return res;
        } else if (encoding == 'json') {
            return JSON.parse(res.toString());
        } else {
            return res.toString(encoding);
        }
    };

     return NodeRSA;
})();