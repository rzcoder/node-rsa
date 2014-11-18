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
     * @param key {string|buffer|object} Key in PEM format, or data for generate key {b: bits, e: exponent}
     * @constructor
     */
    function NodeRSA(key, options) {
        if (! this instanceof NodeRSA)
            return new NodeRSA(key, options);

        this.keyPair = new rsa.Key();
        this.$cache = {};
		
		if(options){
			console.warn("There are no more options and the parameter is deprecated. It may be removed in the future.");
			if(options.signingAlgorithm){
				console.warn("options.signingAlgorithm has been removed. In order to change the signature hashing algorithm create a signature scheme with the appropriate options and set NodeRSA.schemeSignature to that object. Schemes are defined in src/libs/rsa.js Default is RSASSA-PSS (RSA.PSS) with the hashing function sha1");
				this.schemeSignature = new rsa.PKCS1({hash: options.signingAlgorithm});
			}
			if(options.environment)
				console.warn("options.environment has been removed since all encryption is now done through the rsa.js library");
		}

        if (Buffer.isBuffer(key) || _.isString(key)) {
            this.loadFromPEM(key);
        } else if (_.isObject(key)) {
            this.generateKeyPair(key.b, key.e);
        }
    }
	
	NodeRSA.RSA = rsa;

    /**
     * Generate private/public keys pair
     *
     * @param bits {int} length key in bits. Default 2048.
     * @param exp {int} public exponent. Default 65537.
     * @returns {NodeRSA}
     */
    NodeRSA.prototype.generateKeyPair = function(bits, exp) {
        bits = bits || 2048;
        exp = exp || 65537;

        if (bits % 8 !== 0) {
            throw Error('Key size must be a multiple of 8.');
        }

        this.keyPair.generate(bits, exp.toString(16));
        this.$recalculateCache();
        return this;
    };

    /**
     * Load key from PEM string
     * @param pem {string}
     */
    NodeRSA.prototype.loadFromPEM = function(pem) {
        if (Buffer.isBuffer(pem)) {
            pem = pem.toString('utf8');
        }

        if (/^\s*-----BEGIN RSA PRIVATE KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END RSA PRIVATE KEY-----\s*$/g.test(pem)) {
            this.$loadFromPrivatePEM(pem, 'base64');
        } else if (/^\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=]+\s*)+-----END PUBLIC KEY-----\s*$/g.test(pem)) {
            this.$loadFromPublicPEM(pem, 'base64');
        } else
            throw Error('Invalid PEM format');

        this.$recalculateCache();
    };

    /**
     * Make key form private PEM string
     *
     * @param privatePEM {string}
     */
    NodeRSA.prototype.$loadFromPrivatePEM = function(privatePEM, encoding) {
        var pem = privatePEM
            .replace('-----BEGIN RSA PRIVATE KEY-----','')
            .replace('-----END RSA PRIVATE KEY-----','')
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
    NodeRSA.prototype.$loadFromPublicPEM = function(publicPEM, encoding) {
        var pem = publicPEM
            .replace('-----BEGIN PUBLIC KEY-----','')
            .replace('-----END PUBLIC KEY-----','')
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
    NodeRSA.prototype.isPrivate = function() {
        return this.keyPair.n && this.keyPair.e && this.keyPair.d || false;
    };

    /**
     * Check if key pair contains public key
     * @param strict {boolean} - public key only, return false if have private exponent
     */
    NodeRSA.prototype.isPublic = function(strict) {
        return this.keyPair.n && this.keyPair.e && !(strict && this.keyPair.d) || false;
    };

    /**
     * Check if key pair doesn't contains any data
     */
    NodeRSA.prototype.isEmpty = function(strict) {
        return !(this.keyPair.n || this.keyPair.e || this.keyPair.d);
    };

	/*
	 * In order to use a different encryption/signing/padding scheme then the default (OAEP for encrypting and PSS for signing)
	 * create a new scheme object with desired options and set the appropriate variable to that scheme object.
	 * Scheme classes are located in rsa.js and new ones can be easily added.
	 */
    Object.defineProperties(NodeRSA.prototype, {
		schemeEncryption: {
			enumerable: true,
			get: function(){ return this.keyPair.schemeEncryption; },
			set: function(scheme){ this.keyPair.schemeEncryption = scheme; }
		},
		
		schemeSignature: {
			enumerable: true,
			get: function(){ return this.keyPair.schemeSignature; },
			set: function(scheme){ this.keyPair.schemeSignature = scheme; }
		}
	});
	
    /**
     * Encrypting data method
     *
     * @param buffer {string|number|object|array|Buffer} - data for encrypting. Object and array will convert to JSON string.
     * @param encoding {string} - optional. Encoding for output result, may be 'buffer', 'binary', 'hex' or 'base64'. Default 'buffer'.
     * @param source_encoding {string} - optional. Encoding for given string. Default utf8.
     * @returns {string|Buffer}
     */
    NodeRSA.prototype.encrypt = function(buffer, encoding, source_encoding){
		buffer = this.$getDataForEcrypt(buffer, source_encoding);
		try{
	        var res = this.keyPair.encrypt(buffer);
		} catch(e){
			console.warn(e.message);
			return null;
		}

        if (encoding == 'buffer' || !encoding) {
            return res;
        } else {
            return res.toString(encoding);
        }
    };

    /**
     * Decrypting data method
     *
     * @param buffer {Buffer} - buffer for decrypting, or base64 string
     * @param encoding - encoding for result string, can also take 'json' or 'buffer' for the automatic conversion of this type. Default "utf8"
     * @returns {string|Buffer|object}
     */
    NodeRSA.prototype.decrypt = function(buffer, encoding){
        buffer = _.isString(buffer) ? new Buffer(buffer, 'base64') : buffer;
		var clone = new Buffer(buffer.length);
			buffer.copy(clone);
		try{
	        return this.$getDecryptedData(this.keyPair.decrypt(clone), encoding);
		} catch(e){
			console.warn(e.message);
			return null;
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
    NodeRSA.prototype.sign = function(buffer, encoding, source_encoding){
        if(!this.isPrivate()) throw Error("It is not private key");
		
		// Move all the lifting to rsa.js module due to its wider options.
		try{
			var res = this.keyPair.sign(this.$getDataForEcrypt(buffer, source_encoding));
		} catch(e){
			console.warn(e.message);
			return null;
		}
		
		if(encoding && encoding != 'buffer')
			return res.toString(encoding);
		
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
    NodeRSA.prototype.verify = function(buffer, signature, source_encoding, signature_encoding){
		if(!this.isPublic()) throw Error("It is not public key");

		signature_encoding = (!signature_encoding || signature_encoding == 'buffer' ? null : signature_encoding);
		try{
			return this.keyPair.verify(this.$getDataForEcrypt(buffer, source_encoding), signature, signature_encoding);
		} catch(e){
			console.warn(e.message);
			return false;
		}
    };

    NodeRSA.prototype.getPrivatePEM = function () {
        if (!this.isPrivate()) {
            throw Error("It is not private key");
        }

        return this.$cache.privatePEM;
    };

    NodeRSA.prototype.getPublicPEM = function () {
        if (!this.isPublic()) {
            throw Error("It is not public key");
        }

        return this.$cache.publicPEM;
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
    NodeRSA.prototype.$getDataForEcrypt = function(buffer, encoding) {
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
    NodeRSA.prototype.$getDecryptedData = function(buffer, encoding) {
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
    NodeRSA.prototype.$recalculateCache = function() {
        this.$cache.privatePEM = this.$makePrivatePEM();
        this.$cache.publicPEM = this.$makePublicPEM();
    };

    /**
     * private
     * @returns {string} private PEM string
     */
    NodeRSA.prototype.$makePrivatePEM = function() {
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

    /**
     * private
     * @returns {string} public PEM string
     */
    NodeRSA.prototype.$makePublicPEM = function() {
        if (!this.isPublic()) {
            return null;
        }

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

        return '-----BEGIN PUBLIC KEY-----\n' +
            utils.linebrk(writer.buffer.toString('base64'), 64) +
            '\n-----END PUBLIC KEY-----';
    };

    return NodeRSA;
})();
