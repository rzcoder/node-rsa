/*
 * RSA Encryption / Decryption with PKCS1 v2 Padding.
 * 
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

/*
 * Node.js adaptation
 * long message support implementation
 * signing/verifying
 *
 * 2014 rzcoder
 */

/*
 * OAEP / Padding function modifications
 * 
 * Modified Key object to accept a padding key in it's options object.
 * padding key's value may be any object with the appropriate properties & method signatures:
 *		Encryption Schemes
 *		maxMessageLength(key:RSA.Key):uint
 *		encrypt(key:RSA.Key, message:Buffer):Buffer
 *		decrypt(key:RSA.Key, encryptedMessage:Buffer):Buffer
 *		
 *		Signature Schemes
 *		sign(key:RSA.Key, data:Buffer):Buffer
 *		verify(key:RSA.Key, data:Buffer, signature:Buffer):Boolean
 *		
 * If a padding scheme has options then the padding value can be an instantiated class.
 * This allows for future changes by making it easy to add new schemes.
 * This also allows for users to implement their own padding schemes, although not recommended.
 * 
 * 2014 BAM5
 */

var crypt = require('crypto');
var BigInteger = require("./jsbn.js");
var utils = require('../utils.js');
var _ = require('lodash');

var RSA = module.exports;

RSA.$$digestLength = { // In Bytes
	"md2":		16,
	"md5":		16,
	"sha1":		20,
	"sha256":	32,
	"sha384":	48,
	"sha512":	64
};

RSA.BigInteger = BigInteger;
RSA.Key = (function() {
    /**
     * RSA key constructor
     *
     * n - modulus
     * e - publicExponent
     * d - privateExponent
     * p - prime1
     * q - prime2
     * dmp1 - exponent1 -- d mod (p1)
     * dmq1 - exponent2 -- d mod (q-1)
     * coeff - coefficient -- (inverse of q) mod p
     */
    function RSAKey() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
		
		this.usedSign = false;
		this.usedDecrypt = false;
		
		// Default schemes as per recommendation by specification
		this.schemeEncryption = RSA.OAEP.Default;
		this.schemeSignature = RSA.PSS.Default;
    }

    /**
     * Generate a new random private key B bits long, using public expt E
     * @param B
     * @param E
     */
    RSAKey.prototype.generate = function (B, E) {
        var qs = B >> 1;
        this.e = parseInt(E, 16);
        var ee = new BigInteger(E, 16);
        for (; ;) {
            for (; ;) {
                this.p = new BigInteger(B - qs, 1);
                if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 && this.p.isProbablePrime(10))
                    break;
            }
            for (; ;) {
                this.q = new BigInteger(qs, 1);
                if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 && this.q.isProbablePrime(10))
                    break;
            }
            if (this.p.compareTo(this.q) <= 0) {
                var t = this.p;
                this.p = this.q;
                this.q = t;
            }
            var p1 = this.p.subtract(BigInteger.ONE);
            var q1 = this.q.subtract(BigInteger.ONE);
            var phi = p1.multiply(q1);
            if (phi.gcd(ee).compareTo(BigInteger.ONE) === 0) {
                this.n = this.p.multiply(this.q);
                this.d = ee.modInverse(phi);
                this.dmp1 = this.d.mod(p1);
                this.dmq1 = this.d.mod(q1);
                this.coeff = this.q.modInverse(this.p);
                break;
            }
        }
        this.$$recalculateCache();
    };

    /**
     * Set the private key fields N, e, d and CRT params from buffers
     *
     * @param N
     * @param E
     * @param D
     * @param P
     * @param Q
     * @param DP
     * @param DQ
     * @param C
     */
    RSAKey.prototype.setPrivate = function (N, E, D, P, Q, DP, DQ, C) {
        if (N && E && D && N.length > 0 && E.length > 0 && D.length > 0) {
            this.n = new BigInteger(N);
            this.e = utils.get32IntFromBuffer(E, 0);
            this.d = new BigInteger(D);

            if (P && Q && DP && DQ && C) {
                this.p = new BigInteger(P);
                this.q = new BigInteger(Q);
                this.dmp1 = new BigInteger(DP);
                this.dmq1 = new BigInteger(DQ);
                this.coeff = new BigInteger(C);
            } else {
                // TODO: re-calculate any missing CRT params
            }
            this.$$recalculateCache();
        } else
            throw Error("Invalid RSA private key");
    };

    /**
     * Set the public key fields N and e from hex strings
     * @param N
     * @param E
     */
    RSAKey.prototype.setPublic = function (N, E) {
        if (N && E && N.length > 0 && E.length > 0) {
            this.n = new BigInteger(N);
            this.e = utils.get32IntFromBuffer(E, 0);
            this.$$recalculateCache();
        } else
            throw Error("Invalid RSA public key");
    };

    /**
     * private
     * Perform raw private operation on "x": return x^d (mod n)
     *
     * @param x
     * @returns {*}
     */
    RSAKey.prototype.$doPrivate = function (x) {
        if (this.p || this.q)
            return x.modPow(this.d, this.n);

        // TODO: re-calculate any missing CRT params
        var xp = x.mod(this.p).modPow(this.dmp1, this.p);
        var xq = x.mod(this.q).modPow(this.dmq1, this.q);

        while (xp.compareTo(xq) < 0)
            xp = xp.add(this.p);
        return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
    };

    /**
     * private
     * Perform raw public operation on "x": return x^e (mod n)
     *
     * @param x
     * @returns {*}
     */
    RSAKey.prototype.$doPublic = function (x) {
        return x.modPowInt(this.e, this.n);
    };

    /**
     * Return the encryption of buffer with the given scheme, if no scheme is given then this.schemeEncryption is used.
     * @param buffer {Buffer}
     * @param scheme {Object}
     * @returns {Buffer}
     */
    RSAKey.prototype.encrypt = function (buffer, scheme){
		scheme = scheme || this.schemeEncryption;
        var results = [];
		var i, encrypted, temp;
        var chunks = new Array(Math.ceil(buffer.length / scheme.maxMessageLength(this)) || 1);
		
        if(chunks.length == 1)
            chunks[0] = buffer;
        else{
			// Message is too long to be encrypted. Cut message up into smaller encryptable message chunks.
			var chunkSize = Math.ceil(buffer.length / chunks.length || 1); // each buffer size
            for(i = 0; i<chunks.length; i++)
                chunks[i] = buffer.slice(i * chunkSize, (i+1) * chunkSize);
		}
		
        for(i = 0; i<chunks.length; i++){
			encrypted = scheme.encrypt(this, chunks[i]);
			if(encrypted.length < this.encryptedDataLength){
				temp = encrypted;
				encrypted = new Buffer(this.encryptedDataLength);
				encrypted.fill(0, 0, encrypted.length - temp.length); // Fill beginning of array with 0s. This is necessarry because octets in Buffer are uninitiated and can be any value.
				temp.copy(encrypted, encrypted.length - temp.length); // Copy temp to 
			} else if(encrypted.length > this.encryptedDataLength) throw new Error("The returned encrypted message is too long. This is most likely an issue with the scheme that is being used.");
			results.push(encrypted);
        }

        return Buffer.concat(results);
    };

    /**
     * Return the decryption of buffer that uses the given scheme, if scheme is not set then this.schemeEncryption is presumed to be the scheme used in this message.
     * @param buffer {Buffer} This buffer may get mangled to save memory depending on the scheme function used.
     * @returns {Buffer}
     */
    RSAKey.prototype.decrypt = function (buffer, scheme){
		if(this.usedSign) console.warn("It is against recommendations to use the same private key for encryption and signatures.")
		this.usedDecrypt = true;
		
        if(buffer.length % this.encryptedDataLength !== 0)
            throw Error("Incorrect data or key, the buffer must have a length that is the multiple of this key's length");
		
		scheme = scheme || this.schemeEncryption;

        var result = [];
        var chunkCount = buffer.length / this.encryptedDataLength;

        for(var i = 0; i < chunkCount; i++)
			result.push(scheme.decrypt(
				this,								// Key
				buffer.slice(						// Cut out a chunk of the buffer to decrypt with Key
					i*this.encryptedDataLength,		// Beginning of chunk
					(i+1)*this.encryptedDataLength	// End of chunk
				)
			));

        return Buffer.concat(result);
    };
	
	
    RSAKey.prototype.sign = function (data, hashAlgorithm) {
		if(this.usedDecrypt) console.warn("It is against recommendations to use the same private key for encryption and signatures.")
		if(this.hashAlgorithm){
			console.warn("! hashAlgorithm parameter is deprecated and may be removed in future versions.");
			if(!RSA.PKCS1.Temp) RSA.PKCS1.Temp = new RSA.PKCS1();
			RSA.PKCS1.Temp.options.hash = hashAlgorithm;
			var signature = RSA.PKCS1.Temp.sign(this, data);
		} else
        	var signature = this.schemeSignature.sign(this, data);
		
		this.usedSign = true;
        return signature;

    };

    RSAKey.prototype.verify = function (buffer, signature, signature_encoding, hashAlgorithm) {
        if(signature_encoding)
            signature = new Buffer(signature, signature_encoding);
		
		if(hashAlgorithm){
			console.warn("! hashAlgorithm parameter is deprecated and may be removed in future versions.");
			if(!RSA.PKCS1.Temp) RSA.PKCS1.Temp = new RSA.PKCS1();
			RSA.PKCS1.Temp.options.hash = hashAlgorithm;
			return RSA.PKCS1.Temp.verify(this, buffer, signature);
		}
		
		return this.schemeSignature.verify(this, buffer, signature);
    };
	
   
    Object.defineProperty(RSAKey.prototype, 'keySize', {
        get: function() { return this.cache.keyBitLength; }
    });

    Object.defineProperty(RSAKey.prototype, 'encryptedDataLength', {
        get: function() { return this.cache.keyByteLength; }
    });

    Object.defineProperty(RSAKey.prototype, 'maxMessageLength', {
        get: function() { return this.schemeEncryption.maxMessageLength(this); }
    });

    Object.defineProperties(RSAKey.prototype, {
		schemeEncryption: {
			enumerable: true,
			get: function(){ return this._schemeEncryption; },
			set: function(scheme){
				if(RSA.isEncryptionScheme(scheme)) this._schemeEncryption = scheme;
				else throw new Error("Provided object is not an encryption scheme");
			}
		},
		
		schemeSignature: {
			enumerable: true,
			get: function(){ return this._schemeSignature; },
			set: function(scheme){
				if(RSA.isSignatureScheme(scheme)) this._schemeSignature = scheme;
				else throw new Error("Provided object is not a signature scheme");
			}
		}
	});

    /**
     * Caching key data
     */
    RSAKey.prototype.$$recalculateCache = function () {
		this.cache = this.cache || {};
		// Bit & byte length
		this.cache.keyBitLength = this.n.bitLength();
		this.cache.keyBitLength += this.cache.keyBitLength % 2;
		this.cache.keyByteLength = (this.cache.keyBitLength + 6) >> 3;
    };


    return RSAKey;
})();





RSA.isEncryptionScheme = function(object){
	return ("maxMessageLength" in object && "encrypt" in object && "decrypt" in object);
};

RSA.isSignatureScheme = function(object){
	return ("sign" in object && "verify" in object);
};

RSA.OAEP = (function(){
	
	// OAEP Padding Scheme
	
	/*
	 * Retuns an object that OAEP pads, encodes, and encrypts buffer objects with the options specified in options.
	 * 
	 * options	[Object]	Options for the encoding (The defaults should be used unless in special use cases and user knows what they're doing)
	 * ├>label		[Buffer]	Value to pass to the $$eme_oaep_encode and $$eme_oaep_decode functions as the L parameter.
	 * ├>hash		[String]	The hashing function to use when encoding and creating checksums (Default: "sha1")(only SHA-1 and SHA-256/384/512 are recommended)(L parameter max size depends on hashing function, however sha1 and sha256's size limit are too large to touch (TBytes) so length checking is NOT implemented)
	 * └>mgf		[function]	The mask generation function (Default: OAEP.$$eme_oaep_mgf1)
	 * 
	 *	
	 * @param {Object} options
	 * @returns {RSA.OAEP}
	 */
	var OAEP = function(options){
		if(!options) options = {};
		this.options = options;
		this.count = 0;
	};
	
	OAEP.prototype.maxMessageLength = function(key){
		return key.encryptedDataLength - 2*RSA.$$digestLength[this.options.hash] - 2;
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-7.1.1
	 * 
	 * @param {RSA.Key} key
	 * @param {Buffer} message
	 * @returns {Buffer}
	 */
	OAEP.prototype.encrypt = function(key, message){
		var m = OAEP.$$eme_oaep_encode(message, this.options.label, key.encryptedDataLength, this.options);
		m = new BigInteger(m);
		m = key.$doPublic(m);
		m = m.toBuffer(key.encryptedDataLength);
		return m;
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-7.1.2
	 * 
	 * @param {RSA.Key} key
	 * @param {Buffer} encMessage
	 * @returns {Buffer}
	 */
	OAEP.prototype.decrypt = function(key, encMessage){
		if(encMessage.length != key.encryptedDataLength || encMessage.length < 2*RSA.$$digestLength[this.options.hash] + 2)
			throw new Error("Decryption Error");
		
		encMessage = new BigInteger(encMessage);
		encMessage = key.$doPrivate(encMessage);
		encMessage = encMessage.toBuffer(key.encryptedDataLength);
		
		return OAEP.$$eme_oaep_decode(encMessage, this.options.label, this.options);
	};
	
	
	
	
	
	/*
	 * OAEP Mask Generation Function 1
	 * Generates a buffer full of pseudorandom bytes given seed and maskLength.
	 * Giving the same seed, maskLength, and hashFunction will result in the same exact byte values in the buffer.
	 * 
	 * https://tools.ietf.org/html/rfc3447#appendix-B.2.1
	 * 
	 * Parameters:
	 * seed			[Buffer]	The pseudo random seed for this function
	 * maskLength	[int]		The length of the output
	 * hashFunction	[String]	The hashing function to use. Will accept any valid crypto hash. Default "sha1"
	 *		Supports "sha1" and "sha256".
	 *		To add another algorythm the algorythem must be accepted by crypto.createHash, and then the length of the output of the hash function (the digest) must be added to the digestLength object below.
	 *		Most RSA implementations will be expecting sha1
	 */
	OAEP.$$eme_oaep_mgf1 = function(seed, maskLength, hashFunction){
		hashFunction = hashFunction || "sha1";
		var hLen = RSA.$$digestLength[hashFunction];
		var count = Math.ceil(maskLength / hLen);
		var T = new Buffer(hLen * count);
		var c = new Buffer(4);
		for(var i = 0; i < count; ++i) {
			hash = crypt.createHash(hashFunction);
			hash.write(seed);
			c.writeUInt32BE(i, 0);
			hash.end(c);
			hash.read().copy(T, i*hLen);
		}
		return T.slice(0, maskLength);
	};
	
	/*
	 * Encode message with OAEP format + padding
	 * 
	 * https://tools.ietf.org/html/rfc3447#section-7.1.1
	 * 
	 * Parameters:
	 * M		[Buffer]	The message bytes to be encoded
	 * L		[Buffer]	Label to associate with this message. Usually left blank. (Default: '')
	 * emLen	[int]		Size of the returned encoded message
	 * options	[Object]	Options for the encoding (The defaults should be used unless in special use cases and user knows what they're doing)
	 * ├>hash		[String]	The hashing function to use when encoding and creating checksums (Default: "sha1") (L parameter max size depends on hashing function, however sha1 and sha256's size limit are too large to touch so length checking is NOT implemented)
	 * └>mgf		[function]	The mask generation function (Default: $$eme_oaep_mgf1)
	 */
	OAEP.$$eme_oaep_encode = function(M, L, emLen, options){
		// Prepare options
		if(!options) options = {};
		options.hash =	options.hash	|| "sha1";
		options.mgf =	options.mgf		|| OAEP.$$eme_oaep_mgf1;
		
		var hLen = RSA.$$digestLength[options.hash];
		
		// Make sure we can put message into an encoded message of emLen bytes
		if(M.length > emLen - 2*hLen - 2)
			throw new Error("Message is too long to encode into an encoded message with a length of "+emLen+" bytes, increase emLen to fix this error (minimum value for given parameters and options: "+(emLen - 2*hLen - 2)+")");
		
		L = L || new Buffer(0);
		var lHash = crypt.createHash(options.hash);
			lHash.end(L);
			lHash = lHash.read();
		
		var PS = new Buffer(emLen - M.length - 2*hLen - 1); // Padding "String"
			PS.fill(0); // Fill the buffer with octets of 0
			PS[PS.length-1] = 1;
		
		var DB = Buffer.concat([lHash, PS, M]);
		var seed = crypt.randomBytes(hLen);
		
		// mask = dbMask
		var mask = options.mgf(seed, DB.length, options.hash);
		// XOR DB and dbMask together.
		for(var i = 0; i<DB.length; i++)
			DB[i] ^= mask[i];
		// DB = maskedDB
		
		// mask = seedMask
		mask = options.mgf(DB, hLen, options.hash);
		// XOR seed and seedMask together.
		for(i = 0; i<seed.length; i++)
			seed[i] ^= mask[i];
		// seed = maskedSeed
		
		var em = new Buffer(1 + seed.length + DB.length);
			em[0] = 0;
			seed.copy(em, 1);
			DB.copy(em, 1+seed.length);
		
		return em;
	};
	
	/*
	 * Decode an encoded message that was encoded with OAEP scheme
	 * Note: This method works within the buffer given and modifies the values. It also returns a slice of the EM as the return Message.
	 * If the implementation requires that the EM parameter be unmodified then the implementation should pass in a clone of the EM buffer.
	 * 
	 * https://tools.ietf.org/html/rfc3447#section-7.1.2
	 * 
	 * Parameters:
	 * EM		[Buffer]	The encoded message bytes to be decoded
	 * L		[Buffer]	Label to associate with this message. Usually left blank. (Default: '')
	 * options	[Object]	Options for the decoding (The defaults should be used unless in special use cases and user knows what they're doing)
	 * ├>hash		[String]	The hashing function to use when decoding and checking checksums (Default: "sha1") (L parameter max size depends on hashing function, however sha1 and sha256's size limit are too large to touch so length checking is NOT implemented)
	 * └>mgf		[function]	The mask generation function (Default: $$eme_oaep_mgf1)
	 */
	OAEP.$$eme_oaep_decode = function(EM, L, options){
		// Prepare options
		if(!options) options = {};
		options.hash =	options.hash	|| "sha1";
		options.mgf =	options.mgf		|| OAEP.$$eme_oaep_mgf1;
		
		var hLen = RSA.$$digestLength[options.hash];
		
		// Check to see if EM is a properly encoded OAEP message
		if(EM.length < 2*hLen + 2)
			throw new Error("Error decoding message, the supplied message is not long enough to be a valid OAEP encoded message");
		
		var seed = EM.slice(1, hLen+1);	// seed = maskedSeed
		var DB = EM.slice(1+hLen);		// DB = maskedDB
		
		var mask = options.mgf(DB, hLen, options.hash); // seedMask
		// XOR maskedSeed and seedMask together to get the original seed.
		for(var i = 0; i<seed.length; i++)
			seed[i] ^= mask[i];
		// seed = seed
		
		mask = options.mgf(seed, DB.length, options.hash); // dbMask
		// XOR DB and dbMask together to get the original data block.
		for(i = 0; i<DB.length; i++)
			DB[i] ^= mask[i];
		// DB = DB
		
		
		L = L || new Buffer(0);
		var lHash = crypt.createHash(options.hash);
			lHash.end(L);
			lHash = lHash.read();
		
		var lHashEM = DB.slice(0, hLen);
		if(lHashEM.toString("hex") !=  lHash.toString("hex"))
			throw new Error("Error decoding message, the lHash calculated from the label provided and the lHash in the encrypted data do not match.");
		
		// Filter out padding
		i = hLen;
		while(DB[i++] == 0 && i < DB.length);
		if(DB[i-1] != 1)
			throw new Error("Error decoding message, there is no padding message separator byte");
		
		return DB.slice(i); // Message
	};
	
	
	OAEP.Default = new OAEP();
	
	return OAEP;
})();





RSA.PSS = (function(){
	
	
	// PSS Signature Scheme
	
	/*
	 * Retuns an object that PSS signs buffer objects with the options specified in the options parameter.
	 * 
	 * options	[Object]	Options for the encoding (The defaults should be used unless in special use cases and user knows what they're doing)
	 * ├>hash		[String]	The hashing function to use when generating signatures (Default: "sha1")(only SHA-1 and SHA-256/384/512 are recommended)
	 * ├>mgf		[function]	The mask generation function (Default: RSA.OAEP.$$eme_oaep_mgf1)
	 * └>sLen		[uint]		The length of the salt to generate. (default = 20)
	 * 
	 * @param {Object} options
	 * @returns {RSA.PSS}
	 */
	var PSS = function(options){
		if(!options) options = {};
		this.options = options;
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-8.1.1
	 * 
	 * @param {RSA.Key}	key
	 * @param {Buffer}	data
	 * @returns {Buffer} The generated signature
	 */
	PSS.prototype.sign = function(key, data){
		var encoded = PSS.$$emsa_pss_encode(data, key.keySize - 1, this.options);
		encoded = new BigInteger(encoded);
		return key.$doPrivate(encoded).toBuffer(key.encryptedDataLength);
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-8.1.2
	 * 
	 * @param {RSA.Key}	key
	 * @param {Buffer}	data
	 * @param {Buffer}	signature
	 * @returns {Boolean} True if signature is valid, false otherwise.
	 */
	PSS.prototype.verify = function(key, data, signature){
		signature = new BigInteger(signature);
		
		var emLen = Math.ceil((key.keySize - 1)/8);
		signature = key.$doPublic(signature).toBuffer(emLen);
		
		return PSS.$$emsa_pss_verify(data, signature, key.keySize -1, this.options);
	};
	
	
	
	
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-9.1.1
	 * 
	 * M		[Buffer]	Message to encode
	 * emBits	[uint]		Maximum length of output in bits. Must be at least 8hLen + 8sLen + 9 (hLen = Hash digest length in bytes | sLen = length of salt in bytes)
	 * options	[Object]	An object that contains the following keys that specify certain options for encoding.
	 * ├>hash	[String]	Hash function to use when encoding and generating masks. Must be a string accepted by node's crypto.createHash function. (default = "sha1")
	 * ├>mgf	[function]	The mask generation function to use when encoding. (default = mgf1SHA1)
	 * └>sLen	[uint]		The length of the salt to generate. (default = 20)
	 * 
	 * @returns {Buffer} The encoded message
	 */
	PSS.$$emsa_pss_encode = function(M, emBits, options){
		if(!options) options = {};
		options.hash =	options.hash	|| "sha1";
		options.mgf =	options.mgf		|| RSA.OAEP.$$eme_oaep_mgf1;
		options.sLen =	options.sLen	|| 20;
		
		var hLen = RSA.$$digestLength[options.hash];
		var emLen = Math.ceil(emBits / 8);
		
		if(emLen < hLen + options.sLen + 2)
			throw new Error("Output length passed to emBits("+emBits+") is too small for the options specified("+options.hash+", "+options.sLen+"). To fix this issue increase the value of emBits. (minimum size: "+(8*hLen + 8*options.sLen + 9)+")")
		
		var mHash = crypt.createHash(options.hash);
			mHash.end(M);
			mHash = mHash.read();
		
		var salt = crypt.randomBytes(options.sLen);
		
		var Mapostrophe = new Buffer(8 + hLen + options.sLen);
			Mapostrophe.fill(0, 0, 8);
			mHash.copy(Mapostrophe, 8);
			salt.copy(Mapostrophe, 8+mHash.length);
		
		var H = crypt.createHash(options.hash);
			H.end(Mapostrophe);
			H = H.read();
		
		var PS = new Buffer(emLen - salt.length - hLen - 2);
			PS.fill(0);
		
		var DB = new Buffer(PS.length + 1 + salt.length);
			PS.copy(DB);
			DB[PS.length] = 1;
			salt.copy(DB, PS.length + 1);
		
		var dbMask = options.mgf(H, DB.length, options.hash);
		
		// XOR DB and dbMask together
		for(var i = 0; i<DB.length; i++)
			DB[i] ^= dbMask[i];
		
		var mask = 0;
		for(var i = 0, bits = emBits - 8*(emLen-1); i<bits; i++)
			mask |= 1 << i;
		DB[0] &= mask;
		
		var EM = new Buffer(DB.length + H.length + 1);
			DB.copy(EM, 0);
			H.copy(EM, DB.length);
			EM[EM.length-1] = 0xbc;
		
		return EM;
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-9.1.2
	 * 
	 * M		[Buffer]	Message
	 * EM		[Buffer]	Signature
	 * emBits	[uint]		Length of EM in bits. Must be at least 8hLen + 8sLen + 9 to be a valid signature. (hLen = Hash digest length in bytes | sLen = length of salt in bytes)
	 * options	[Object]	An object that contains the following keys that specify certain options for encoding.
	 * ├>hash	[String]	Hash function to use when encoding. Must be a string accepted by node's crypto.createHash function. (default = "sha1")
	 * ├>mgf	[function]	The mask generation function to use when encoding. (default = mgf1SHA1)
	 * └>sLen	[uint]		The length of the salt to generate. (default = 20)
	 * 
	 * @returns {Boolean} True if signature(EM) matches message(M)
	 */
	PSS.$$emsa_pss_verify = function(M, EM, emBits, options){
		if(!options) options = {};
		options.hash =	options.hash	|| "sha1";
		options.mgf =	options.mgf		|| RSA.OAEP.$$eme_oaep_mgf1;
		options.sLen =	options.sLen	|| 20;
		
		var hLen = RSA.$$digestLength[options.hash];
		var emLen = Math.ceil(emBits / 8);
		
		if(emLen < hLen + options.sLen + 2 || EM[EM.length-1] != 0xbc)
			return false;
		
		var DB = new Buffer(emLen - hLen - 1);
			EM.copy(DB, 0, 0, emLen - hLen - 1);
		
		var mask = 0;
		for(var i = 0, bits = 8*emLen - emBits; i<bits; i++)
			mask |= 1 << (7-i);
		if((DB[0] & mask) != 0)
			return false;
		
		var H = EM.slice(emLen - hLen - 1, emLen - 1);
		var dbMask = options.mgf(H, DB.length, options.hash);
		
		// Unmask DB
		for(var i = 0; i<DB.length; i++)
			DB[i] ^= dbMask[i];
		
		var mask = 0;
		for(var i = 0, bits = emBits - 8*(emLen-1); i<bits; i++)
			mask |= 1 << i;
		DB[0] &= mask;
		
		// Filter out padding
		while(DB[i++] == 0 && i < DB.length);
		if(DB[i-1] != 1)
			return false;
		
		var salt = DB.slice(DB.length - options.sLen);
		
		var mHash = crypt.createHash(options.hash);
			mHash.end(M);
			mHash = mHash.read();
		
		var Mapostrophe = new Buffer(8 + hLen + options.sLen);
			Mapostrophe.fill(0, 0, 8);
			mHash.copy(Mapostrophe, 8);
			salt.copy(Mapostrophe, 8+mHash.length);
		
		var Hapostrophe = crypt.createHash(options.hash);
			Hapostrophe.end(Mapostrophe);
			Hapostrophe = Hapostrophe.read();
		
		return H.toString("hex") == Hapostrophe.toString("hex");
	};
	
	
	
	PSS.Default = new PSS();
	
	return PSS;
})();





RSA.PKCS1 = (function(){
	
	// PKCS1 padding scheme.
	
	/*
	 * options
	 * └>hash	[String] The hashing algorithm to use when signing and verifying.
	 * 
	 * @param {Object} options
	 * @returns {RSA.PKCS1}
	 */
	var PKCS1 = function(options){
		if(!options) options = {};
		this.options = options;
	};
	
	PKCS1.prototype.maxMessageLength = function(key){
		return key.encryptedDataLength - 11;
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-7.2.1
	 * 
	 * @param {RSA.Key}	key
	 * @param {Buffer}	data
	 * @returns {Buffer} Encrypted Data
	 */
	PKCS1.prototype.encrypt = function(key, data){
		if(data.length > key.encryptedDataLength - 11)
			throw new Error("Data is too long to be encrypted.");
		
		var em = PKCS1.$$eme_pkcs1_encode(data, key.encryptedDataLength);
		em = new BigInteger(em);
		em = key.$doPublic(em);
		em = em.toBuffer(key.encryptedDataLength);
		return em;
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-7.2.2
	 * 
	 * @param {RSA.Key}	key
	 * @param {Buffer}	data
	 * @returns {Buffer} Decrypted Data
	 */
	PKCS1.prototype.decrypt = function(key, data){
		if(data.length != key.encryptedDataLength)
			throw new Error("Data is not of the right length to be decrypted by the given key")
		
		data = new BigInteger(data);
		data = key.$doPrivate(data);
		data = data.toBuffer(key.encryptedDataLength);
		
		return PKCS1.$$eme_pkcs1_decode(data);
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-8.2.1
	 * 
	 * @param {RSA.Key}	key
	 * @param {Buffer}	data
	 * @returns {Buffer} Signature
	 */
	PKCS1.prototype.sign = function(key, data){
		var S = PKCS1.$$emsa_pkcs1_v1_5(data, key.encryptedDataLength, this.options.hash);
		S = new BigInteger(S);
		S = key.$doPrivate(S);
		return S.toBuffer(key.encryptedDataLength);
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-8.2.2
	 * 
	 * @param {RSA.Key}	key
	 * @param {Buffer}	data
	 * @param {Buffer}	signature
	 * @returns {Boolean} Whether or not the signature is valid for given data.
	 */
	PKCS1.prototype.verify = function(key, data, signature){
		if(signature.length != key.encryptedDataLength)
			return false;
		
		signature = new BigInteger(signature);
		signature = key.$doPublic(signature);
		signature = signature.toBuffer(key.encryptedDataLength);
		var S = PKCS1.$$emsa_pkcs1_v1_5(data, key.encryptedDataLength, this.options.hash);
		
		return signature.toString("hex") == S.toString("hex");
	};
	
	
	
	

	PKCS1.$$SIGNINFOHEAD = {
		md2:	new Buffer('3020300c06082a864886f70d020205000410',		'hex'),
		md5:    new Buffer('3020300c06082a864886f70d020505000410',		'hex'),
		sha1:   new Buffer('3021300906052b0e03021a05000414',			'hex'),
		sha256: new Buffer('3031300d060960864801650304020105000420',	'hex'),
		sha384:	new Buffer('3041300d060960864801650304020205000430',	'hex'),
		sha512:	new Buffer('3051300d060960864801650304020305000440',	'hex')
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-9.2
	 * 
	 * @param {Buffer}	M				Message to encode.
	 * @param {uint}	emLen			Length of the output encoded message in bytes
	 * @param {String}	hashFunction	The hashing function to use when encoding (Default: "sha1")(SHA-1 or SHA-256/384/512 are recommended for new applications)
	 * @returns {Buffer} The encoded message.
	 */
	PKCS1.$$emsa_pkcs1_v1_5 = function(M, emLen, hashFunction){
		hashFunction = hashFunction || "sha1";
		
		var H = crypt.createHash(hashFunction);
			H.end(M);
			H = H.read();
		
		var tLen = PKCS1.$$SIGNINFOHEAD[hashFunction].length + H.length;
		
		if(emLen < tLen + 11)
			throw new Error("The size of the output message (passed as emLen("+emLen+")) is too small to contain the signature with given hashing function. Minimum emLen with given parameters would be "+(tLen + 11));
		
		var PS = new Buffer(emLen - tLen);
			PS.fill(0xFF, 2);
			PS[0] = 0;
			PS[1] = 1;
			PS[PS.length-1] = 0;
		
		return Buffer.concat([PS, PKCS1.$$SIGNINFOHEAD[hashFunction], H]);
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-7.2.1
	 * 
	 * @param {Buffer}	M
	 * @param {uint}	emLen
	 * @returns {Buffer}
	 */
	PKCS1.$$eme_pkcs1_encode = function(M, emLen){
		var PS = crypt.randomBytes(emLen - M.length);
		for(var i = 0; i<PS.length; i++)
			if(PS[i] == 0) PS[i] = 1;
		PS[0] = 0;
		PS[1] = 2;
		PS[PS.length-1] = 0;
		return Buffer.concat([PS, M]);
	};
	
	/*
	 * https://tools.ietf.org/html/rfc3447#section-7.2.2
	 * 
	 * @param {Buffer}	M
	 * @returns {Buffer}
	 */
	PKCS1.$$eme_pkcs1_decode = function(EM){
		if(EM[0] != 0 || EM[1] != 2) throw new Error("Encoded Message is not encoded correctly and thus cannot be decoded");
		
		var i = 2;
		while(EM[i++] != 0 && i < EM.length);
		if(EM[i-1] != 0) throw new Error("No padding separator was found and thus no message was decoded.");
		
		return EM.slice(i);
	};
	
	
	
	PKCS1.Default = new PKCS1();
	
	return PKCS1;
})();