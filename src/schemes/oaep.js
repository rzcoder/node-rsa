/**
 * PKCS_OAEP signature scheme
 */

var BigInteger = require('../libs/jsbn');
var crypt = require('crypto');

module.exports = {
    isEncryption: true,
    isSignature: false
};

module.exports.digestLength = {
    md4: 16,
    md5: 16,
    ripemd160: 20,
    rmd160: 20,
    sha: 20,
    sha1: 20,
    sha224: 28,
    sha256: 32,
    sha384: 48,
    sha512: 64
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
module.exports.eme_oaep_mgf1 = function (seed, maskLength, hashFunction) {
    hashFunction = hashFunction || "sha1";
    var hLen = module.exports.digestLength[hashFunction];
    var count = Math.ceil(maskLength / hLen);
    var T = new Buffer(hLen * count);
    var c = new Buffer(4);
    for (var i = 0; i < count; ++i) {
        var hash = crypt.createHash(hashFunction);
        hash.write(seed);
        c.writeUInt32BE(i, 0);
        hash.end(c);
        hash.read().copy(T, i * hLen);
    }
    return T.slice(0, maskLength);
};

module.exports.makeScheme = function (key, options) {
    function Scheme(key, options) {
        this.key = key;
        this.options = options;
    }

    Scheme.prototype.maxMessageLength = function(key){
        return key.encryptedDataLength - 2*RSA.$$digestLength[this.hash] - 2;
    };

    /**
     * Pad input
     * alg: PKCS1_OAEP
     *
     * https://tools.ietf.org/html/rfc3447#section-7.1.1
     */
    Scheme.prototype.encPad = function(buffer, emLen, options){
        var hash = this.options.encryptionSchemeOptions.hash	|| "sha1";
        var mgf =	this.options.encryptionSchemeOptions.mgf		|| module.exports.eme_oaep_mgf1;
        var label =	this.options.encryptionSchemeOptions.label		|| new Buffer(0);

        var hLen = module.exports.digestLength[hash];

        // Make sure we can put message into an encoded message of emLen bytes
        if(buffer.length > emLen - 2*hLen - 2) {
            throw new Error("Message is too long to encode into an encoded message with a length of " + emLen + " bytes, increase" +
            "emLen to fix this error (minimum value for given parameters and options: " + (emLen - 2 * hLen - 2) + ")");
        }

        var lHash = crypt.createHash(hash);
        lHash.update(label);
        lHash = lHash.digest();

        var PS = new Buffer(emLen - buffer.length - 2*hLen - 1); // Padding "String"
        PS.fill(0); // Fill the buffer with octets of 0
        PS[PS.length-1] = 1;

        var DB = Buffer.concat([lHash, PS, buffer]);
        var seed = crypt.randomBytes(hLen);

        // mask = dbMask
        var mask = mgf(seed, DB.length, hash);
        // XOR DB and dbMask together.
        for(var i = 0; i<DB.length; i++){
            DB[i] ^= mask[i];
        }
        // DB = maskedDB

        // mask = seedMask
        mask = mgf(DB, hLen, hash);
        // XOR seed and seedMask together.
        for(i = 0; i<seed.length; i++){
            seed[i] ^= mask[i];
        }
        // seed = maskedSeed

        var em = new Buffer(1 + seed.length + DB.length);
        em[0] = 0;
        seed.copy(em, 1);
        DB.copy(em, 1+seed.length);

        return em;
    };

    /**
     * Unpad input
     * alg: PKCS1_OAEP
     *
     * Note: This method works within the buffer given and modifies the values. It also returns a slice of the EM as the return Message.
     * If the implementation requires that the EM parameter be unmodified then the implementation should pass in a clone of the EM buffer.
     *
     * https://tools.ietf.org/html/rfc3447#section-7.1.2
     */
    Scheme.prototype.encUnPad = function(buffer){
        var hash = this.options.encryptionSchemeOptions.hash	|| "sha1";
        var mgf =	this.options.encryptionSchemeOptions.mgf		|| module.exports.eme_oaep_mgf1;
        var label =	this.options.encryptionSchemeOptions.label		|| new Buffer(0);

        var hLen = module.exports.digestLength[hash];

        // Check to see if buffer is a properly encoded OAEP message
        if(buffer.length < 2*hLen + 2) {
            throw new Error("Error decoding message, the supplied message is not long enough to be a valid OAEP encoded message");
        }

        var seed = buffer.slice(1, hLen+1);	// seed = maskedSeed
        var DB = buffer.slice(1+hLen);		// DB = maskedDB

        var mask = mgf(DB, hLen, hash); // seedMask
        // XOR maskedSeed and seedMask together to get the original seed.
        for(var i = 0; i<seed.length; i++){
            seed[i] ^= mask[i];
        }
        // seed = seed

        mask = mgf(seed, DB.length, hash); // dbMask
        // XOR DB and dbMask together to get the original data block.
        for(i = 0; i<DB.length; i++){
            DB[i] ^= mask[i];
        }
        // DB = DB

        label = label || new Buffer(0);
        var lHash = crypt.createHash(hash);
        lHash.end(label);
        lHash = lHash.read();

        var lHashEM = DB.slice(0, hLen);
        if(lHashEM.toString("hex") !=  lHash.toString("hex")) {
            throw new Error("Error decoding message, the lHash calculated from the label provided and the lHash in the encrypted data do not match.");
        }

        // Filter out padding
        i = hLen;
        while(DB[i++] == 0 && i < DB.length);
        if(DB[i-1] != 1){
            throw new Error("Error decoding message, there is no padding message separator byte");
        }

        return DB.slice(i); // Message
    };


    return new Scheme(key, options);
};

/*
OAEP.prototype.maxMessageLength = function(key){
    return key.encryptedDataLength - 2*RSA.$$digestLength[this.hash] - 2;
};
*/
/*
 * https://tools.ietf.org/html/rfc3447#section-7.1.1
 *
 * @param {RSA.Key} key
 * @param {Buffer} message
 * @returns {Buffer}
 */
//OAEP.prototype.encrypt = function(key, message){
//    var m = OAEP.$$eme_oaep_encode(message, this.label, key.encryptedDataLength, this.options);
//    m = new BigInteger(m);
//    m = key.$doPublic(m);
//    m = m.toBuffer(key.encryptedDataLength);
//    return m;
//};

/*
 * https://tools.ietf.org/html/rfc3447#section-7.1.2
 *
 * @param {RSA.Key} key
 * @param {Buffer} encMessage
 * @returns {Buffer}
 */
//OAEP.prototype.decrypt = function(key, encMessage){
//    if(encMessage.length != key.encryptedDataLength || encMessage.length < 2*RSA.$$digestLength[this.hash] + 2)
//        throw new Error("Decryption Error");
//
//    encMessage = new BigInteger(encMessage);
//    encMessage = key.$doPrivate(encMessage);
//    encMessage = encMessage.toBuffer(key.encryptedDataLength);
//
//    return OAEP.$$eme_oaep_decode(encMessage, this.label, this.options);
//};







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
/*OAEP.$$eme_oaep_encode = function(M, label, emLen){
    // Prepare options
    if(!options) options = {};
    var hash = this.options.encryptionSchemeOptions.hash	|| "sha1";
    var mgf =	this.options.encryptionSchemeOptions.mgf		|| module.exports.eme_oaep_mgf1;
    var label =	this.options.encryptionSchemeOptions.label		|| new Buffer(0);

    var hLen = RSA.$$digestLength[hash];

    // Make sure we can put message into an encoded message of emLen bytes
    if(M.length > emLen - 2*hLen - 2)
        throw new Error("Message is too long to encode into an encoded message with a length of "+emLen+" bytes, increase emLen to fix this error (minimum value for given parameters and options: "+(emLen - 2*hLen - 2)+")");

    var lHash = crypt.createHash(hash);
    lHash.update(label);
    lHash = lHash.digest();

    var PS = new Buffer(emLen - M.length - 2*hLen - 1); // Padding "String"
    PS.fill(0); // Fill the buffer with octets of 0
    PS[PS.length-1] = 1;

    var DB = Buffer.concat([lHash, PS, M]);
    var seed = crypt.randomBytes(hLen);

    // mask = dbMask
    var mask = mgf(seed, DB.length, hash);
    // XOR DB and dbMask together.
    for(var i = 0; i<DB.length; i++){
        DB[i] ^= mask[i];
    }
    // DB = maskedDB

    // mask = seedMask
    mask = mgf(DB, hLen, hash);
    // XOR seed and seedMask together.
    for(i = 0; i<seed.length; i++){
        seed[i] ^= mask[i];
    }
    // seed = maskedSeed

    var em = new Buffer(1 + seed.length + DB.length);
    em[0] = 0;
    seed.copy(em, 1);
    DB.copy(em, 1+seed.length);

    return em;
};*/

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
/*OAEP.$$eme_oaep_decode = function(EM, L, options){
    // Prepare options
    if(!options) options = {};
    hash =	hash	|| "sha1";
    mgf =	mgf		|| OAEP.$$eme_oaep_mgf1;

    var hLen = RSA.$$digestLength[hash];

    // Check to see if EM is a properly encoded OAEP message
    if(EM.length < 2*hLen + 2)
        throw new Error("Error decoding message, the supplied message is not long enough to be a valid OAEP encoded message");

    var seed = EM.slice(1, hLen+1);	// seed = maskedSeed
    var DB = EM.slice(1+hLen);		// DB = maskedDB

    var mask = mgf(DB, hLen, hash); // seedMask
    // XOR maskedSeed and seedMask together to get the original seed.
    for(var i = 0; i<seed.length; i++)
        seed[i] ^= mask[i];
    // seed = seed

    mask = mgf(seed, DB.length, hash); // dbMask
    // XOR DB and dbMask together to get the original data block.
    for(i = 0; i<DB.length; i++)
        DB[i] ^= mask[i];
    // DB = DB


    L = L || new Buffer(0);
    var lHash = crypt.createHash(hash);
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
};*/