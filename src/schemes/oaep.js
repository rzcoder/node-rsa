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
module.exports.eme_oaep_mgf1 = function(seed, maskLength, hashFunction){
    hashFunction = hashFunction || "sha1";
    var hLen = module.exports.digestLength[hashFunction];
    var count = Math.ceil(maskLength / hLen);
    var T = new Buffer(hLen * count);
    var c = new Buffer(4);
    for(var i = 0; i < count; ++i) {
        var hash = crypt.createHash(hashFunction);
        hash.write(seed);
        c.writeUInt32BE(i, 0);
        hash.end(c);
        hash.read().copy(T, i*hLen);
    }
    return T.slice(0, maskLength);
};

module.exports.makeScheme = function (key, options) {
    function Scheme(key, options) {
        this.key = key;
        this.options = options;
    }


    return new Scheme(key, options);
};