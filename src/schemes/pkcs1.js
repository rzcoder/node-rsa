/**
 * PKCS1 padding and signature scheme
 */

var BigInteger = require('../libs/jsbn');
var crypt = require('crypto');
var SIGN_INFO_HEAD = {
    md2: new Buffer('3020300c06082a864886f70d020205000410', 'hex'),
    md5: new Buffer('3020300c06082a864886f70d020505000410', 'hex'),
    sha1: new Buffer('3021300906052b0e03021a05000414', 'hex'),
    sha224: new Buffer('302d300d06096086480165030402040500041c', 'hex'),
    sha256: new Buffer('3031300d060960864801650304020105000420', 'hex'),
    sha384: new Buffer('3041300d060960864801650304020205000430', 'hex'),
    sha512: new Buffer('3051300d060960864801650304020305000440', 'hex'),
    ripemd160: new Buffer('3021300906052b2403020105000414', 'hex'),
    rmd160: new Buffer('3021300906052b2403020105000414', 'hex')
};

var SIGN_ALG_TO_HASH_ALIASES = {
    'ripemd160': 'rmd160'
};

module.exports = {
    isEncryption: true,
    isSignature: true
};

module.exports.makeScheme = function (key, options) {
    function Scheme(key, options) {
        this.key = key;
        this.options = options;
    }

    /**
     * Pad input buffer to encryptedDataLength bytes, and return a BigInteger
     * alg: PKCS#1 (type 2, random)
     * @param buffer
     * @returns {BigInteger}
     */
    Scheme.prototype.encPad = function (buffer) {
        if (buffer.length > this.key.maxMessageLength) {
            throw new Error("Message too long for RSA (n=" + this.key.encryptedDataLength + ", l=" + buffer.length + ")");
        }

        // TODO: make n-length buffer
        var ba = Array.prototype.slice.call(buffer, 0);

        // random padding
        ba.unshift(0);
        var rand = crypt.randomBytes(this.key.encryptedDataLength - ba.length - 2);
        for (var i = 0; i < rand.length; i++) {
            var r = rand[i];
            while (r === 0) { // non-zero only
                r = crypt.randomBytes(1)[0];
            }
            ba.unshift(r);
        }
        ba.unshift(2);
        ba.unshift(0);

        return new BigInteger(ba);
    };

    /**
     * Unpad input BigInteger and, if valid, return the Buffer object
     * alg: PKCS#1 (type 2, random)
     * @param buffer
     * @returns {Buffer}
     */
    Scheme.prototype.encUnPad = function (buffer) {
        var b = buffer.toByteArray();
        var i = 0;

        while (i < b.length && b[i] === 0) {
            ++i;
        }

        if (b.length - i != this.key.encryptedDataLength - 1 || b[i] != 2) {
            return null;
        }

        ++i;
        while (b[i] !== 0) {
            if (++i >= b.length) {
                return null;
            }
        }

        var c = 0;
        var res = new Buffer(b.length - i - 1);
        while (++i < b.length) {
            res[c++] = b[i] & 255;
        }

        return res;
    };

    Scheme.prototype.sign = function (buffer, encoding) {
        if (this.options.environment == 'browser') {
            var hashAlgorithm = this.options.signingSchemeOptions.hash;
            hashAlgorithm = SIGN_ALG_TO_HASH_ALIASES[hashAlgorithm] || hashAlgorithm;

            var hasher = crypt.createHash(hashAlgorithm);
            hasher.update(buffer);
            var hash = this.pkcs1pad(hasher.digest(), hashAlgorithm);
            var res = this.key.$doPrivate(new BigInteger(hash)).toBuffer(true);

            while (res.length < this.encryptedDataLength) {
                res = Buffer.concat([new Buffer([0]), res]);
            }

            if (encoding && encoding != 'buffer') {
                res = res.toString(encoding);
            }
            return res;
        } else {
            encoding = (!encoding || encoding == 'buffer' ? null : encoding);
            var signer = crypt.createSign('RSA-' + this.options.signingSchemeOptions.hash.toUpperCase());
            signer.update(buffer);
            return signer.sign(this.options.rsaUtils.getPrivatePEM(), encoding);
        }
    };

    Scheme.prototype.verify = function (buffer, signature, signature_encoding) {
        if (this.options.environment == 'browser') {
            var hashAlgorithm = this.options.signingSchemeOptions.hash;
            hashAlgorithm = SIGN_ALG_TO_HASH_ALIASES[hashAlgorithm] || hashAlgorithm;

            if (signature_encoding) {
                signature = new Buffer(signature, signature_encoding);
            }

            var hasher = crypt.createHash(hashAlgorithm);
            hasher.update(buffer);
            var hash = this.pkcs1pad(hasher.digest(), hashAlgorithm);
            var m = this.key.$doPublic(new BigInteger(signature));

            return m.toBuffer().toString('hex') == hash.toString('hex');
        } else {
            var verifier = crypt.createVerify('RSA-' + this.options.signingSchemeOptions.hash.toUpperCase());
            verifier.update(buffer);
            return verifier.verify(this.options.rsaUtils.getPublicPEM(), signature, signature_encoding);
        }
    };

    /**
     * PKCS#1 pad input buffer to max data length
     * @param hashBuf
     * @param hashAlgorithm
     * @returns {*}
     */
    Scheme.prototype.pkcs1pad = function (hashBuf, hashAlgorithm) {
        var digest = SIGN_INFO_HEAD[hashAlgorithm];
        if (!digest) {
            throw Error('Unsupported hash algorithm');
        }

        var data = Buffer.concat([digest, hashBuf]);

        if (data.length + 10 > this.key.encryptedDataLength) {
            throw Error('Key is too short for signing algorithm (' + hashAlgorithm + ')');
        }

        var filled = new Buffer(this.key.encryptedDataLength - data.length - 1);
        filled.fill(0xff, 0, filled.length - 1);
        filled[0] = 1;
        filled[filled.length - 1] = 0;

        var res = Buffer.concat([filled, data]);

        return res;
    };

    return new Scheme(key, options);
};


