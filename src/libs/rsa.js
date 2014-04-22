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

var crypt = require('crypto');
var BigInteger = require("./jsbn.js");
var utils = require('../utils.js');
var _ = require('lodash');

var SIGNINFOHEAD = {
    sha1:   new Buffer('3021300906052b0e03021a05000414','hex'),
    sha256: new Buffer('3031300d060960864801650304020105000420','hex'),
    md5:    new Buffer('3020300c06082a864886f70d020505000410','hex')
};

exports.BigInteger = BigInteger;
module.exports.Key = (function() {
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
     * Return the PKCS#1 RSA encryption of buffer
     * @param buffer {Buffer}
     * @returns {Buffer}
     */
    RSAKey.prototype.encrypt = function (buffer) {
        var buffers = [];
        var results = [];

        var bufferSize = buffer.length;
        var buffersCount = Math.ceil(bufferSize / this.maxMessageLength) || 1; // total buffers count for encrypt
        var dividedSize = Math.ceil(bufferSize / buffersCount || 1); // each buffer size

        if ( buffersCount == 1) {
            buffers.push(buffer);
        } else {
            for (var bufNum = 0; bufNum < buffersCount; bufNum++) {
                buffers.push(buffer.slice(bufNum * dividedSize, (bufNum+1) * dividedSize));
            }
        }

        for(var i in buffers) {
            var buf = buffers[i];

            var m = this.$$pkcs1pad2(buf);

            if (m === null) {
                return null;
            }

            var c = this.$doPublic(m);

            if (c === null) {
                return null;
            }

            var encryptedBuffer = c.toBuffer(true);

            while (encryptedBuffer.length < this.encryptedDataLength) {
                encryptedBuffer = Buffer.concat([new Buffer([0]), encryptedBuffer]);
            }

            results.push(encryptedBuffer);
        }

        return Buffer.concat(results);
    };

    /**
     * Return the PKCS#1 RSA decryption of buffer
     * @param buffer {Buffer}
     * @returns {Buffer}
     */
    RSAKey.prototype.decrypt = function (buffer) {
        if (buffer.length % this.encryptedDataLength > 0)
            throw Error('Incorrect data or key');

        var result = [];

        var offset = 0;
        var length = 0;

        var buffersCount = buffer.length / this.encryptedDataLength;

        for (var i = 0; i < buffersCount; i++) {
            offset = i * this.encryptedDataLength;
            length = offset + this.encryptedDataLength;

            var c = new BigInteger(buffer.slice(offset, Math.min(length, buffer.length)));

            var m = this.$doPrivate(c);

            if (m === null) {
                return null;
            }

            result.push(this.$$pkcs1unpad2(m));
        }

        return Buffer.concat(result);
    };

    RSAKey.prototype.sign = function (buffer, hashAlgorithm) {
        var hasher = crypt.createHash(hashAlgorithm);
        hasher.update(buffer);
        var hash = this.$$pkcs1(hasher.digest(), hashAlgorithm);
        var encryptedBuffer = this.$doPrivate(new BigInteger(hash)).toBuffer(true);

        while (encryptedBuffer.length < this.encryptedDataLength) {
            encryptedBuffer = Buffer.concat([new Buffer([0]), encryptedBuffer]);
        }

        return encryptedBuffer;

    };

    RSAKey.prototype.verify = function (buffer, signature, signature_encoding, hashAlgorithm) {

        if (signature_encoding) {
            signature = new Buffer(signature, signature_encoding);
        }

        var hasher = crypt.createHash(hashAlgorithm);
        hasher.update(buffer);

        var hash = this.$$pkcs1(hasher.digest(), hashAlgorithm);
        var m = this.$doPublic(new BigInteger(signature));

        return m.toBuffer().toString('hex') == hash.toString('hex');
    };

    Object.defineProperty(RSAKey.prototype, 'keySize', {
        get: function() { return this.cache.keyBitLength; }
    });

    Object.defineProperty(RSAKey.prototype, 'encryptedDataLength', {
        get: function() { return this.cache.keyByteLength; }
    });

    Object.defineProperty(RSAKey.prototype, 'maxMessageLength', {
        get: function() { return this.encryptedDataLength - 11; }
    });

    /**
     * Caching key data
     */
    RSAKey.prototype.$$recalculateCache = function () {
        this.cache = this.cache || {};
        // Bit & byte length
        this.cache.keyBitLength = this.n.bitLength();
        if (this.cache.keyBitLength % 2 == 1) {
            this.cache.keyBitLength = this.cache.keyBitLength + 1;
        }

        this.cache.keyByteLength = (this.cache.keyBitLength + 6) >> 3;
    };

    /**
     * PKCS#1 pad input buffer to max data length
     * @param hashBuf
     * @param hashAlgorithm
     * @param n
     * @returns {*}
     */
    RSAKey.prototype.$$pkcs1 = function (hashBuf, hashAlgorithm, n) {
        if(!SIGNINFOHEAD[hashAlgorithm])
            throw Error('Unsupported hash algorithm');

        var data = Buffer.concat([SIGNINFOHEAD[hashAlgorithm], hashBuf]);

        if (data.length + 10 > this.encryptedDataLength) {
            throw Error('Key is too short for signing algorithm (' + hashAlgorithm + ')');
        }

        var filled = new Buffer(this.encryptedDataLength - data.length - 1);
        filled.fill(0xff, 0, filled.length - 1);
        filled[0] = 1;
        filled[filled.length - 1] = 0;

        var res = Buffer.concat([filled, data]);

        return res;
    };

    /**
     * PKCS#1 (type 2, random) pad input buffer to encryptedDataLength bytes, and return a bigint
     * @param buffer
     * @returns {*}
     */
    RSAKey.prototype.$$pkcs1pad2 = function (buffer) {
        if (buffer.length > this.maxMessageLength) {
            throw new Error("Message too long for RSA (n=" + this.encryptedDataLength + ", l=" + buffer.length + ")");
        }

        // TO-DO: make n-length buffer
        var ba = Array.prototype.slice.call(buffer, 0);

        // random padding
        ba.unshift(0);
        var rand = crypt.randomBytes(this.encryptedDataLength - ba.length - 2);
        for(var i = 0; i < rand.length; i++) {
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
     * Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
     * @param d
     * @returns {Buffer}
     */
    RSAKey.prototype.$$pkcs1unpad2 = function (d) {
        var b = d.toByteArray();
        var i = 0;
        while (i < b.length && b[i] === 0) {
            ++i;
        }

        if (b.length - i != this.encryptedDataLength - 1 || b[i] != 2) {
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

    return RSAKey;
})();

