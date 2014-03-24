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
var crypt = require('crypto');
var BigInteger = require("./jsbn.js");

/**
 * PKCS#1 (type 2, random) pad input buffer buf to n bytes, and return a bigint
 * @param buf
 * @param n
 * @returns {*}
 */
function pkcs1pad2(buf, n) {
    if (n < buf.length + 11) {
        throw new Error("Message too long for RSA (n=" + n + ", l=" + s.length + ")");
    }

    // TO-DO: make buffer n-length
    var ba = Array.prototype.slice.call(buf, 0);

    // random padding
    ba.unshift(0);
    var rand = crypt.randomBytes(n - ba.length - 2);
    for(var i = 0; i < rand.length; i++) {
        var r = rand[i];
        while (r === 0) // non-zero only
            r = crypt.randomBytes(1)[0];
        ba.unshift(r);
    }
    ba.unshift(2);
    ba.unshift(0);

    return new BigInteger(ba);
}

/**
 * Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
 * @param d
 * @param n
 * @returns {Buffer}
 */
function pkcs1unpad2(d, n) {
    var b = d.toByteArray();
    var i = 0;
    while (i < b.length && b[i] === 0)
        ++i;

    if (b.length - i != n - 1 || b[i] != 2)
        return null;
    ++i;
    while (b[i] !== 0)
        if (++i >= b.length)
            return null;

    var ret = [];
    while (++i < b.length) {
        var c = b[i] & 255;
        ret.push(c);
    }
    return new Buffer(ret);
}

/**
 * Trying get a 32-bit unsigned integer from the partial buffer
 * @param buffer
 * @param offset
 * @returns {Number}
 */
function get32Int(buffer, offset) {
    offset = offset || 0;
    var size = 0;
    if ((size = buffer.length - offset) > 0) {
        if (size >= 4) {
            return buffer.readUInt32BE(offset);
        } else {
            var res = 0;
            for (var i = offset + size, d = 0; i > offset; i--, d+=2) {
                res += buffer[i-1] * Math.pow(16, d);
            }
            return res;
        }
    } else {
        return NaN;
    }
}

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
            this.e = get32Int(E, 0);
            this.d = new BigInteger(D);

            if (P && Q && DP && DQ && C) {
                this.p = new BigInteger(P);
                this.q = new BigInteger(Q);
                this.dmp1 = new BigInteger(DP);
                this.dmq1 = new BigInteger(DQ);
                this.coeff = new BigInteger(C);
            }
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
            this.e = get32Int(E, 0);
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
     * @param buf {Buffer}
     * @returns {Buffer}
     */
    RSAKey.prototype.encrypt = function (buf) {
        var m = pkcs1pad2(buf, (this.n.bitLength() + 7) >> 3);

        if (m === null)
            return null;

        var c = this.$doPublic(m);
        if (c === null)
            return null;

        return new Buffer(c.toByteArray());
    };

    /**
     * Return the PKCS#1 RSA decryption of buffer
     * @param buf {Buffer}
     * @returns {Buffer}
     */
    RSAKey.prototype.decrypt = function (buf) {
        var c = new BigInteger(buf);
        var m = this.$doPrivate(c);
        if (m === null)
            return null;
        return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
    };

    return RSAKey;
})();

