var fs = require('fs');
var assert = require('chai').assert;
var _ = require('lodash');
var NodeRSA = require('../src/NodeRSA');
var OAEP = require('../src/schemes/oaep');
var constants = require('../src/polyfillHandler.js').constants;

describe('NodeRSA', function () {
    var keySizes = [
        {b: 512, e: 3},
        {b: 512, e: 5},
        {b: 512, e: 257},
        {b: 512, e: 65537},
        {b: 768}, // 'e' should be 65537
        {b: 1024}, // 'e' should be 65537
        {b: 2048} // 'e' should be 65537
    ];

    var environments = ['browser', 'node'];
    var encryptSchemes = [
        'pkcs1',
        'pkcs1_oaep',
        {
            scheme:'pkcs1',
            padding: constants.RSA_NO_PADDING,
            toString: function() {
                return 'pkcs1-nopadding';
            }
        }
        ];
    var signingSchemes = ['pkcs1', 'pss'];
    var signHashAlgorithms = {
        'node': ['MD4', 'MD5', 'RIPEMD160', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
        'browser': ['MD5', 'RIPEMD160', 'SHA1', 'SHA256', 'SHA512']
    };

    var dataBundle = {
        'string': {
            data: 'ascii + 12345678',
            encoding: 'utf8'
        },
        'unicode string': {
            data: 'ascii + юникод スラ ⑨',
            encoding: 'utf8'
        },
        'empty string': {
            data: '',
            encoding: ['utf8', 'ascii', 'hex', 'base64']
        },
        'long string': {
            data: 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
            encoding: ['utf8', 'ascii']
        },
        'buffer': {
            data: Buffer.from('ascii + юникод スラ ⑨'),
            encoding: 'buffer'
        },
        'json object': {
            data: {str: 'string', arr: ['a', 'r', 'r', 'a', 'y', true, '⑨'], int: 42, nested: {key: {key: 1}}},
            encoding: 'json'
        },
        'json array': {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, [10, 11, 12, [13], 14, 15, [16, 17, [18]]]],
            encoding: 'json'
        }
    };

    var privateKeyPKCS1 = '-----BEGIN RSA PRIVATE KEY-----\n' +
        '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\n' +
        '-----END RSA PRIVATE KEY-----';

    var privateKeyComponents = {
        n: 'ALBNXncn06GUb+nBTpAdLQCeaiaK+GBeQnHCQC9H0v6NWJNdFUlx+F8eKXkiYGECpDtB6jtYQM+pPXRUAeFNQp1rUY7TRHCH8nKq2a4busqLubMm+knFd2bv/W5u/w8mi5cf4CYVD0dTsTs2qrBL5bu4Ww4TSyGKNcyhW/2lAWw+vlHGhsR9gXxTXc1QLVUlaXP7NmN7G6DDe6wclI+/d+4kJWjCDb1Y8mrMp2LsxzcOmUT/ST/X8MawsmsZ0z1sVZdKr1WkDtvk7RTLQ1x9jlWbVlnixwC/HIpXcNBvrtqlak6iBhMDciZbAB8pGjxQDFtMS7nrpq0pQfiVCT60b78OJwQneBjqzUpTwhP8ZZNQm/CWiAky7w1HGHN2ai946gLngYZKcNrgs/MVSXjgNSmOJECCMfCRAbAGM4Mj9ost',
        e: 65537,
        d: 'IwXLnUoZHYEaVkpja/ePyA6wMaXrv2EaO/UFwR64iH7VuLiGEQgF+gdI39p3YO4gZ/EpMc7PWTFalvBVS0eI0zLNidzoPJ6VCDhuc8roaXImWrOEhwEmPhmws65zFrRmiIf5hDcsyNOUYpnygIEjSw5NcFde1nPZSiRH3PRZewJf1mjkvsXb4jHBcZba2o5LC5I89Lgw/de3irJGxOOZVC3xqniNJGA2nVqfPKcOopFyZZ9qd2NTzUBd3stnDfkp83dI8f3OXw/Qdc8SmL+W1KPlJ08wcVfNXvcQiX5HV7/ug+ag59YBi3WWWuRcbWW0YFYf2Zaj/cWK+9mrP1hZiANtMEYBz4Fry8h7IdF04amX9vzt0fCphb/Gk/pJnOYrOrFSLSCIu5baK1WqU5CWot88/1UjAQWi/srRTfY1ZeE=',
        p: 'AN8vxMx5le6AFM3vKrrNlY3z7rQxRrHPT+Up3OajfnPfaulUp2xh33bamZyw1hqiP8f0veP80/j3P5Id9ila9NrsC8l82VdhzcFFchqul+deybrkjMrMdoX2LbF1fGR9MRgi85AMwsVKKI5tYkxX5CpTFveW67f8JHchxuB5M6l2IL9P9mX9hiXXsmplMeYsVk+rvF7C22DNCisNFYgUO2U=',
        q: 'AMo4+uM9f4BpOHSmayhLhHArIGs4386BkXSeOLeQitaQJ/2czb459O87XoCAonZbq+dI7XRnBU3toQvEsZgrtGkOFXCZJMWAQxD5BQ5vEYT6c86huGpX6h3ODlJ6UGi+5CWyMQ1cFlBkfffFAarjSYTVlyj736sOeDuJWX133z5VQBQ81xSH23kNF95vxB4I1fXG8WL11YZU7VEwSLC4aCk=',
        dmp1: 'CkY/sA4U2eLpkkVlWS4nqV5GaeMu1vatPeZ8dd2m75ykZlNwVav3xpfvpGf7o0Q+3Wyl5T35YCe5tHdOor6+MOnW7RKjSsOE3lXdF99bvNn/PWxSEu/wsOARYG8BJ/sfbHYHcmUz/jMYxN3CPbN6HHywvPskpNalsxpJ9oF94FpAza3XsQBH0awpWX6JGoiF/KryRAaCZOVrh2nVyOrthQ==',
        dmq1: 'ByidOQ4kRVd0OCzr/jEuLwpXy3Pn+Fd93rL7LwRe5dmUkNXMMr+6e/2OCt6C4c28+CMMxOIgvfF7kf8Uil6BtHZbK/E/6/3uYdtu4mPsKtjy4I25CYqzLvrsZt8NmaeoS+1S7zYjVBU6oFrJBFOndpxZDYpdEKEigHkMQfTMYliCPDUrJ/7nNhHQln8+YhHOATVZtjcdp/O5svYSnK7qgQ==',
        coeff: 'N3eUVas9q2DGkXUlcwQUVtohF03EeQoDhhiAxMzgw+BWK6dhf/IntJpfyNacLbfUD25Wfj6Rv4O8qNz5m5NC+chQra7ou8iKdUWycMQD4FtfB6EC3B0cMwO2pgV3HiG8JZDAE2fincnQ47a1thUy28zlo4R9FJhqB+ZHLCENQCNbxTREGfOWZeFBDoH1uOqihLYyxGsmtLkJTrzZ9veEGg=='
    };

    var publicKeyPKCS8 = '-----BEGIN PUBLIC KEY-----\n' +
        'MIIBYjANBgkqhkiG9w0BAQEFAAOCAU8AMIIBSgKCAUEAsE1edyfToZRv6cFOkB0t\n' +
        'AJ5qJor4YF5CccJAL0fS/o1Yk10VSXH4Xx4peSJgYQKkO0HqO1hAz6k9dFQB4U1C\n' +
        'nWtRjtNEcIfycqrZrhu6you5syb6ScV3Zu/9bm7/DyaLlx/gJhUPR1OxOzaqsEvl\n' +
        'u7hbDhNLIYo1zKFb/aUBbD6+UcaGxH2BfFNdzVAtVSVpc/s2Y3sboMN7rByUj793\n' +
        '7iQlaMINvVjyasynYuzHNw6ZRP9JP9fwxrCyaxnTPWxVl0qvVaQO2+TtFMtDXH2O\n' +
        'VZtWWeLHAL8cildw0G+u2qVqTqIGEwNyJlsAHykaPFAMW0xLueumrSlB+JUJPrRv\n' +
        'vw4nBCd4GOrNSlPCE/xlk1Cb8JaICTLvDUcYc3ZqL3jqAueBhkpw2uCz8xVJeOA1\n' +
        'KY4kQIIx8JEBsAYzgyP2iy0CAwEAAQ==\n' +
        '-----END PUBLIC KEY-----';

    var generatedKeys = [];
    var privateNodeRSA = null;
    var publicNodeRSA = null;

    describe('Setup options', function () {
        it('should use browser environment', function () {
            assert.equal((new NodeRSA(null, {environment: 'browser'})).$options.environment, 'browser');
        });

        it('should use io.js environment', function () {
            assert.equal((new NodeRSA(null, {environment: 'iojs'})).$options.environment, 'iojs');
        });

        it('should make empty key pair with default options', function () {
            var key = new NodeRSA(null);
            assert.equal(key.isEmpty(), true);
            assert.equal(key.$options.signingScheme, 'pkcs1');
            assert.equal(key.$options.signingSchemeOptions.hash, 'sha256');
            assert.equal(key.$options.signingSchemeOptions.saltLength, null);

            assert.equal(key.$options.encryptionScheme, 'pkcs1_oaep');
            assert.equal(key.$options.encryptionSchemeOptions.hash, 'sha1');
            assert.equal(key.$options.encryptionSchemeOptions.label, null);
        });

        it('should make key pair with pkcs1-md5 signing scheme', function () {
            var key = new NodeRSA(null, {signingScheme: 'md5'});
            assert.equal(key.$options.signingScheme, 'pkcs1');
            assert.equal(key.$options.signingSchemeOptions.hash, 'md5');
        });

        it('should make key pair with pss-sha512 signing scheme', function () {
            var key = new NodeRSA(null, {signingScheme: 'pss-sha512'});
            assert.equal(key.$options.signingScheme, 'pss');
            assert.equal(key.$options.signingSchemeOptions.hash, 'sha512');
        });

        it('should make key pair with pkcs1 encryption scheme, and pss-sha1 signing scheme', function () {
            var key = new NodeRSA(null, {encryptionScheme: 'pkcs1', signingScheme: 'pss'});
            assert.equal(key.$options.encryptionScheme, 'pkcs1');
            assert.equal(key.$options.signingScheme, 'pss');
            assert.equal(key.$options.signingSchemeOptions.hash, null);
        });

        it('change options', function () {
            var key = new NodeRSA(null, {signingScheme: 'pss-sha1'});
            assert.equal(key.$options.signingScheme, 'pss');
            assert.equal(key.$options.signingSchemeOptions.hash, 'sha1');
            key.setOptions({signingScheme: 'pkcs1'});
            assert.equal(key.$options.signingScheme, 'pkcs1');
            assert.equal(key.$options.signingSchemeOptions.hash, null);
            key.setOptions({signingScheme: 'pkcs1-sha256'});
            assert.equal(key.$options.signingScheme, 'pkcs1');
            assert.equal(key.$options.signingSchemeOptions.hash, 'sha256');
        });

        it('advanced options change', function () {
            var key = new NodeRSA(null);
            key.setOptions({
                encryptionScheme: {
                    scheme: 'pkcs1_oaep',
                    hash: 'sha512',
                    label: 'horay'
                },
                signingScheme: {
                    scheme: 'pss',
                    hash: 'md5',
                    saltLength: 15
                }
            });

            assert.equal(key.$options.signingScheme, 'pss');
            assert.equal(key.$options.signingSchemeOptions.hash, 'md5');
            assert.equal(key.$options.signingSchemeOptions.saltLength, 15);
            assert.equal(key.$options.encryptionScheme, 'pkcs1_oaep');
            assert.equal(key.$options.encryptionSchemeOptions.hash, 'sha512');
            assert.equal(key.$options.encryptionSchemeOptions.label, 'horay');
        });

        it('should throw \'unsupported hashing algorithm\' exception', function () {
            var key = new NodeRSA(null);
            assert.equal(key.isEmpty(), true);
            assert.equal(key.$options.signingScheme, 'pkcs1');
            assert.equal(key.$options.signingSchemeOptions.hash, 'sha256');

            assert.throw(function () {
                key.setOptions({
                    environment: 'browser',
                    signingScheme: 'md4'
                });
            }, Error, 'Unsupported hashing algorithm');
        });
    });

    describe('Base methods', function () {
        it('importKey() should throw exception if key data not specified', function () {
            var key = new NodeRSA(null);

            assert.throw(function () {
                key.importKey();
            }, Error, 'Empty key given');
        });

        it('importKey() should return this', function () {
            var key = new NodeRSA(null);
            assert.equal(key.importKey(publicKeyPKCS8), key);
        });
    });

    describe('Work with keys', function () {
        describe('Generating keys', function () {
            for (var size in keySizes) {
                (function (size) {
                    it('should make key pair ' + size.b + '-bit length and public exponent is ' + (size.e ? size.e : size.e + ' and should be 65537'), function () {
                        this.timeout(35000);
                        generatedKeys.push(new NodeRSA({b: size.b, e: size.e}, {encryptionScheme: 'pkcs1'}));
                        assert.instanceOf(generatedKeys[generatedKeys.length - 1].keyPair, Object);
                        assert.equal(generatedKeys[generatedKeys.length - 1].isEmpty(), false);
                        assert.equal(generatedKeys[generatedKeys.length - 1].getKeySize(), size.b);
                        assert.equal(generatedKeys[generatedKeys.length - 1].getMaxMessageSize(), (size.b / 8 - 11));
                        assert.equal(generatedKeys[generatedKeys.length - 1].keyPair.e, size.e || 65537);
                    });
                })(keySizes[size]);
            }
        });

        describe('Import/Export keys', function () {
            var publicKeyComponents = {
                n: 'ALBNXncn06GUb+nBTpAdLQCeaiaK+GBeQnHCQC9H0v6NWJNdFUlx+F8eKXkiYGECpDtB6jtYQM+pPXRUAeFNQp1rUY7TRHCH8nKq2a4busqLubMm+knFd2bv/W5u/w8mi5cf4CYVD0dTsTs2qrBL5bu4Ww4TSyGKNcyhW/2lAWw+vlHGhsR9gXxTXc1QLVUlaXP7NmN7G6DDe6wclI+/d+4kJWjCDb1Y8mrMp2LsxzcOmUT/ST/X8MawsmsZ0z1sVZdKr1WkDtvk7RTLQ1x9jlWbVlnixwC/HIpXcNBvrtqlak6iBhMDciZbAB8pGjxQDFtMS7nrpq0pQfiVCT60b78OJwQneBjqzUpTwhP8ZZNQm/CWiAky7w1HGHN2ai946gLngYZKcNrgs/MVSXjgNSmOJECCMfCRAbAGM4Mj9ost',
                e: 65537,
            };

            var privateKeyPEMNotTrimmed = 'random     \n\n data    \n\n ' + privateKeyPKCS1 + '\n \n  \n\n random data ';
            var publicKeyPEMNotTrimmed = '\n\n\n\nrandom     \n\n data\n ' + publicKeyPKCS8 + '\n \n random data\n\n  ';

            var fileKeyPKCS1 = '-----BEGIN RSA PRIVATE KEY-----\n' +
                'MIICXAIBAAKBgQCCdY+EpDC/vPa335l751SBM8d5Lf4z4QZX4bc+DqTY9zVY/rmP\n' +
                'GbTkCueKnIKApuOGMXJOaCwNH9wUftNt7T0foEwjl16uIC8m4hwSjjNL5TKqMVey\n' +
                'Syv04oBuidv76u5yNiLC4J85lbmW3WAyYkTCbm/VJZAXNJuqCm7AVWmQMQIDAQAB\n' +
                'AoGAEYR3oPfrE9PrzQTZNyn4zuCFCGCEobK1h1dno42T1Q5cu3Z4tB5fi79rF9Gs\n' +
                'NFo0cvBwyNZ0E88TXi0pdrlEW6mdPgQFd3CFxrOgKt9AGpOtI1zzVOb1Uddywq/m\n' +
                'WBPyETwEKzq7lC2nAcMUr0rlFrrDmUT2dafHeuWnFMZ/1YECQQDCtftsH9/prbgu\n' +
                'Q4F2lOWsLz96aix/jnI8FhBmukKmfLMXjCZYYv+Dsr8TIl/iriGqcSgGkBHHoGe1\n' +
                'nmLUZ4EHAkEAq4YcB8T9DLIYUeaS+JRWwLOejU6/rYdgxBIaGn2m0Ldp/z7lLM7g\n' +
                'b0H5Al+7POajkAdnDclBDhyxqInHO4VvBwJBAJ25jNEpgNhqQKg5RsYoF2RDYchn\n' +
                '+WPan+7McLzGZPc4TFrmzKkMiK7GPMHjNokJRXwr7aBjVAPBjEEy7BvjPEECQFOJ\n' +
                '4rcKAzEewGeLREObg9Eg6nTqSMLMb52vL1V9ozR+UDrHuDilnXuyhwPX+kqEDl+E\n' +
                'q3V0cqHb6c8rI4TizRsCQANIyhoJ33ughNzbCIknkMPKtgvLOUARnbya/bkfRexL\n' +
                'icyYzXPNuqZDY8JZQHlshN8cCcZcYjGPYYscd2LKB6o=\n' +
                '-----END RSA PRIVATE KEY-----';
            var keysFolder = __dirname + '/keys/';
            var keys_formats = {
                'pkcs1-private-der': {public: false, der: true, file: 'private_pkcs1.der'},
                'pkcs1-private-pem': {public: false, der: false, file: 'private_pkcs1.pem'},
                'pkcs8-private-der': {public: false, der: true, file: 'private_pkcs8.der'},
                'pkcs8-private-pem': {public: false, der: false, file: 'private_pkcs8.pem'},
                'pkcs1-public-der': {public: true, der: true, file: 'public_pkcs1.der'},
                'pkcs1-public-pem': {public: true, der: false, file: 'public_pkcs1.pem'},
                'pkcs8-public-der': {public: true, der: true, file: 'public_pkcs8.der'},
                'pkcs8-public-pem': {public: true, der: false, file: 'public_pkcs8.pem'},

                'private': {public: false, der: false, file: 'private_pkcs1.pem'},
                'public': {public: true, der: false, file: 'public_pkcs8.pem'},
                'private-der': {public: false, der: true, file: 'private_pkcs1.der'},
                'public-der': {public: true, der: true, file: 'public_pkcs8.der'},

                'pkcs1': {public: false, der: false, file: 'private_pkcs1.pem'},
                'pkcs1-private': {public: false, der: false, file: 'private_pkcs1.pem'},
                'pkcs1-der': {public: false, der: true, file: 'private_pkcs1.der'},
                'pkcs8': {public: false, der: false, file: 'private_pkcs8.pem'},
                'pkcs8-private': {public: false, der: false, file: 'private_pkcs8.pem'},
                'pkcs8-der': {public: false, der: true, file: 'private_pkcs8.der'},
                'pkcs1-public': {public: true, der: false, file: 'public_pkcs1.pem'},
                'pkcs8-public': {public: true, der: false, file: 'public_pkcs8.pem'},

                'openssh-public': {public: true, der: false, file: 'id_rsa.pub'},
                'openssh-private': {public: false, der: false, file: 'id_rsa'}
            };

            describe('Good cases', function () {
                describe('Common cases', function () {
                    it('should load private key from (not trimmed) PKCS1-PEM string', function () {
                        privateNodeRSA = new NodeRSA(privateKeyPEMNotTrimmed);
                        assert.instanceOf(privateNodeRSA.keyPair, Object);
                        assert(privateNodeRSA.isPrivate());
                        assert(privateNodeRSA.isPublic());
                        assert(!privateNodeRSA.isPublic(true));
                    });

                    it('should load public key from (not trimmed) PKCS8-PEM string', function () {
                        publicNodeRSA = new NodeRSA(publicKeyPEMNotTrimmed);
                        assert.instanceOf(publicNodeRSA.keyPair, Object);
                        assert(publicNodeRSA.isPublic());
                        assert(publicNodeRSA.isPublic(true));
                        assert(!publicNodeRSA.isPrivate());
                    });

                    it('.exportKey() should return private PEM string', function () {
                        assert.equal(privateNodeRSA.exportKey('private'), privateKeyPKCS1);
                        assert.equal(privateNodeRSA.exportKey(), privateKeyPKCS1);
                    });

                    it('.exportKey() from public key should return pkcs8 public PEM string', function () {
                        assert.equal(publicNodeRSA.exportKey('public'), publicKeyPKCS8);
                    });

                    it('.exportKey() from private key should return pkcs8 public PEM string', function () {
                        assert.equal(privateNodeRSA.exportKey('public'), publicKeyPKCS8);
                    });

                    it('should create and load key from buffer/fs.readFileSync output', function () {
                        var key = new NodeRSA(fs.readFileSync(keysFolder + 'private_pkcs1.pem'));
                        assert.equal(key.exportKey(), fileKeyPKCS1);
                        key = new NodeRSA();
                        key.importKey(fs.readFileSync(keysFolder + 'private_pkcs1.pem'));
                        assert.equal(key.exportKey(), fileKeyPKCS1);
                    });

                    it('should gracefully handle data outside of encapsulation boundaries for pkcs1 private keys', function () {
                        let privateFileWithNoise = 'Lorem ipsum' + fs.readFileSync(keysFolder + 'private_pkcs1.pem') + 'dulce et decorum';
                        let key = new NodeRSA(privateFileWithNoise);
                        assert.equal(key.exportKey(), fileKeyPKCS1);
                    });

                    it('should gracefully handle data outside of encapsulation boundaries for pkcs1 public keys', function () {
                        let publicFileWithNoise = 'Lorem ipsum' + fs.readFileSync(keysFolder + 'public_pkcs1.pem') + 'dulce et decorum';
                        let publicNodeRSA = new NodeRSA(publicFileWithNoise);
                        assert.instanceOf(publicNodeRSA.keyPair, Object);
                        assert(publicNodeRSA.isPublic());
                        assert(publicNodeRSA.isPublic(true));
                        assert(!publicNodeRSA.isPrivate());
                    });

                    it('should gracefully handle data outside of encapsulation boundaries for pkcs8 private keys', function () {
                        let privateFileWithNoise = 'Lorem ipsum' + fs.readFileSync(keysFolder + 'private_pkcs8.pem') + 'dulce et decorum';
                        let key = new NodeRSA(privateFileWithNoise);
                        assert.equal(key.exportKey(), fileKeyPKCS1);
                    });

                    it('should gracefully handle data outside of encapsulation boundaries for pkcs8 public keys', function () {
                        let publicFileWithNoise = 'Lorem ipsum' + fs.readFileSync(keysFolder + 'public_pkcs8.pem') + 'dulce et decorum';
                        let publicNodeRSA = new NodeRSA(publicFileWithNoise);
                        assert.instanceOf(publicNodeRSA.keyPair, Object);
                        assert(publicNodeRSA.isPublic());
                        assert(publicNodeRSA.isPublic(true));
                        assert(!publicNodeRSA.isPrivate());
                    });

                    it('should handle data without begin/end encapsulation boundaries for pkcs1 private keys', function () {
                        let privateFile = fs.readFileSync(keysFolder + 'private_pkcs1.pem', "utf8");
                        let privateFileNoBoundaries = privateFile.substring("-----BEGIN RSA PRIVATE KEY-----".length, privateFile.indexOf("-----END RSA PRIVATE KEY-----"));
                        let key = new NodeRSA(privateFileNoBoundaries, "pkcs1-private-pem");
                        assert.equal(key.exportKey(), fileKeyPKCS1);
                    });

                    it('should handle data without begin/end encapsulation boundaries for pkcs1 public keys', function () {
                        let publicFile = fs.readFileSync(keysFolder + 'public_pkcs1.pem', "utf8");
                        let publicFileNoBoundaries = publicFile.substring("-----BEGIN RSA PUBLIC KEY-----".length, publicFile.indexOf("-----END RSA PUBLIC KEY-----"));
                        let publicNodeRSA = new NodeRSA(publicFileNoBoundaries, "pkcs1-public-pem");
                        assert.instanceOf(publicNodeRSA.keyPair, Object);
                        assert(publicNodeRSA.isPublic());
                        assert(publicNodeRSA.isPublic(true));
                        assert(!publicNodeRSA.isPrivate());
                    });

                    it('should handle data without begin/end encapsulation boundaries for pkcs8 private keys', function () {
                        let privateFile = fs.readFileSync(keysFolder + 'private_pkcs8.pem', "utf8");
                        let privateFileNoBoundaries = privateFile.substring('-----BEGIN PRIVATE KEY-----'.length, privateFile.indexOf('-----END PRIVATE KEY-----'));
                        let key = new NodeRSA(privateFileNoBoundaries, "pkcs8-private-pem");
                        assert.equal(key.exportKey(), fileKeyPKCS1);
                    });

                    it('should handle data without begin/end encapsulation boundaries for pkcs8 public keys', function () {
                        let publicFile = fs.readFileSync(keysFolder + 'public_pkcs8.pem', "utf8");
                        let publicFileNoBoundaries = publicFile.substring("-----BEGIN PUBLIC KEY-----".length, publicFile.indexOf("-----END PUBLIC KEY-----"));
                        let publicNodeRSA = new NodeRSA(publicFileNoBoundaries, "pkcs8-public-pem");
                        assert.instanceOf(publicNodeRSA.keyPair, Object);
                        assert(publicNodeRSA.isPublic());
                        assert(publicNodeRSA.isPublic(true));
                        assert(!publicNodeRSA.isPrivate());
                    });

                    it('.importKey() from private components', function () {
                        var key = new NodeRSA();
                        key.importKey({
                            n: Buffer.from(privateKeyComponents.n, 'base64'),
                            e: 65537,
                            d: Buffer.from(privateKeyComponents.d, 'base64'),
                            p: Buffer.from(privateKeyComponents.p, 'base64'),
                            q: Buffer.from(privateKeyComponents.q, 'base64'),
                            dmp1: Buffer.from(privateKeyComponents.dmp1, 'base64'),
                            dmq1: Buffer.from(privateKeyComponents.dmq1, 'base64'),
                            coeff: Buffer.from(privateKeyComponents.coeff, 'base64')
                        }, 'components');
                        assert(key.isPrivate());
                        assert.equal(key.exportKey('pkcs1-private'), privateKeyPKCS1);
                        assert.equal(key.exportKey('pkcs8-public'), publicKeyPKCS8);
                    });

                    it('.importKey() from public components', function () {
                        var key = new NodeRSA();
                        key.importKey({
                            n: Buffer.from(publicKeyComponents.n, 'base64'),
                            e: 65537
                        }, 'components-public');
                        assert(key.isPublic(true));
                        assert.equal(key.exportKey('pkcs8-public'), publicKeyPKCS8);
                    });

                    it('.exportKey() private components', function () {
                        var key = new NodeRSA(privateKeyPKCS1);
                        var components = key.exportKey('components');
                        assert(_.isEqual({
                            n: components.n.toString('base64'),
                            e: components.e,
                            d: components.d.toString('base64'),
                            p: components.p.toString('base64'),
                            q: components.q.toString('base64'),
                            dmp1: components.dmp1.toString('base64'),
                            dmq1: components.dmq1.toString('base64'),
                            coeff: components.coeff.toString('base64')
                        }, privateKeyComponents));
                    });

                    it('.exportKey() public components', function () {
                        var key = new NodeRSA(publicKeyPKCS8);
                        var components = key.exportKey('components-public');
                        assert(_.isEqual({
                            n: components.n.toString('base64'),
                            e: components.e
                        }, publicKeyComponents));
                    });
                });

                describe('Different key formats', function () {
                    var sampleKey = new NodeRSA(fileKeyPKCS1);

                    for (var format in keys_formats) {
                        (function (format) {
                            var options = keys_formats[format];

                            it('should load from ' + options.file + ' (' + format + ')', function () {
                                var key = new NodeRSA(fs.readFileSync(keysFolder + options.file), format);
                                if (options.public) {
                                    assert.equal(key.exportKey('public'), sampleKey.exportKey('public'));
                                } else {
                                    assert.equal(key.exportKey(), sampleKey.exportKey());
                                }
                            });

                            it('should export to \'' + format + '\' format', function () {
                                var keyData = fs.readFileSync(keysFolder + options.file);
                                var exported = sampleKey.exportKey(format);

                                if (options.der) {
                                    assert(Buffer.isBuffer(exported));
                                    assert.equal(exported.toString('hex'), keyData.toString('hex'));
                                } else {
                                    assert(_.isString(exported));
                                    assert.equal(exported.replace(/\s+|\n\r|\n|\r$/gm, ''), keyData.toString('utf8').replace(/\s+|\n\r|\n|\r$/gm, ''));
                                }
                            });
                        })(format);
                    }
                });

                describe('OpenSSH keys', function () {
                    /*
                     * Warning!
                     * OpenSSH private key contains unused 64bit value, this value is set by ssh-keygen,
                     * but it's not used. NodeRSA does NOT store this value, so importing and exporting key sets this value to 0.
                     * This value is 0 in test files, so the tests pass.
                     */
                    it('key export should preserve key data including comment', function(){
                        const opensshPrivateKey = fs.readFileSync(keysFolder + 'id_rsa_comment').toString();
                        const opensshPublicKey = fs.readFileSync(keysFolder + 'id_rsa_comment.pub').toString();
                        const opensshPriv = new NodeRSA(opensshPrivateKey);
                        const opensshPub = new NodeRSA(opensshPublicKey);

                        assert.equal(
                            opensshPriv.exportKey('openssh-private'),
                            opensshPrivateKey
                        );

                        assert.equal(
                            opensshPriv.exportKey('openssh-public'),
                            opensshPublicKey
                        );

                        assert.equal(
                            opensshPub.exportKey('openssh-public'),
                            opensshPublicKey
                        );
                    });
                })
            });

            describe('Bad cases', function () {
                it('not public key', function () {
                    var key = new NodeRSA();
                    assert.throw(function () {
                        key.exportKey();
                    }, Error, 'This is not private key');
                    assert.throw(function () {
                        key.exportKey('public');
                    }, Error, 'This is not public key');
                });

                it('not private key', function () {
                    var key = new NodeRSA(publicKeyPKCS8);
                    assert.throw(function () {
                        key.exportKey();
                    }, Error, 'This is not private key');
                    assert.doesNotThrow(function () {
                        key.exportKey('public');
                    }, Error, 'This is not public key');
                });
            });
        });
    });

    describe('Encrypting & decrypting', function () {
        for (var env in environments) {
            (function (env) {
                for (var scheme_i in encryptSchemes) {
                    (function (scheme) {
                        describe('Environment: ' + env + '. Encryption scheme: ' + scheme, function () {
                            describe('Good cases', function () {
                                var encrypted = {};
                                var decrypted = {};
                                for (var i in dataBundle) {
                                    (function (i) {
                                        var key = null;
                                        var suit = dataBundle[i];

                                        it('`encrypt()` should encrypt ' + i, function () {
                                            key = new NodeRSA(generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey(), {
                                                environment: env,
                                                encryptionScheme: scheme
                                            });
                                            encrypted[i] = key.encrypt(suit.data);
                                            assert(Buffer.isBuffer(encrypted[i]));
                                            assert(encrypted[i].length > 0);
                                        });

                                        it('`decrypt()` should decrypt ' + i, function () {
                                            decrypted[i] = key.decrypt(encrypted[i], _.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding);
                                            if (Buffer.isBuffer(decrypted[i])) {
                                                assert.equal(suit.data.toString('hex'), decrypted[i].toString('hex'));
                                            } else {
                                                assert(_.isEqual(suit.data, decrypted[i]));
                                            }
                                        });
                                    })(i);
                                }


                            });

                            describe('Bad cases', function () {
                                it('unsupported data types', function () {
                                    assert.throw(function () {
                                        generatedKeys[0].encrypt(null);
                                    }, Error, 'Unexpected data type');
                                    assert.throw(function () {
                                        generatedKeys[0].encrypt(undefined);
                                    }, Error, 'Unexpected data type');
                                    assert.throw(function () {
                                        generatedKeys[0].encrypt(true);
                                    }, Error, 'Unexpected data type');
                                });

                                it('incorrect key for decrypting', function () {
                                    var encrypted = generatedKeys[0].encrypt('data');
                                    assert.throw(function () {
                                        generatedKeys[1].decrypt(encrypted);
                                    }, Error, 'Error during decryption');
                                });
                            });
                        });
                    })(encryptSchemes[scheme_i]);
                }

                describe('Environment: ' + env + '. encryptPrivate & decryptPublic', function () {
                    var encrypted = {};
                    var decrypted = {};
                    for (var i in dataBundle) {
                        (function (i) {
                            var key = null;
                            var suit = dataBundle[i];

                            it('`encryptPrivate()` should encrypt ' + i, function () {
                                key = new NodeRSA(generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey(), {
                                    environment: env
                                });
                                encrypted[i] = key.encryptPrivate(suit.data);
                                assert(Buffer.isBuffer(encrypted[i]));
                                assert(encrypted[i].length > 0);
                            });

                            it('`decryptPublic()` should decrypt ' + i, function () {
                                decrypted[i] = key.decryptPublic(encrypted[i], _.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding);
                                if (Buffer.isBuffer(decrypted[i])) {
                                    assert.equal(suit.data.toString('hex'), decrypted[i].toString('hex'));
                                } else {
                                    assert(_.isEqual(suit.data, decrypted[i]));
                                }
                            });
                        })(i);
                    }
                });
            })(environments[env]);
        }

        describe('Compatibility of different environments', function () {
            for (var scheme_i in encryptSchemes) {
                (function (scheme) {
                    var encrypted = {};
                    var decrypted = {};
                    for (var i in dataBundle) {
                        (function (i) {
                            var key1 = null;
                            var key2 = null;
                            var suit = dataBundle[i];

                            it('Encryption scheme: ' + scheme + ' `encrypt()` by browser ' + i, function () {
                                var key = generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey();
                                key1 = new NodeRSA(key, {
                                    environment: 'browser',
                                    encryptionScheme: scheme
                                });
                                key2 = new NodeRSA(key, {
                                    environment: 'node',
                                    encryptionScheme: scheme
                                });
                                encrypted[i] = key1.encrypt(suit.data);
                                assert(Buffer.isBuffer(encrypted[i]));
                                assert(encrypted[i].length > 0);
                            });

                            it('Encryption scheme: ' + scheme + ' `decrypt()` by node ' + i, function () {
                                decrypted[i] = key2.decrypt(encrypted[i], _.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding);
                                if (Buffer.isBuffer(decrypted[i])) {
                                    assert.equal(suit.data.toString('hex'), decrypted[i].toString('hex'));
                                } else {
                                    assert(_.isEqual(suit.data, decrypted[i]));
                                }
                            });
                        })(i);
                    }

                    encrypted = {};
                    decrypted = {};
                    for (var i in dataBundle) {
                        (function (i) {
                            var key1 = null;
                            var key2 = null;
                            var suit = dataBundle[i];

                            it('Encryption scheme: ' + scheme + ' `encrypt()` by node ' + i + '. Scheme', function () {
                                var key = generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey();
                                key1 = new NodeRSA(key, {
                                    environment: 'node',
                                    encryptionScheme: scheme
                                });
                                key2 = new NodeRSA(key, {
                                    environment: 'browser',
                                    encryptionScheme: scheme
                                });
                                encrypted[i] = key1.encrypt(suit.data);
                                assert(Buffer.isBuffer(encrypted[i]));
                                assert(encrypted[i].length > 0);
                            });

                            it('Encryption scheme: ' + scheme + ' `decrypt()` by browser ' + i, function () {
                                decrypted[i] = key2.decrypt(encrypted[i], _.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding);
                                if (Buffer.isBuffer(decrypted[i])) {
                                    assert.equal(suit.data.toString('hex'), decrypted[i].toString('hex'));
                                } else {
                                    assert(_.isEqual(suit.data, decrypted[i]));
                                }
                            });
                        })(i);
                    }
                })(encryptSchemes[scheme_i]);
            }

            describe('encryptPrivate & decryptPublic', function () {
                var encrypted = {};
                var decrypted = {};
                for (var i in dataBundle) {
                    (function (i) {
                        var key1 = null;
                        var key2 = null;
                        var suit = dataBundle[i];

                        it('`encryptPrivate()` by browser ' + i, function () {
                            var key = generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey();
                            key1 = new NodeRSA(key, {environment: 'browser'});
                            key2 = new NodeRSA(key, {environment: 'node'});
                            encrypted[i] = key1.encryptPrivate(suit.data);
                            assert(Buffer.isBuffer(encrypted[i]));
                            assert(encrypted[i].length > 0);
                        });

                        it('`decryptPublic()` by node ' + i, function () {
                            decrypted[i] = key2.decryptPublic(encrypted[i], _.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding);
                            if (Buffer.isBuffer(decrypted[i])) {
                                assert.equal(suit.data.toString('hex'), decrypted[i].toString('hex'));
                            } else {
                                assert(_.isEqual(suit.data, decrypted[i]));
                            }
                        });
                    })(i);
                }

                for (var i in dataBundle) {
                    (function (i) {
                        var key1 = null;
                        var key2 = null;
                        var suit = dataBundle[i];

                        it('`encryptPrivate()` by node ' + i, function () {
                            var key = generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey();
                            key1 = new NodeRSA(key, {environment: 'browser'});
                            key2 = new NodeRSA(key, {environment: 'node'});
                            encrypted[i] = key1.encryptPrivate(suit.data);
                            assert(Buffer.isBuffer(encrypted[i]));
                            assert(encrypted[i].length > 0);
                        });

                        it('`decryptPublic()` by browser ' + i, function () {
                            decrypted[i] = key2.decryptPublic(encrypted[i], _.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding);
                            if (Buffer.isBuffer(decrypted[i])) {
                                assert.equal(suit.data.toString('hex'), decrypted[i].toString('hex'));
                            } else {
                                assert(_.isEqual(suit.data, decrypted[i]));
                            }
                        });
                    })(i);
                }
            });
        });
    });

    describe('Signing & verifying', function () {
        for (var scheme_i in signingSchemes) {
            (function (scheme) {
                describe('Signing scheme: ' + scheme, function () {
                    var envs = ['node'];
                    if (scheme == 'pkcs1') {
                        envs = environments;
                    }

                    for (var env in envs) {
                        (function (env) {
                            describe('Good cases ' + (envs.length > 1 ? ' in ' + env + ' environment' : ''), function () {
                                var signed = {};
                                var key = null;

                                for (var i in dataBundle) {
                                    (function (i) {
                                        var suit = dataBundle[i];
                                        it('should sign ' + i, function () {
                                            key = new NodeRSA(generatedKeys[generatedKeys.length - 1].exportKey(), {
                                                signingScheme: scheme + '-sha256',
                                                environment: env
                                            });
                                            signed[i] = key.sign(suit.data);
                                            assert(Buffer.isBuffer(signed[i]));
                                            assert(signed[i].length > 0);
                                        });

                                        it('should verify ' + i, function () {
                                            assert(key.verify(suit.data, signed[i]));
                                        });
                                    })(i);
                                }

                                for (var alg in signHashAlgorithms[env]) {
                                    (function (alg) {
                                        it('signing with custom algorithm (' + alg + ')', function () {
                                            var key = new NodeRSA(generatedKeys[generatedKeys.length - 1].exportKey(), {
                                                signingScheme: scheme + '-' + alg,
                                                environment: env
                                            });
                                            var signed = key.sign('data');
                                            assert(key.verify('data', signed));
                                        });

                                        if (scheme === 'pss') {
                                            it('signing with custom algorithm (' + alg + ') with max salt length', function () {
                                                var a = alg.toLowerCase();
                                                var key = new NodeRSA(generatedKeys[generatedKeys.length - 1].exportKey(), {
                                                    signingScheme: { scheme: scheme, hash: a, saltLength: OAEP.digestLength[a] },
                                                    environment: env
                                                });
                                                var signed = key.sign('data');
                                                assert(key.verify('data', signed));
                                            });
                                        }
                                    })(signHashAlgorithms[env][alg]);
                                }
                            });

                            describe('Bad cases' + (envs.length > 1 ? ' in ' + env + ' environment' : ''), function () {
                                it('incorrect data for verifying', function () {
                                    var key = new NodeRSA(generatedKeys[0].exportKey(), {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    });
                                    var signed = key.sign('data1');
                                    assert(!key.verify('data2', signed));
                                });

                                it('incorrect key for signing', function () {
                                    var key = new NodeRSA(generatedKeys[0].exportKey('pkcs8-public'), {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    });
                                    assert.throw(function () {
                                        key.sign('data');
                                    }, Error, 'This is not private key');
                                });

                                it('incorrect key for verifying', function () {
                                    var key1 = new NodeRSA(generatedKeys[0].exportKey(), {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    });
                                    var key2 = new NodeRSA(generatedKeys[1].exportKey('pkcs8-public'), {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    });
                                    var signed = key1.sign('data');
                                    assert(!key2.verify('data', signed));
                                });

                                it('incorrect key for verifying (empty)', function () {
                                    var key = new NodeRSA(null, {environment: env});

                                    assert.throw(function () {
                                        key.verify('data', 'somesignature');
                                    }, Error, 'This is not public key');
                                });

                                it('different algorithms', function () {
                                    var singKey = new NodeRSA(generatedKeys[0].exportKey(), {
                                        signingScheme: scheme + '-md5',
                                        environment: env
                                    });
                                    var verifyKey = new NodeRSA(generatedKeys[0].exportKey(), {
                                        signingScheme: scheme + '-sha1',
                                        environment: env
                                    });
                                    var signed = singKey.sign('data');
                                    assert(!verifyKey.verify('data', signed));
                                });
                            });
                        })(envs[env]);
                    }

                    if (scheme !== 'pkcs1') {
                        return;
                    }

                    describe('Compatibility of different environments', function () {
                        for (var alg in signHashAlgorithms['browser']) {
                            (function (alg) {
                                it('signing with custom algorithm (' + alg + ') (equal test)', function () {
                                    var nodeKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'node'
                                    });
                                    var browserKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'browser'
                                    });

                                    assert.equal(nodeKey.sign('data', 'hex'), browserKey.sign('data', 'hex'));
                                });

                                it('sign in node & verify in browser (' + alg + ')', function () {
                                    var nodeKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'node'
                                    });
                                    var browserKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'browser'
                                    });

                                    assert(browserKey.verify('data', nodeKey.sign('data')));
                                });

                                it('sign in browser & verify in node (' + alg + ')', function () {
                                    var nodeKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'node'
                                    });
                                    var browserKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'browser'
                                    });

                                    assert(nodeKey.verify('data', browserKey.sign('data')));
                                });
                            })(signHashAlgorithms['browser'][alg]);
                        }
                    });
                });
            })(signingSchemes[scheme_i]);
        }
    });
});