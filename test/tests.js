/**
 * TODO: tests for compatibility with other rsa libraries
 */

var assert = require('chai').assert;
var _ = require('lodash');
var NodeRSA = require('../src/NodeRSA');

describe('NodeRSA', function(){
    var nodeRSA = null;
    var privateNodeRSA = null;
    var publicNodeRSA = null;

    var dataBundle = {
        "string": "ascii + юникод スラ ⑨",
        "empty string": "",
        "long string": "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
        "buffer": new Buffer("ascii + юникод スラ ⑨"),
        "json object": {str: "string", arr: ["a","r","r", "a", "y", true, '⑨'], int: 42, nested: {key: {key: 1}}},
        "json array": [1,2,3,4,5,6,7,8,9,[10,11,12,[13],14,15,[16,17,[18]]]]
    };

    describe('Work with keys', function(){
        it('.generateKeyPair() should make key pair', function(){
            nodeRSA = new NodeRSA({b: 512});
            assert.instanceOf(nodeRSA.keyPair, Object);
        });

        describe('PEM', function(){
            var privateKeyPEM = '-----BEGIN RSA PRIVATE KEY-----\n'+
                'MIIFwgIBAAKCAUEAsE1edyfToZRv6cFOkB0tAJ5qJor4YF5CccJAL0fS/o1Yk10V\n'+
                'SXH4Xx4peSJgYQKkO0HqO1hAz6k9dFQB4U1CnWtRjtNEcIfycqrZrhu6you5syb6\n'+
                'ScV3Zu/9bm7/DyaLlx/gJhUPR1OxOzaqsEvlu7hbDhNLIYo1zKFb/aUBbD6+UcaG\n'+
                'xH2BfFNdzVAtVSVpc/s2Y3sboMN7rByUj7937iQlaMINvVjyasynYuzHNw6ZRP9J\n'+
                'P9fwxrCyaxnTPWxVl0qvVaQO2+TtFMtDXH2OVZtWWeLHAL8cildw0G+u2qVqTqIG\n'+
                'EwNyJlsAHykaPFAMW0xLueumrSlB+JUJPrRvvw4nBCd4GOrNSlPCE/xlk1Cb8JaI\n'+
                'CTLvDUcYc3ZqL3jqAueBhkpw2uCz8xVJeOA1KY4kQIIx8JEBsAYzgyP2iy0CAwEA\n'+
                'AQKCAUAjBcudShkdgRpWSmNr94/IDrAxpeu/YRo79QXBHriIftW4uIYRCAX6B0jf\n'+
                '2ndg7iBn8Skxzs9ZMVqW8FVLR4jTMs2J3Og8npUIOG5zyuhpciZas4SHASY+GbCz\n'+
                'rnMWtGaIh/mENyzI05RimfKAgSNLDk1wV17Wc9lKJEfc9Fl7Al/WaOS+xdviMcFx\n'+
                'ltrajksLkjz0uDD917eKskbE45lULfGqeI0kYDadWp88pw6ikXJln2p3Y1PNQF3e\n'+
                'y2cN+Snzd0jx/c5fD9B1zxKYv5bUo+UnTzBxV81e9xCJfkdXv+6D5qDn1gGLdZZa\n'+
                '5FxtZbRgVh/ZlqP9xYr72as/WFmIA20wRgHPgWvLyHsh0XThqZf2/O3R8KmFv8aT\n'+
                '+kmc5is6sVItIIi7ltorVapTkJai3zz/VSMBBaL+ytFN9jVl4QKBoQDfL8TMeZXu\n'+
                'gBTN7yq6zZWN8+60MUaxz0/lKdzmo35z32rpVKdsYd922pmcsNYaoj/H9L3j/NP4\n'+
                '9z+SHfYpWvTa7AvJfNlXYc3BRXIarpfnXsm65IzKzHaF9i2xdXxkfTEYIvOQDMLF\n'+
                'SiiObWJMV+QqUxb3luu3/CR3IcbgeTOpdiC/T/Zl/YYl17JqZTHmLFZPq7xewttg\n'+
                'zQorDRWIFDtlAoGhAMo4+uM9f4BpOHSmayhLhHArIGs4386BkXSeOLeQitaQJ/2c\n'+
                'zb459O87XoCAonZbq+dI7XRnBU3toQvEsZgrtGkOFXCZJMWAQxD5BQ5vEYT6c86h\n'+
                'uGpX6h3ODlJ6UGi+5CWyMQ1cFlBkfffFAarjSYTVlyj736sOeDuJWX133z5VQBQ8\n'+
                '1xSH23kNF95vxB4I1fXG8WL11YZU7VEwSLC4aCkCgaAKRj+wDhTZ4umSRWVZLiep\n'+
                'XkZp4y7W9q095nx13abvnKRmU3BVq/fGl++kZ/ujRD7dbKXlPflgJ7m0d06ivr4w\n'+
                '6dbtEqNKw4TeVd0X31u82f89bFIS7/Cw4BFgbwEn+x9sdgdyZTP+MxjE3cI9s3oc\n'+
                'fLC8+ySk1qWzGkn2gX3gWkDNrdexAEfRrClZfokaiIX8qvJEBoJk5WuHadXI6u2F\n'+
                'AoGgByidOQ4kRVd0OCzr/jEuLwpXy3Pn+Fd93rL7LwRe5dmUkNXMMr+6e/2OCt6C\n'+
                '4c28+CMMxOIgvfF7kf8Uil6BtHZbK/E/6/3uYdtu4mPsKtjy4I25CYqzLvrsZt8N\n'+
                'maeoS+1S7zYjVBU6oFrJBFOndpxZDYpdEKEigHkMQfTMYliCPDUrJ/7nNhHQln8+\n'+
                'YhHOATVZtjcdp/O5svYSnK7qgQKBoDd3lFWrPatgxpF1JXMEFFbaIRdNxHkKA4YY\n'+
                'gMTM4MPgViunYX/yJ7SaX8jWnC231A9uVn4+kb+DvKjc+ZuTQvnIUK2u6LvIinVF\n'+
                'snDEA+BbXwehAtwdHDMDtqYFdx4hvCWQwBNn4p3J0OO2tbYVMtvM5aOEfRSYagfm\n'+
                'RywhDUAjW8U0RBnzlmXhQQ6B9bjqooS2MsRrJrS5CU682fb3hBo=\n'+
                '-----END RSA PRIVATE KEY-----';

            var publicKeyPEM = '-----BEGIN PUBLIC KEY-----\n'+
                'MIIBYjANBgkqhkiG9w0BAQEFAAOCAU8AMIIBSgKCAUEAsE1edyfToZRv6cFOkB0t\n'+
                'AJ5qJor4YF5CccJAL0fS/o1Yk10VSXH4Xx4peSJgYQKkO0HqO1hAz6k9dFQB4U1C\n'+
                'nWtRjtNEcIfycqrZrhu6you5syb6ScV3Zu/9bm7/DyaLlx/gJhUPR1OxOzaqsEvl\n'+
                'u7hbDhNLIYo1zKFb/aUBbD6+UcaGxH2BfFNdzVAtVSVpc/s2Y3sboMN7rByUj793\n'+
                '7iQlaMINvVjyasynYuzHNw6ZRP9JP9fwxrCyaxnTPWxVl0qvVaQO2+TtFMtDXH2O\n'+
                'VZtWWeLHAL8cildw0G+u2qVqTqIGEwNyJlsAHykaPFAMW0xLueumrSlB+JUJPrRv\n'+
                'vw4nBCd4GOrNSlPCE/xlk1Cb8JaICTLvDUcYc3ZqL3jqAueBhkpw2uCz8xVJeOA1\n'+
                'KY4kQIIx8JEBsAYzgyP2iy0CAwEAAQ==\n'+
                '-----END PUBLIC KEY-----';

            it('.loadFromPrivatePEM() should load private key from PEM string', function(){
                privateNodeRSA = new NodeRSA(privateKeyPEM);
                assert.instanceOf(privateNodeRSA.keyPair, Object);
                assert(privateNodeRSA.isPrivate());
                assert(privateNodeRSA.isPublic());
                assert(!privateNodeRSA.isPublic(true));
            });

            it('.loadFromPublicPEM() should load public key from PEM string', function(){
                publicNodeRSA = new NodeRSA(publicKeyPEM);
                assert.instanceOf(privateNodeRSA.keyPair, Object);
                assert(publicNodeRSA.isPublic());
                assert(publicNodeRSA.isPublic(true));
                assert(!publicNodeRSA.isPrivate());
            });

            it('.toPrivatePEM() should return private PEM string', function(){
                assert.equal(privateNodeRSA.getPrivatePEM(), privateKeyPEM);
            });

            it('.toPublicPEM() from public key should return public PEM string', function(){
                assert.equal(publicNodeRSA.getPublicPEM(), publicKeyPEM);
            });

            it('.toPublicPEM() from private key should return public PEM string', function(){
                assert.equal(privateNodeRSA.getPublicPEM(), publicKeyPEM);
            });
        });
    });


    var dataForEncrypt = "ascii + юникод スラ ⑨";
    var longDataForEncrypt = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    var JSONForEncrypt = {str: "string", arr: ["a","r","r", "a", "y", true, '⑨'], int: 42, nested: {key: {key: 1}}}

    var encrypted = null;
    var encryptedLong = null;
    var encryptedBuffer = null;
    var encryptedJSON = null;

    var decrypted = null;
    var decryptedLong = null;
    var decryptedJSON = null;

    describe('Encrypting', function(){
        it('.encrypt() should return Buffer object', function(){
            encryptedBuffer = nodeRSA.encrypt(dataForEncrypt, 'buffer');
            assert(Buffer.isBuffer(encryptedBuffer));
        });

        it('.encrypt() should return base64 encrypted string', function(){
            encrypted = nodeRSA.encrypt(dataForEncrypt, 'base64');
            assert.isString(encrypted);
            assert.match(encrypted, /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/);
        });

        it('.encrypt() should return encrypted Buffer for long message', function(){
            encryptedLong = nodeRSA.encrypt(longDataForEncrypt, 'buffer');
            assert(Buffer.isBuffer(encryptedLong));
        });

        it('.encrypt() for js object. Should return Buffer object', function(){
            encryptedJSON = nodeRSA.encrypt(JSONForEncrypt, 'buffer');
            assert(Buffer.isBuffer(encryptedJSON));
        });
    });

    describe('Decrypting', function(){
        it('.decrypt() should return decrypted Buffer', function(){
            decrypted = nodeRSA.decrypt(encryptedBuffer);
            assert(Buffer.isBuffer(decrypted));
        });

        it('.decrypt() should return decrypted string', function(){
            decrypted = nodeRSA.decrypt(new Buffer(encrypted, 'base64'), 'utf8');
            assert.isString(decrypted);
        });

        it('.decrypt() should return decrypted string for long message', function(){
            decryptedLong = nodeRSA.decrypt(encryptedLong, 'utf8');
            assert.isString(decryptedLong);
        });

        it('.decrypt() for js object. Should return decrypted js object', function(){
            decryptedJSON = nodeRSA.decrypt(encryptedJSON, 'json');
            assert.isObject(decryptedJSON);
        });

        it('source and decrypted should be the same', function(){
            assert.equal(decrypted, dataForEncrypt);
        });

        it('long source and decrypted should be the same', function(){
            assert.equal(decryptedLong, longDataForEncrypt);
        });

        it('source JSON and decrypted JSON should be the same', function(){
            assert(_.isEqual(decryptedJSON, JSONForEncrypt));
        });
    });

    describe('Signing & verifying', function () {


        var signed = {};

        for(var i in dataBundle) {
            var sign = dataBundle[i];
            var signature = null;

            it('should signed '+i, function(){
                signature = nodeRSA.sign(sign, 'hex');
                console.log(signature)
            });

        }
    });
});