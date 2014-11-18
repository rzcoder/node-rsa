# Node-RSA

Node.js RSA library<br/>
Based on jsbn library from Tom Wu http://www-cs-students.stanford.edu/~tjw/jsbn/

* Pure JavaScript
* No needed OpenSSL
* Generating keys
* Supports long messages for encrypt/decrypt
* Signing and verifying
 

## Example

```javascript
var NodeRSA = require('node-rsa');
var key = new NodeRSA({b: 512});

var text = 'Hello RSA!';
var encrypted = key.encrypt(text, 'base64');
console.log('encrypted: ', encrypted);
var decrypted = key.decrypt(encrypted, 'utf8');
console.log('decrypted: ', decrypted);
```


## Installing

```shell
npm install node-rsa
```

### Testing

```shell
npm test
```

## Work environment

This library developed and tested primary for Node.js, but it still can work in browsers with [browserify](http://browserify.org/).

## Usage

### Create instance
```javascript
var NodeRSA = require('node-rsa');

var key = new NodeRSA([key], [options]);
```
**key** - parameters of a generated key or the key in PEM format.<br/>

#### "Empty" key
```javascript
var key = new NodeRSA();
```

### Generate new key 512bit-length and with public exponent 65537
```javascript
var key = new NodeRSA({b: 512});
```

### Load key from PEM string

```javascript
var key = new NodeRSA('-----BEGIN RSA PRIVATE KEY-----\n'+
                      'MIIBOQIBAAJAVY6quuzCwyOWzymJ7C4zXjeV/232wt2ZgJZ1kHzjI73wnhQ3WQcL\n'+
                      'DFCSoi2lPUW8/zspk0qWvPdtp6Jg5Lu7hwIDAQABAkBEws9mQahZ6r1mq2zEm3D/\n'+
                      'VM9BpV//xtd6p/G+eRCYBT2qshGx42ucdgZCYJptFoW+HEx/jtzWe74yK6jGIkWJ\n'+
                      'AiEAoNAMsPqwWwTyjDZCo9iKvfIQvd3MWnmtFmjiHoPtjx0CIQCIMypAEEkZuQUi\n'+
                      'pMoreJrOlLJWdc0bfhzNAJjxsTv/8wIgQG0ZqI3GubBxu9rBOAM5EoA4VNjXVigJ\n'+
                      'QEEk1jTkp8ECIQCHhsoq90mWM/p9L5cQzLDWkTYoPI49Ji+Iemi2T5MRqwIgQl07\n'+
                      'Es+KCn25OKXR/FJ5fu6A6A+MptABL3r8SEjlpLc=\n'+
                      '-----END RSA PRIVATE KEY-----');
```

Also you can use next methods:

```javascript
key.generateKeyPair([bits], [exp]);
key.loadFromPEM(pem_string|buffer_contains_pem);
```
**bits** - key size in bits. 2048 by default.  
**exp** - public exponent. 65537 by default.

### Export keys
```javascript
key.getPrivatePEM();
key.getPublicPEM();
```

### Properties

#### Key testing
```javascript
key.isPrivate();
key.isPublic([strict]);
```
**strict** - if true method will return false if key pair have private exponent. Default `false`.

```javascript
key.isEmpty();
```
Return `true` if key pair doesn't have any data.

#### Key info
```javascript
key.getKeySize();
```
Return key size in bits.

```javascript
key.getMaxMessageSize();
```
Return max data size for encrypt in bytes.

### Encrypting/decrypting

*As of v0.1.55 the default encryption scheme is RSAES-OAEP using sha1 and mgf1.
PKCS1 is still available with the following configuring*

```javascript
key.schemeEncryption = new NodeRSA.RSA.PKCS1.Default;
```

```javascript
key.encrypt(buffer, [encoding], [source_encoding]);
```
Return encrypted data.<br/>
**buffer** - data for encrypting, may be string, Buffer, or any object/array. Arrays and objects will encoded to JSON string first.<br/>
**encoding** - encoding for output result, may be `'buffer'`, `'binary'`, `'hex'` or `'base64'`. Default `'buffer'`.<br/>
**source_encoding** - source encoding, works only with string buffer. Can take standard Node.js Buffer encodings (hex, utf8, base64, etc). `'utf8'` by default.<br/>

```javascript
key.decrypt(buffer, [encoding]);
```
Return decrypted data.<br/>
**buffer** - data for decrypting. Takes Buffer object or base64 encoded string.<br/>
**encoding** - encoding for result string. Can also take `'buffer'` for raw Buffer object, or `'json'` for automatic JSON.parse result. Default `'buffer'`.

### Signing/Verifying

*As of v0.1.55 the default signature scheme is RSASSA-PSS using sha1.
PKCS1 is still available with the following configuring*

```javascript
key.schemeSignature = new NodeRSA.RSA.PKCS1.Default;
```

```javascript
key.sign(buffer, [encoding], [source_encoding]);
```
Return signature for buffer. All the arguments are the same as for `encrypt` method.

```javascript
key.verify(buffer, signature, [source_encoding], [signature_encoding])
```
Return result of check, `true` or `false`.<br/>
**buffer** - data for check, same as `encrypt` method.<br/>
**signature** - signature for check, result of `sign` method.<br/>
**source_encoding** - same as for `encrypt` method.<br/>
**signature_encoding** - encoding of given signature. May be `'buffer'`, `'binary'`, `'hex'` or `'base64'`. Default `'buffer'`.

### Changing Encryption/Signature schemes.

Schemes are the way RSA packs up it's data before encrypting/decrypting/signing/verifying and there are a few ways that it can do it. The most common are RSAES-OAEP, RSASSA-PSS, RSAES-PKCS1-v1_5(encryption/decryption), and RSASSA-PKCS1-v1_5(signing/verifying).
As of v0.1.55 these 4 mentioned schemes are included in the package with the ability to easily add more later and by users. See below for how to configure NodeRSA to use these different schemes.

*Note: The default encryption / signature schemes have been changed from PKCS1 to the more secure OAEP(encryption) and PSS(signature) schemes as per the recommendations of the spec, this can be breaking.*

```javascript
key.schemeSignature = NodeRSA.RSA.PSS.Default; // This is an object that has been automatically instantiated and has the default settings for PSS signing.
key.schemeSignature = NodeRSA.RSA.PKCS1.Default; // This is an object that has been automatically instantiated and has the default settings for PKCS1 signing/encrypting.

key.schemeEncryption = NodeRSA.RSA.OAEP.Default; // This is an object that has been automatically instantiated and has the default settings for OAEP encrypting.
key.schemeEncryption = NodeRSA.RSA.PKCS1.Default; // This is an object that has been automatically instantiated and has the default settings for PKCS1 signing/encrypting.
```
To change schemes between the various defaults, each provided scheme class has a property named "Default" that provides a scheme object with the default settings for that scheme.

```javascript
var pssMD5Scheme = new NodeRSA.RSA.PSS({
	// The options a scheme accepts should be documented in the scheme definition.
	hash: "md5", // Use a different type of hashing function instead of sha1
	mgf:  customMaskGenerationFunction // Use a custom mask generation function that accepts 3 parameters (seed, maskLength, hashFunction)
});
key.schemeSignature = pssMD5Scheme;
key2.schemeSignature = pssMD5Scheme;
```
Schemes can also be initialized with custom options and can be shared between keys.

## Contributing

Questions, comments, bug reports, and pull requests are all welcome.

## Changelog

### 0.1.54
 * Added support for loading PEM key from Buffer (`fs.readFileSync()` output)
 * Added `isEmpty()` method

### 0.1.52
 * Improve work with not properly trimming PEM strings

### 0.1.50
 * Implemented native js signing and verifying for browsers
 * `options.signingAlgorithm` now takes only hash-algorithm name
 * Added `.getKeySize()` and `.getMaxMessageSize()` methods
 * `.loadFromPublicPEM` and `.loadFromPrivatePEM` methods marked as private

### 0.1.40
 * Added signing/verifying

### 0.1.30
 * Added long message support


## License for NodeRSA.js

Copyright (c) 2014  rzcoder<br/>
All Rights Reserved.

BSD

## Licensing for code used in rsa.js and jsbn.js

Copyright (c) 2003-2005  Tom Wu<br/>
All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

In addition, the following condition applies:

All redistributions must retain an intact copy of this copyright notice
and disclaimer.
