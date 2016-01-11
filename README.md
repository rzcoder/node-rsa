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
> <sub>Requires nodejs >= 0.10.x or io.js >= 1.x</sub>

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

var key = new NodeRSA([keyData, [format]], [options]);
```

* keyData — `{string|buffer|object}` — parameters for generating key or the key in one of supported formats.<br/>
* format — `{string}` — format for importing key. See more details about formats in [Export/Import](#importexport-keys) section.<br/>
* options — `{object}` — additional settings.

#### Options
You can specify some options by second/third constructor argument, or over `key.setOptions()` method.

* environment — working environment (default autodetect):
    * `'browser'` — will run pure js implementation of RSA algorithms.
    * `'node'` for `nodejs >= 0.10.x or io.js >= 1.x` — provide some native methods like sign/verify and encrypt/decrypt.
* encryptionScheme — padding scheme for encrypt/decrypt. Can be `'pkcs1_oaep'` or `'pkcs1'`. Default `'pkcs1_oaep'`.
* signingScheme — scheme used for signing and verifying. Can be `'pkcs1'` or `'pss'` or 'scheme-hash' format string (eg `'pss-sha1'`). Default `'pkcs1-sha256'`, or, if chosen pss: `'pss-sha1'`.

> *Notice:* This lib supporting next hash algorithms: `'md5'`, `'ripemd160'`, `'sha1'`, `'sha256'`, `'sha512'` in browser and node environment and additional `'md4'`, `'sha'`, `'sha224'`, `'sha384'` in node only.

<sub>Some [advanced options info](https://github.com/rzcoder/node-rsa/wiki/Advanced-options)</sub>

#### Creating "empty" key
```javascript
var key = new NodeRSA();
```

#### Generate new 512bit-length key
```javascript
var key = new NodeRSA({b: 512});
```

Also you can use next method:

```javascript
key.generateKeyPair([bits], [exp]);
```

* bits — `{int}` — key size in bits. 2048 by default.
* exp — `{int}` — public exponent. 65537 by default.

#### Load key from PEM string

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

### Import/Export keys
```javascript
key.importKey(keyData, [format]);
key.exportKey([format]);
```

* keyData — `{string|buffer}` — key in PEM string **or** Buffer containing PEM string **or** Buffer containing DER encoded data.
* format  — `{string}` — format id for export/import.

#### Format string syntax
Format string composed of several parts: `scheme-[key_type]-[output_type]`<br/>

Scheme — NodeRSA supports multiple format schemes for import/export keys:

  * `'pkcs1'` — public key starts from `'-----BEGIN RSA PUBLIC KEY-----'` header and private key starts from `'-----BEGIN RSA PRIVATE KEY-----'` header
  * `'pkcs8'` — public key starts from `'-----BEGIN PUBLIC KEY-----'` header and private key starts from `'-----BEGIN PRIVATE KEY-----'` header

Key type — can be `'private'` or `'public'`. Default `'private'`<br/>
Output type — can be:

 * `'pem'` — Base64 encoded string with header and footer. Used by default.
 * `'der'` — Binary encoded key data.

> *Notice:* For import, if *keyData* is PEM string or buffer containing string, you can do not specify format, but if you provide *keyData* as DER you must specify it in format string.

**Shortcuts and examples**
 * `'private'` or `'pkcs1'` or `'pkcs1-private'` == `'pkcs1-private-pem'` — private key encoded in pcks1 scheme as pem string.
 * `'public'` or `'pkcs8-public'` == `'pkcs8-public-pem'` — public key encoded in pcks8 scheme as pem string.
 * `'pkcs8'` or `'pkcs8-private'` == `'pkcs8-private-pem'` — private key encoded in pcks8 scheme as pem string.
 * `'pkcs1-der'` == `'pkcs1-private-der'` — private key encoded in pcks1 scheme as binary buffer.
 * `'pkcs8-public-der'` — public key encoded in pcks8 scheme as binary buffer.

**Code example**

```javascript
var keyData = '-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----';
key.importKey(keyData, 'pkcs8');
var publicDer = key.exportKey('pkcs8-public-der');
var privateDer = key.exportKey('pkcs1-der');
```

### Properties

#### Key testing
```javascript
key.isPrivate();
key.isPublic([strict]);
```
strict — `{boolean}` — if true method will return false if key pair have private exponent. Default `false`.

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

```javascript
key.encrypt(buffer, [encoding], [source_encoding]);
key.encryptPrivate(buffer, [encoding], [source_encoding]); // use private key for encryption
```
Return encrypted data.<br/>

* buffer — `{buffer}` —  data for encrypting, may be string, Buffer, or any object/array. Arrays and objects will encoded to JSON string first.<br/>
* encoding — `{string}` — encoding for output result, may be `'buffer'`, `'binary'`, `'hex'` or `'base64'`. Default `'buffer'`.<br/>
* source_encoding — `{string}` —  source encoding, works only with string buffer. Can take standard Node.js Buffer encodings (hex, utf8, base64, etc). `'utf8'` by default.<br/>

```javascript
key.decrypt(buffer, [encoding]);
key.decryptPublic(buffer, [encoding]); // use public key for decryption
```
Return decrypted data.<br/>

* buffer — `{buffer}` — data for decrypting. Takes Buffer object or base64 encoded string.<br/>
* encoding — `{string}` — encoding for result string. Can also take `'buffer'` for raw Buffer object, or `'json'` for automatic JSON.parse result. Default `'buffer'`.

> *Notice:* `encryptPrivate` and `decryptPublic` using only pkcs1 padding type 1 (not random)

### Signing/Verifying
```javascript
key.sign(buffer, [encoding], [source_encoding]);
```
Return signature for buffer. All the arguments are the same as for `encrypt` method.

```javascript
key.verify(buffer, signature, [source_encoding], [signature_encoding])
```
Return result of check, `true` or `false`.<br/>

* buffer — `{buffer}` — data for check, same as `encrypt` method.<br/>
* signature — `{string}` — signature for check, result of `sign` method.<br/>
* source_encoding — `{string}` — same as for `encrypt` method.<br/>
* signature_encoding — `{string}` — encoding of given signature. May be `'buffer'`, `'binary'`, `'hex'` or `'base64'`. Default `'buffer'`.

## Contributing

Questions, comments, bug reports, and pull requests are all welcome.

## Changelog

### 0.2.30
 * Fixed a issue when the key was generated by 1 bit smaller than specified. It may slow down the generation of large keys.    

### 0.2.24
 * Now used old hash APIs for webpack compatible.

### 0.2.22
 * `encryptPrivate` and `decryptPublic` now using only pkcs1 (type 1) padding.

### 0.2.20
 * Added `.encryptPrivate()` and `.decryptPublic()` methods.
 * Encrypt/decrypt methods in nodejs 0.12.x and io.js using native implementation (> 40x speed boost).
 * Fixed some regex issue causing catastrophic backtracking.

### 0.2.10
 * **Methods `.exportPrivate()` and `.exportPublic()` was replaced by `.exportKey([format])`.**
    * By default `.exportKey()` returns private key as `.exportPrivate()`, if you need public key from `.exportPublic()` you must specify format as `'public'` or `'pkcs8-public-pem'`.
 * Method `.importKey(key, [format])` now has second argument.

### 0.2.0
 * **`.getPublicPEM()` method was renamed to `.exportPublic()`**
 * **`.getPrivatePEM()` method was renamed to `.exportPrivate()`**
 * **`.loadFromPEM()` method was renamed to `.importKey()`**
 * Added PKCS1_OAEP encrypting/decrypting support.
     * **PKCS1_OAEP now default scheme, you need to specify 'encryptingScheme' option to 'pkcs1' for compatibility with 0.1.x version of NodeRSA.**
 * Added PSS signing/verifying support.
 * Signing now supports `'md5'`, `'ripemd160'`, `'sha1'`, `'sha256'`, `'sha512'` hash algorithms in both environments
 and additional `'md4'`, `'sha'`, `'sha224'`, `'sha384'` for nodejs env.
 * **`options.signingAlgorithm` was renamed to `options.signingScheme`**
 * Added `encryptingScheme` option.
 * Property `key.options` now mark as private. Added `key.setOptions(options)` method.


### 0.1.54
 * Added support for loading PEM key from Buffer (`fs.readFileSync()` output).
 * Added `isEmpty()` method.

### 0.1.52
 * Improve work with not properly trimming PEM strings.

### 0.1.50
 * Implemented native js signing and verifying for browsers.
 * `options.signingAlgorithm` now takes only hash-algorithm name.
 * Added `.getKeySize()` and `.getMaxMessageSize()` methods.
 * `.loadFromPublicPEM` and `.loadFromPrivatePEM` methods marked as private.

### 0.1.40
 * Added signing/verifying.

### 0.1.30
 * Added long message support.


## License

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

[![Build Status](https://travis-ci.org/rzcoder/node-rsa.svg?branch=master)](https://travis-ci.org/rzcoder/node-rsa)
