# Node-RSA

Node.js RSA library<br/>
Based on jsbn library from Tom Wu http://www-cs-students.stanford.edu/~tjw/jsbn/

* Pure JavaScript
* No needed OpenSSL
* Generating keys
* Supports long messages for encrypt/decrypt
* Signing and verifying


## Installing

```shell
npm install node-rsa
```

### Testing

```shell
npm test
```

## Usage

### Create instance
```js
var key = new NodeRSA([key], [options]);
```
**key** - parameters of a generated key or the key in PEM format.<br/>
**options** - additional settings
 * **signingAlgorithm** - algorithm used for signing and verifying. Default _'RSA-SHA256'_

#### "Empty" key
```js
var key = new NodeRSA();
```

### Generate new key 512bit-length and with public exponent 65537
```js
var key = new NodeRSA({b: 512});
```

### Load key from PEM string

```js
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

```js
key.generateKeyPair([bits], [exp]);
key.loadFromPEM(pem_string);
```
**bits** - key size in bits. 2048 by default.  
**exp** - public exponent. 65537 by default.

### Export keys
```js
key.getPrivatePEM();
key.getPublicPEM();
```

### Test key
```js
key.isPrivate();
key.isPublic([strict]);
```
**strict** - if true method will return false if key pair have private exponent. Default *false*.

### Encrypting/decrypting
```js
key.encrypt(buffer, [encoding], [source_encoding]);
```
**buffer** - data for encrypting, may be string, Buffer, or any object/array. Arrays and objects will encoded to JSON string first.<br/>
**encoding** - encoding for output result, may be 'buffer', 'binary', 'hex' or 'base64'. Default *buffer*.
**source_encoding** - source encoding, works only with string buffer. Can take standard Node.js Buffer encodings (hex, utf8, base64, etc). *Utf8* by default.<br/>

```js
key.decrypt(buffer, [encoding]);
```
**buffer** - data for decrypting. Takes Buffer object or base64 encoded string.<br/>
**encoding** - encoding for result string. Can also take 'buffer' for raw Buffer object, or 'json' for automatic JSON.parse result. Default 'buffer'.

### Signing/Verifying

## Contributing

Questions, comments, bug reports, and pull requests are all welcome.

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
