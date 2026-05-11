import NodeRSA from 'node-rsa';

console.log('=== node-rsa ESM example ===');

const key = new NodeRSA({ b: 1024 });
console.log(`Generated key size: ${key.getKeySize()} bits`);

const ct = key.encrypt('hello from ESM');
console.log(`Ciphertext length: ${ct.length} bytes`);

const pt = key.decrypt(ct, 'utf8');
console.log(`Decrypted: ${pt}`);

const sig = key.sign('signed payload');
const ok = key.verify('signed payload', sig);
console.log(`Signature verify: ${ok}`);

if (pt !== 'hello from ESM' || !ok) {
  console.error('FAILED');
  process.exit(1);
}
console.log('OK');
