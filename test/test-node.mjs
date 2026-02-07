/**
 * Node.js test for Keybearer v2 core functionality
 */

// Node v15+ has crypto.webcrypto, but we need to make it available as global crypto
import { webcrypto } from 'crypto';
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: false,
    configurable: false
  });
}

// Import our modules
import * as noble from '../src/kb-noble.js';

console.log('=== Keybearer v2 Node.js Test ===\n');

try {
  // Test 1: Random bytes generation
  console.log('Test 1: Generate random bytes...');
  const randomBytes = noble.getRandomBytes(32);
  console.log('✓ Generated', randomBytes.length, 'random bytes');

  // Test 2: PBKDF2 key derivation
  console.log('\nTest 2: PBKDF2 key derivation...');
  const password = 'test password';
  const salt = noble.getRandomBytes(16);
  const key = noble.deriveKeyFromPassword(password, salt, 10000, 32);
  console.log('✓ Derived key:', key.length, 'bytes');

  // Test 3: ChaCha20-Poly1305 encryption
  console.log('\nTest 3: ChaCha20-Poly1305 encryption...');
  const plaintext = new TextEncoder().encode('Hello, Keybearer v2!');
  const encKey = noble.getRandomBytes(32);
  const { ciphertext, nonce } = noble.encryptChaCha20Poly1305(encKey, plaintext);
  console.log('✓ Encrypted', plaintext.length, 'bytes →', ciphertext.length, 'bytes');
  console.log('  Nonce:', nonce.length, 'bytes');

  // Test 4: ChaCha20-Poly1305 decryption
  console.log('\nTest 4: ChaCha20-Poly1305 decryption...');
  const decrypted = noble.decryptChaCha20Poly1305(encKey, ciphertext, nonce);
  const decryptedText = new TextDecoder().decode(decrypted);
  console.log('✓ Decrypted:', decryptedText);

  if (decryptedText === 'Hello, Keybearer v2!') {
    console.log('\n🎉 ALL TESTS PASSED!');
  } else {
    console.log('\n✗ Decryption mismatch!');
    process.exit(1);
  }

  // Test 5: Base64 encoding/decoding
  console.log('\nTest 5: Base64 encoding/decoding...');
  const data = new Uint8Array([1, 2, 3, 4, 5]);
  const b64 = noble.encodeBase64(data);
  const decoded = noble.decodeBase64(b64);
  console.log('✓ Base64:', Array.from(data), '→', b64, '→', Array.from(decoded));

  // Test 6: Random integers
  console.log('\nTest 6: Random integers...');
  const randoms = noble.randomIntegers(100, 10);
  console.log('✓ Generated 10 random integers:', randoms);
  const allValid = randoms.every(n => n >= 0 && n < 100);
  console.log('  All in range [0, 100):', allValid);

  console.log('\n✅ All Noble crypto tests passed!');

} catch (err) {
  console.error('\n✗ ERROR:', err.message);
  console.error(err.stack);
  process.exit(1);
}
