import keybearer from '../src/kb.js';

console.log('=== End-to-End Encryption/Decryption Test ===\n');

try {
  // Step 1: Generate salt
  console.log('1. Generating salt...');
  keybearer.makeSalt();
  console.log('   ✓ Salt length:', keybearer._salt.length, 'bytes');

  // Step 2: Set plaintext
  console.log('\n2. Setting plaintext...');
  const testData = new TextEncoder().encode('Hello, Keybearer v2!');
  keybearer.setPlaintext(testData, 'test.txt', 'text/plain');
  console.log('   ✓ Plaintext length:', testData.length, 'bytes');

  // Step 3: Encrypt with passwords
  console.log('\n3. Encrypting with passwords...');
  const passwords = ['alpha', 'beta', 'gamma'];
  const threshold = 2;
  console.log('   Passwords:', passwords.join(', '));
  console.log('   Threshold:', threshold);

  const encrypted = keybearer.encryptWithPasswords(passwords, threshold);
  console.log('   ✓ Encrypted JSON length:', encrypted.length, 'bytes');

  const encObj = JSON.parse(encrypted);
  console.log('   Version:', encObj.v);
  console.log('   Mode:', encObj.mode);
  console.log('   Keys:', encObj.keys.length);
  console.log('   Salt (base64) length:', encObj.salt.length);
  console.log('   IV (base64) length:', encObj.iv.length);

  // Step 4: Decrypt with subset of passwords
  console.log('\n4. Decrypting with passwords...');
  keybearer.setCipherJSON(encrypted);
  keybearer.makeKeyCombinations(['alpha', 'beta'], threshold);

  console.log('   Derived keys:', keybearer._keys.length);
  console.log('   Key 0 length:', keybearer._keys[0].length, 'bytes');
  console.log('   Encrypted master keys in file:', keybearer._cipherobj.keys.length);
  console.log('   Key 0 IV length:', keybearer._cipherobj.keys[0].iv.length, 'bytes');
  console.log('   Key 0 key length:', keybearer._cipherobj.keys[0].key.length, 'bytes');

  const gotKey = keybearer.decryptKeys();
  if (!gotKey) {
    throw new Error('Failed to decrypt master key');
  }
  console.log('   ✓ Master key decrypted');
  console.log('   Master key length:', keybearer._master.length, 'bytes');

  keybearer.decryptCiphertext();
  const decrypted = new TextDecoder().decode(keybearer.getPlaintext());
  console.log('   ✓ Ciphertext decrypted');
  console.log('   Result:', decrypted);

  if (decrypted === 'Hello, Keybearer v2!') {
    console.log('\n🎉 SUCCESS! All tests passed!');
  } else {
    throw new Error('Decryption mismatch!');
  }

} catch (err) {
  console.error('\n❌ ERROR:', err.message);
  console.error(err.stack);
  process.exit(1);
}
