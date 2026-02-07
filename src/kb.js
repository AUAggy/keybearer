/**
 * Keybearer v2 - Client-side Shamir's Secret Sharing file encryption
 *
 * Migration to Noble cryptography libraries (@noble/ciphers, @noble/hashes)
 * Maintains backward compatibility with SJCL-encrypted files (v1)
 */

import * as noble from './kb-noble.js';
import * as legacy from './kb-legacy.js';

// Global keybearer object (IIFE export for browser compatibility)
const keybearer = {
  // Public settings
  salt_length: 16, // in bytes (changed from SJCL words to bytes)
  aes_key_strength: 32, // in bytes (256-bit key)
  aes_cipher_mode: 'chacha20poly1305', // v2 default (v1 was 'ccm')
  pbkdf2_iterations: 50000,

  // Private state
  _badngramlist: [],
  _salt: null,
  _plaintext: null, // Uint8Array of file to be encrypted
  _cipherobj: null, // parsed encrypted data object
  _passwords: [],
  _keys: [], // Derived keys (Uint8Array arrays for v2, bitArrays for v1 compat)
  _master: null, // Master encryption key
  _filename: null,
  _filetype: null,
  _nPasswords: null,
  _nToUnlock: null,
  _lastMetadata: null,
  _wordlist: [],

  /**
   * Load wordlist from URL
   */
  loadWordlist: function(url, field, callback) {
    const startTime = Date.now();
    const txtFile = new XMLHttpRequest();
    txtFile.open('GET', url, true);
    txtFile.onreadystatechange = function() {
      if (txtFile.readyState === 4 && txtFile.status === 200) {
        keybearer[field] = txtFile.responseText.split('\n');
        const endTime = Date.now();
        // No need to seed RNG - crypto.getRandomValues() is always ready
        callback();
      }
    };
    txtFile.send();
  },

  /**
   * Generate password from wordlist
   */
  makePassword: function(length) {
    const pwd = [];
    const selections = noble.randomIntegers(keybearer._wordlist.length, length);
    for (let i = 0; i < length; i++) {
      pwd[i] = keybearer._wordlist[selections[i]];
    }

    // Ensure no bad n-grams
    const joined = pwd.join(' ');
    for (let i = 0; i < keybearer._badngramlist.length; i++) {
      if (joined.indexOf(keybearer._badngramlist[i]) !== -1) {
        return keybearer.makePassword(length);
      }
    }
    return joined;
  },

  /**
   * Generate array of random integers
   */
  randto: function(end, num) {
    return noble.randomIntegers(end, num);
  },

  /**
   * Normalize string (trim and collapse whitespace)
   */
  normalizeString: function(string) {
    return string.replace(/\s+/g, ' ').replace(/(^\s|\s$)/g, '');
  },

  /**
   * Generate salt
   */
  makeSalt: function() {
    keybearer._salt = noble.getRandomBytes(keybearer.salt_length);
  },

  /**
   * Derive key from password using PBKDF2-SHA256
   */
  makeKeyFromPassword: function(password) {
    // For legacy decryption, use SJCL if available and salt is bitArray
    if (typeof sjcl !== 'undefined' && Array.isArray(keybearer._salt)) {
      return legacy.deriveKeyLegacy(
        password,
        keybearer._salt,
        keybearer.pbkdf2_iterations,
        keybearer.aes_key_strength * 8 // Convert bytes to bits
      );
    }
    // For v2, use Noble
    return noble.deriveKeyFromPassword(
      password,
      keybearer._salt,
      keybearer.pbkdf2_iterations,
      keybearer.aes_key_strength
    );
  },

  /**
   * Generate all password combinations (n choose k)
   */
  makeCombinedPasswords: function(passwords, nToUnlock) {
    keybearer._nPasswords = passwords.length;
    keybearer._nToUnlock = nToUnlock;

    const combine = function(passwords, output, prefix, levels_left, start) {
      if (levels_left <= 0) {
        output.push(prefix.replace(/ /, ''));
      } else {
        for (let i = start; i < passwords.length; i++) {
          combine(passwords, output, [prefix, passwords[i]].join(' '), levels_left - 1, i + 1);
        }
      }
    };

    const combined = [];
    for (let i = 0; i < passwords.length; i++) {
      passwords[i] = keybearer.normalizeString(passwords[i]);
    }
    passwords.sort();
    combine(passwords, combined, null, nToUnlock, 0);
    return combined;
  },

  /**
   * Generate all key combinations with progress callback
   */
  makeKeyCombinations: function(passwords, nToUnlock, callback) {
    callback = callback || function(x) {};
    keybearer._keys = [];
    const combinations = keybearer.makeCombinedPasswords(passwords, nToUnlock);
    callback(0);

    for (let i = 0; i < combinations.length; i++) {
      keybearer._keys.push(keybearer.makeKeyFromPassword(combinations[i]));
      callback((i + 1) / combinations.length);
    }
    callback(1);
    return keybearer._keys;
  },

  /**
   * Generate master encryption key
   */
  makeAESKey: function() {
    keybearer._master = noble.getRandomBytes(keybearer.aes_key_strength);
  },

  /**
   * Create metadata object for encrypted file
   */
  makeMetadataObject: function() {
    const nonce = noble.getRandomBytes(12); // ChaCha20-Poly1305 uses 96-bit nonce
    return {
      adata: '',
      iter: keybearer.pbkdf2_iterations,
      mode: keybearer.aes_cipher_mode,
      cipher: 'chacha20',
      ts: 128, // tag size (bits)
      ks: keybearer.aes_key_strength * 8, // key size in bits
      salt: keybearer._salt,
      iv: nonce,
      v: 2, // Version 2
      ct: null,
      fn: keybearer._filename,
      ft: keybearer._filetype,
      nkeys: keybearer._nPasswords,
      nunlock: keybearer._nToUnlock
    };
  },

  /**
   * Decrypt master key from encrypted key list
   */
  decryptKeys: function() {
    // Check if legacy format
    if (typeof sjcl !== 'undefined' && legacy.isLegacyFormat(keybearer._cipherobj)) {
      return keybearer.decryptKeysLegacy();
    }

    // V2 decryption using Noble
    let success = false;
    for (let i = 0; i < keybearer._keys.length; i++) {
      for (let j = 0; j < keybearer._cipherobj.keys.length; j++) {
        try {
          const keyiv = keybearer._cipherobj.keys[j];
          keybearer._master = noble.decryptChaCha20Poly1305(
            keybearer._keys[i],
            keyiv.key,
            keyiv.iv,
            new Uint8Array(0)
          );
          success = true;
          break;
        } catch (err) {
          // This wasn't the right key, continue
        }
      }
      if (success) break;
    }
    return success;
  },

  /**
   * Decrypt master key using legacy SJCL (v1)
   */
  decryptKeysLegacy: function() {
    let success = false;
    for (let i = 0; i < keybearer._keys.length; i++) {
      for (let j = 0; j < keybearer._cipherobj.keys.length; j++) {
        const master = legacy.decryptKeyLegacy(
          keybearer._cipherobj,
          keybearer._keys[i],
          keybearer._cipherobj.keys[j]
        );
        if (master) {
          keybearer._master = master;
          success = true;
          break;
        }
      }
      if (success) break;
    }
    return success;
  },

  /**
   * Decrypt ciphertext
   */
  decryptCiphertext: function() {
    // Check if legacy format
    if (typeof sjcl !== 'undefined' && legacy.isLegacyFormat(keybearer._cipherobj)) {
      keybearer._plaintext = legacy.decryptLegacy(keybearer._cipherobj, keybearer._master);
    } else {
      // V2 decryption using Noble
      keybearer._plaintext = noble.decryptChaCha20Poly1305(
        keybearer._master,
        keybearer._cipherobj.ct,
        keybearer._cipherobj.iv,
        new Uint8Array(0)
      );
    }
  },

  /**
   * Complete encryption process with passwords
   */
  encryptWithPasswords: function(passwords, nUnlock, callback) {
    keybearer.makeKeyCombinations(passwords, nUnlock, callback);
    keybearer.makeAESKey();
    return keybearer.encryptPlaintext(keybearer._plaintext);
  },

  /**
   * Encrypt plaintext (always uses v2 Noble crypto)
   */
  encryptPlaintext: function(pt) {
    const p = keybearer.makeMetadataObject();
    const ptxt = pt || keybearer._plaintext;
    keybearer._lastMetadata = p;

    // Encrypt file content with master key
    const result = noble.encryptChaCha20Poly1305(keybearer._master, ptxt, p.iv, new Uint8Array(0));
    p.ct = result.ciphertext;
    p.iv = result.nonce;

    keybearer._cipherobj = p;
    keybearer.augmentWithEncryptedKeys(keybearer._cipherobj);
    return keybearer.getCipherJSON();
  },

  /**
   * Encrypt master key with all password combinations
   */
  augmentWithEncryptedKeys: function(obj) {
    const encKeys = [];
    for (let i = 0; i < keybearer._keys.length; i++) {
      const nonce = noble.getRandomBytes(12);
      const result = noble.encryptChaCha20Poly1305(
        keybearer._keys[i],
        keybearer._master,
        nonce,
        new Uint8Array(0)
      );
      encKeys.push({ iv: result.nonce, key: result.ciphertext });
    }
    obj.keys = encKeys;
    keybearer.shuffle(obj.keys);
  },

  /**
   * Fisher-Yates shuffle
   */
  shuffle: function(arr) {
    let i = arr.length;
    if (i === 0) return false;
    while (--i) {
      const j = keybearer.randto(i + 1, 1)[0];
      const tempi = arr[i];
      arr[i] = arr[j];
      arr[j] = tempi;
    }
    return arr;
  },

  /**
   * Set plaintext from ArrayBuffer
   */
  setPlaintext: function(data, fn, ft) {
    keybearer._plaintext = new Uint8Array(data);
    if (fn) keybearer.setFileName(fn);
    if (ft) keybearer.setFileType(ft);
    return true;
  },

  setFileName: function(fname) {
    keybearer._filename = fname;
    return keybearer._filename;
  },

  setFileType: function(ftype) {
    keybearer._filetype = ftype;
    return keybearer._filetype;
  },

  setPBKDF2Iterations: function(num) {
    keybearer.pbkdf2_iterations = num;
  },

  setWordlist: function(wl) {
    keybearer._wordlist = wl;
  },

  setBadNGramList: function(wl) {
    keybearer._badngramlist = wl;
  },

  getFileName: function() {
    return keybearer._filename;
  },

  getFileType: function() {
    return keybearer._filetype;
  },

  getNPasswords: function() {
    return keybearer._nPasswords;
  },

  getNPasswordsDecrypt: function() {
    return keybearer._cipherobj.nkeys;
  },

  getNumToUnlock: function() {
    return keybearer._nToUnlock;
  },

  getWordlist: function() {
    return keybearer._wordlist;
  },

  getBadNGramList: function() {
    return keybearer._badngramlist;
  },

  resetKeys: function() {
    keybearer._keys = [];
  },

  isPlaintextReady: function() {
    return keybearer._plaintext !== null;
  },

  isCipherObjectReady: function() {
    return keybearer._cipherobj !== null;
  },

  /**
   * Parse encrypted JSON and prepare for decryption
   */
  setCipherJSON: function(data) {
    const obj = JSON.parse(data);

    // Detect version
    const isLegacy = legacy.isLegacyFormat(obj);

    if (isLegacy) {
      // V1 format - keep SJCL bitArrays
      obj.salt = sjcl.codec.base64.toBits(obj.salt);
      obj.iv = sjcl.codec.base64.toBits(obj.iv);
      obj.ct = sjcl.codec.base64.toBits(obj.ct);
      for (let i = 0; i < obj.keys.length; i++) {
        obj.keys[i].iv = sjcl.codec.base64.toBits(obj.keys[i].iv);
        obj.keys[i].key = sjcl.codec.base64.toBits(obj.keys[i].key);
      }
    } else {
      // V2 format - use Uint8Array
      obj.salt = noble.decodeBase64(obj.salt);
      obj.iv = noble.decodeBase64(obj.iv);
      obj.ct = noble.decodeBase64(obj.ct);
      for (let i = 0; i < obj.keys.length; i++) {
        obj.keys[i].iv = noble.decodeBase64(obj.keys[i].iv);
        obj.keys[i].key = noble.decodeBase64(obj.keys[i].key);
      }
    }

    // Set keybearer fields
    keybearer._salt = obj.salt;
    keybearer._nPasswords = obj.nkeys;
    keybearer._nToUnlock = obj.nunlock;
    keybearer.setFileName(obj.fn);
    keybearer.setFileType(obj.ft);
    keybearer.setPBKDF2Iterations(obj.iter);
    keybearer._cipherobj = obj;
  },

  /**
   * Export encrypted object as JSON
   */
  getCipherJSON: function() {
    // Create a shallow copy and convert Uint8Arrays to base64
    const obj = {
      v: keybearer._cipherobj.v,
      mode: keybearer._cipherobj.mode,
      cipher: keybearer._cipherobj.cipher,
      ts: keybearer._cipherobj.ts,
      ks: keybearer._cipherobj.ks,
      iter: keybearer._cipherobj.iter,
      adata: keybearer._cipherobj.adata,
      fn: keybearer._cipherobj.fn,
      ft: keybearer._cipherobj.ft,
      nkeys: keybearer._cipherobj.nkeys,
      nunlock: keybearer._cipherobj.nunlock,
      salt: noble.encodeBase64(keybearer._cipherobj.salt),
      iv: noble.encodeBase64(keybearer._cipherobj.iv),
      ct: noble.encodeBase64(keybearer._cipherobj.ct),
      keys: []
    };

    // Base64 encode all key entries
    for (let i = 0; i < keybearer._cipherobj.keys.length; i++) {
      obj.keys.push({
        iv: noble.encodeBase64(keybearer._cipherobj.keys[i].iv),
        key: noble.encodeBase64(keybearer._cipherobj.keys[i].key)
      });
    }

    return JSON.stringify(obj);
  },

  /**
   * Get plaintext as Uint8Array
   */
  getPlaintext: function() {
    return keybearer._plaintext;
  },

  /**
   * Augment object with properties from another
   */
  augment: function(toAug, augger) {
    for (const k in augger) {
      if (augger.hasOwnProperty(k)) {
        toAug[k] = augger[k];
      }
    }
  }
};

// Export for ES modules
export default keybearer;

// Set global for browser (IIFE bundle will execute this)
if (typeof window !== 'undefined') {
  window.keybearer = keybearer;
}
