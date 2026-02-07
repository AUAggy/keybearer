/**
 * kb-noble.js - Noble cryptography implementations for Keybearer v2
 *
 * This module provides modern cryptographic primitives using @noble/ciphers and @noble/hashes
 * to replace the deprecated SJCL library.
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Generate cryptographically secure random bytes using Web Crypto API
 * Replaces: sjcl.random.randomWords(n)
 */
export function getRandomBytes(count) {
  const bytes = new Uint8Array(count);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate random words (32-bit integers) for compatibility
 * Used for IV generation and similar purposes
 */
export function getRandomWords(count) {
  const bytes = getRandomBytes(count * 4);
  const words = new Uint32Array(bytes.buffer);
  return Array.from(words);
}

/**
 * Derive encryption key from password using PBKDF2-SHA256
 * Replaces: sjcl.misc.pbkdf2()
 *
 * @param {string} password - Password string
 * @param {Uint8Array} salt - Salt bytes
 * @param {number} iterations - PBKDF2 iteration count
 * @param {number} keyLength - Key length in bytes (default 32 for 256-bit)
 * @returns {Uint8Array} - Derived key
 */
export function deriveKeyFromPassword(password, salt, iterations, keyLength = 32) {
  const passwordBytes = new TextEncoder().encode(password);
  return pbkdf2(sha256, passwordBytes, salt, {
    c: iterations,
    dkLen: keyLength
  });
}

/**
 * Encrypt plaintext using ChaCha20-Poly1305
 * Replaces: sjcl.mode.ccm.encrypt() and sjcl.mode.ocb2.encrypt()
 *
 * @param {Uint8Array} key - 256-bit encryption key
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} nonce - 96-bit (12-byte) nonce (optional, generated if not provided)
 * @param {Uint8Array} aad - Additional authenticated data (optional)
 * @returns {Object} - {ciphertext: Uint8Array, nonce: Uint8Array}
 */
export function encryptChaCha20Poly1305(key, plaintext, nonce = null, aad = new Uint8Array(0)) {
  if (!nonce) {
    nonce = getRandomBytes(12); // ChaCha20-Poly1305 uses 96-bit nonce
  }

  // AAD is passed to constructor in Noble
  const cipher = chacha20poly1305(key, nonce, aad);
  // ChaCha20-Poly1305 adds 16-byte authentication tag
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

/**
 * Decrypt ciphertext using ChaCha20-Poly1305
 *
 * @param {Uint8Array} key - 256-bit decryption key
 * @param {Uint8Array} ciphertext - Data to decrypt (includes auth tag)
 * @param {Uint8Array} nonce - 96-bit (12-byte) nonce
 * @param {Uint8Array} aad - Additional authenticated data (optional)
 * @returns {Uint8Array} - Decrypted plaintext
 * @throws {Error} - If authentication fails
 */
export function decryptChaCha20Poly1305(key, ciphertext, nonce, aad = new Uint8Array(0)) {
  // AAD is passed to constructor in Noble
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ciphertext);
}

/**
 * Encode Uint8Array to base64 string
 * Replaces: sjcl.codec.base64.fromBits()
 */
export function encodeBase64(uint8array) {
  const binaryString = Array.from(uint8array, byte => String.fromCharCode(byte)).join('');
  return btoa(binaryString);
}

/**
 * Decode base64 string to Uint8Array
 * Replaces: sjcl.codec.base64.toBits()
 */
export function decodeBase64(base64str) {
  const binaryString = atob(base64str);
  return Uint8Array.from(binaryString, char => char.charCodeAt(0));
}

/**
 * Generate random integers in range [0, max)
 * Replaces: keybearer.randto() but uses secure random source
 *
 * @param {number} max - Upper bound (exclusive)
 * @param {number} count - Number of random integers to generate
 * @returns {Array<number>} - Array of random integers
 */
export function randomIntegers(max, count) {
  const result = [];
  const randomBytes = getRandomBytes(count * 4); // 4 bytes per integer
  const randomInts = new Uint32Array(randomBytes.buffer);

  // Use rejection sampling to avoid modulo bias
  const maxValid = Math.floor(0xFFFFFFFF / max) * max;

  for (let i = 0; i < count; i++) {
    let value = randomInts[i];
    // Regenerate if value would cause bias
    while (value >= maxValid) {
      const newBytes = getRandomBytes(4);
      value = new Uint32Array(newBytes.buffer)[0];
    }
    result.push(value % max);
  }

  return result;
}
