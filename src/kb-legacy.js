/**
 * kb-legacy.js - Minimal SJCL wrapper for legacy CCM/OCB2 decryption
 *
 * This module provides ONLY the decryption functionality needed for backward compatibility
 * with existing .kbr.json files that use AES-CCM or AES-OCB2.
 *
 * IMPORTANT: This code is NOT used for new encryptions - only for decrypting legacy files.
 */

/**
 * Convert SJCL bitArray to Uint8Array
 */
export function bitArrayToBytes(bitArray) {
  const out = [];
  const bl = sjcl.bitArray.bitLength(bitArray);
  let tmp;

  for (let i = 0; i < bl / 8; i++) {
    if ((i & 3) === 0) {
      tmp = bitArray[i / 4];
    }
    out.push(tmp >>> 24);
    tmp <<= 8;
  }

  return new Uint8Array(out);
}

/**
 * Convert Uint8Array to SJCL bitArray
 */
export function bytesToBitArray(bytes) {
  const out = [];
  let tmp = 0;

  for (let i = 0; i < bytes.length; i++) {
    tmp = (tmp << 8) | bytes[i];
    if ((i & 3) === 3) {
      out.push(tmp);
      tmp = 0;
    }
  }

  if (bytes.length & 3) {
    out.push(sjcl.bitArray.partial(8 * (bytes.length & 3), tmp));
  }

  return out;
}

/**
 * Decrypt using legacy SJCL (CCM or OCB2 mode)
 *
 * @param {Object} cipherobj - Legacy cipher object with SJCL bitArrays
 * @param {Array} key - SJCL bitArray key
 * @returns {Uint8Array} - Decrypted plaintext as Uint8Array
 */
export function decryptLegacy(cipherobj, key) {
  // Use SJCL for legacy decryption
  const prp = new sjcl.cipher[cipherobj.cipher](key);
  const plaintext = sjcl.mode[cipherobj.mode].decrypt(
    prp,
    cipherobj.ct,
    cipherobj.iv,
    cipherobj.adata,
    cipherobj.ts
  );

  // Convert bitArray result to Uint8Array
  return bitArrayToBytes(plaintext);
}

/**
 * Decrypt master key using legacy SJCL
 *
 * @param {Object} cipherobj - Legacy cipher object
 * @param {Array} key - SJCL bitArray key
 * @param {Object} keyiv - {key: bitArray, iv: bitArray}
 * @returns {Array|null} - Decrypted master key as SJCL bitArray, or null if failed
 */
export function decryptKeyLegacy(cipherobj, key, keyiv) {
  try {
    const prp = new sjcl.cipher[cipherobj.cipher](key);
    const master = sjcl.mode[cipherobj.mode].decrypt(
      prp,
      keyiv.key,
      keyiv.iv,
      cipherobj.adata,
      cipherobj.ts
    );
    return master;
  } catch (err) {
    return null;
  }
}

/**
 * Derive key using legacy SJCL PBKDF2
 * (kept for consistency with legacy files, though Noble's PBKDF2 should produce same output)
 *
 * @param {string} password - Password string
 * @param {Array} salt - SJCL bitArray salt
 * @param {number} iterations - PBKDF2 iteration count
 * @param {number} keyBits - Key length in bits
 * @returns {Array} - SJCL bitArray key
 */
export function deriveKeyLegacy(password, salt, iterations, keyBits) {
  return sjcl.misc.pbkdf2(password, salt, iterations, keyBits);
}

/**
 * Check if cipher object is legacy format (v1 or missing version)
 */
export function isLegacyFormat(cipherobj) {
  // Legacy formats:
  // 1. No version field (original format)
  // 2. v: 1
  // 3. mode: 'ccm' or 'ocb2'
  return (
    !cipherobj.v ||
    cipherobj.v === 1 ||
    cipherobj.mode === 'ccm' ||
    cipherobj.mode === 'ocb2'
  );
}
