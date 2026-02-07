# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Keybearer is a client-side JavaScript cryptographic tool that implements Shamir's Secret Sharing scheme for file encryption. It allows encrypting a file with multiple independent passwords where only a subset of those passwords is required for decryption.

**Example use case**: Encrypt a file with 5 passwords, requiring any 3 of them to decrypt.

## Architecture

### Core Components

**src/kb.js** - Core cryptography library (v2)
- Implements the main `keybearer` object with all encryption/decryption logic
- Uses Noble crypto for new encryptions (ChaCha20-Poly1305), SJCL for legacy decryption only
- Key functions:
  - Password combination generation (n-choose-k algorithm)
  - PBKDF2 key derivation via `@noble/hashes` (configurable iterations)
  - ChaCha20-Poly1305 encryption (v2), AES-CCM/OCB2 decryption (v1 backward compat)
  - Master key generation and multi-password encryption
  - RNG via `crypto.getRandomValues()` (no entropy collection needed)

**src/kb-noble.js** - Noble crypto wrappers
- ChaCha20-Poly1305 encrypt/decrypt, PBKDF2-SHA256, base64 codec, secure RNG

**src/kb-legacy.js** - SJCL backward compatibility
- Minimal wrapper for decrypting v1 files (AES-CCM/OCB2 only)

**src/kb-worker.js** - Web Worker entry point
- Delegates calls to kb.js for non-blocking encryption

**example/js/kbpage-v2.js** - UI controller (v2)
- Simplified from v1: no entropy collection, cleaner init
- Manages Web Worker for encryption operations
- File reading/writing via FileAPI and Blob API

**example/kb-v2.html** - User interface (v2)
- Bootstrap-based responsive UI, no entropy progress bar
- Dual-panel design: encryption (left) and decryption (right)

**Legacy files** (v1, kept for reference):
- `kb.js` (original), `example/js/kbpage.js`, `example/kb.html`

### Cryptographic Flow

**Encryption**:
1. Generate salt from RNG
2. Create all password combinations (n-choose-k)
3. Derive keys from each combination using PBKDF2
4. Generate random master AES key
5. Encrypt file with master key
6. Encrypt master key with each derived key combination
7. Shuffle encrypted keys and package with metadata

**Decryption**:
1. Load encrypted file and parse metadata
2. User provides m passwords (subset of n original)
3. Generate key from password combination
4. Try decrypting master key from encrypted key list
5. Decrypt file contents with recovered master key

### Dependencies

- **@noble/ciphers** / **@noble/hashes**: Audited modern crypto (ChaCha20-Poly1305, PBKDF2-SHA256)
- **SJCL** (git submodule at `sjcl/`): **[DEPRECATED]** Kept only for v1 file decryption (AES-CCM/OCB2)
- **esbuild**: Bundles ESM sources into `dist/kb.js` (IIFE)
- **jQuery 1.8.2**: DOM manipulation and AJAX
- **Bootstrap 2.x**: UI components and responsive layout

## Key Technical Details

### Web Worker Usage
- Encryption runs in a Web Worker (`dist/kb-worker.js`) to avoid blocking the UI
- Decryption runs synchronously in main thread

### Browser Compatibility Issues
- Requires FileAPI, Blob, and `crypto.getRandomValues()` support (all modern browsers)

### Password Normalization
- Passwords are trimmed and internal whitespace collapsed to single spaces
- All combinations are sorted before key derivation

### Security Parameters (configurable in UI)
- **PBKDF2 iterations**: 2,000 (Weak) to 200,000 (Paranoid), default 50,000
- **Key strength**: 256-bit
- **Salt length**: 16 bytes (128 bits)
- **Cipher mode**: ChaCha20-Poly1305 (v2), CCM/OCB2 (v1 legacy)

### File Format
Encrypted files are JSON with base64-encoded fields:
- `salt`, `iv`, `ct` (ciphertext)
- `keys[]` array with encrypted master keys and IVs
- `fn` (filename) and `ft` (MIME type) stored in plaintext
- Metadata: `v` (version), `iter`, `mode`, `cipher`, `ks`, `ts`, `nkeys`, `nunlock`
- v2 files have `"v": 2, "mode": "chacha20poly1305"`; v1 files have `"mode": "ccm"` or `"ocb2"`

## Development

### Building
```bash
npm install
npm run build    # produces dist/kb.js and dist/kb-worker.js
```

### Running the Example
Serve via HTTP (needed for Web Workers):
```bash
python -m http.server 8000
# v2: http://localhost:8000/example/kb-v2.html
# v1: http://localhost:8000/example/kb.html
```

### Testing
```bash
node test/test-e2e.mjs                      # Node.js end-to-end test
# Open test/test-suite.html via HTTP server  # Browser test suite
```

### Git Submodules
SJCL is included as a git submodule (needed for v1 decryption):
```bash
git submodule update --init
```

## Important Notes

- v2 crypto uses audited Noble libraries; SJCL is retained only for v1 backward compatibility
- File names and MIME types are stored in **unauthenticated plaintext** in the encrypted output
- Random password generation uses `example/wordlists/wordlist.txt` (50,000 common English words)
- Bad n-gram filtering prevents offensive word combinations in generated passwords
