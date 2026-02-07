# Keybearer

Keybearer uses several independent passwords to encrypt a file and later requires a subset of those passwords to decrypt it.

All operation are performed in client-side Javascript.

**Note**: This is a fork of [msolomon/keybearer](https://github.com/msolomon/keybearer) with v2 enhancements. See the original [live version](http://michael-solomon.net/keybearer/) from the parent repo.

## Example

For example, Magician Mike uses Keybearer to encrypt the password to his laptop containing his secret repertoire of tricks. He gives the 3 passcodes he used to his estranged siblings Alice, Bob, and Charlie, on the condition that at least 2 of them reunite on his death to gaze on the majesty of his secrets.

After Magician Mike is tragically sawed in half by his careless assistant, Alice and Bob meet to decrypt Mike's files using their passcodes. They are reunited through their Keybearer experience, while Charlie maintains his grudge and burns his passcode with fire.

## v2

v2 replaces the deprecated SJCL library with [Noble](https://paulmillr.com/noble/) cryptography (`@noble/ciphers`, `@noble/hashes`). New encryptions use ChaCha20-Poly1305. Existing v1 files (AES-CCM/OCB2) can still be decrypted. SJCL is retained solely for backward compatibility.

Other changes:
* No more mouse movement for entropy - uses `crypto.getRandomValues()`
* Bundled with esbuild (`npm run build` produces `dist/kb.js`)
* v2 UI at `example/kb-v2.html`

## Known issues
* Web workers and the File Reader API must be supported by the browser for Keybearer to function (all modern browsers support these)
* The code organization could be improved - the UI controller (kbpage-v2.js) is tightly coupled with the DOM, though v2 has simplified it significantly

## Notes on operation
* Whitespace is stripped from each end of each password
* Whitespace inside passwords is collapsed down to a single space
* Encryption is done in a web worker (v2 uses `dist/kb-worker.js`)
* Decryption is done in the main thread
* Randomized passwords are generated from a list of ~44,000 common English words
* v2 uses `crypto.getRandomValues()` for all random number generation (no entropy collection required)
