# ecies-js (standalone single file)

ecies-js is a pure JavaScript implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES), offering simple encryption and decryption with Bitcoin- and Ethereum-style key pairs. Encrypt with a public key and decrypt with the matching private key—under the hood, a temporary key pair and elliptic-curve Diffie–Hellman derive a shared secret to encrypt the message.

This repository provides two plain vanilla JS files (no modules, no bundler, no runtime imports):

- `./ecies-min.js` — the readable ECIES implementation
- `./noble-crypto.js` — a vendored single-file bundle of the audited
  [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) v3.2.0,
  [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) v3.2.0 and
  [@noble/hashes](https://github.com/paulmillr/noble-hashes) v2.4.0 (`sha512` only), built with
  esbuild into one IIFE exposing `globalThis.nobleCrypto` (same style as `web3.min.js`)

When `noble-crypto.js` is loaded (script tag before `ecies-min.js`, or automatically via
`require` in Node), secp256k1 and ed25519 scalar multiplication use noble's hardened
constant-time algorithms. `ecies-min.js` still works standalone with its internal BigInt
fallback (secp256k1/x25519 only, not constant-time).

Try the live demo at: https://dzimbeck.github.io/ecies-js

## Browser usage

```html
<script src="./noble-crypto.js"></script>
<script src="./ecies-min.js"></script>
<script>
  (async () => {
    const receiver = ECIES.generateKeyPair({ curve: 'secp256k1' });
    const ciphertextHex = await ECIES.encrypt(receiver.publicKey, 'hello', {
      curve: 'secp256k1',
      cipher: 'aes-256-gcm',
      compressed: false,
      nonceLength: 16
    });
    const plaintext = await ECIES.decrypt(receiver.privateKey, ciphertextHex, {
      curve: 'secp256k1',
      cipher: 'aes-256-gcm',
      nonceLength: 16
    });
    console.log(plaintext);
  })();
</script>
```

## API

`ECIES` is a static class:

- `generateKeyPair(options={}) -> { publicKey, privateKey }` (hex, sync)
- `getPublicKey(privateKeyHex, options={}) -> publicKeyHex` (sync)
- `ecdh(privateKeyHex, publicKeyHex, options={}) -> {x,y,infinity} | {bytes}` (sync)
- `encrypt(receiverPublicKeyHex, data, options={}) -> Promise<string>` (hex transport)
- `decrypt(receiverPrivateKeyHex, ciphertextHex, options={}) -> Promise<string>`
- `decryptToBytes(receiverPrivateKeyHex, ciphertextHex, options={}) -> Promise<Uint8Array>`

Supported options:

- `curve: 'secp256k1' | 'x25519' | 'ed25519'` (default `secp256k1`; `ed25519` requires `noble-crypto.js`)
- `cipher: 'aes-256-gcm' | 'xchacha20'` (default `aes-256-gcm`)
- `compressed: boolean` (default `false`)
- `hkdfCompressed: boolean` (default `false`, secp256k1 only)
- `nonceLength: 12 | 16` for AES-GCM (default `16`)

## Ciphertext format

Hex-only transport:

- `secp256k1`: `ephemeralPublicKey(33/65) || nonce || tag || ciphertext`
- `x25519` / `ed25519`: `ephemeralPublicKey(32) || nonce || tag || ciphertext`

The transport and HKDF input (`senderPoint || sharedPoint`) match `ecies/js`.

## Migration note

If you previously used older buggy XChaCha ciphertext encodings, do not assume compatibility. Re-encrypt with this format.

## Security and limitations

- ECIES encryption by itself does **not** authenticate sender identity.
- For authentication one could also hash and sign/verify messages in production.
- This implementation rejects unsupported curves/ciphers (for example `p256`).
- With `noble-crypto.js` loaded, elliptic-curve scalar multiplication uses the audited noble
  libraries' constant-time hardened algorithms. Without it, the BigInt fallback is **not**
  constant-time and `ed25519` is unavailable.
- This repository does **not** claim this standalone port itself is audited.
