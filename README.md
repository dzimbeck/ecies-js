# ecies-js (standalone single file)

This repository provides one self-contained implementation file: `/home/runner/work/ecies-js/ecies-js/ecies-min.js`.

- No runtime imports
- No bundler/transpiler required
- Works as a plain browser script when Web Crypto is available

## Browser usage

```html
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

Supported options:

- `curve: 'secp256k1' | 'x25519'` (default `secp256k1`)
- `cipher: 'aes-256-gcm' | 'xchacha20'` (default `aes-256-gcm`)
- `compressed: boolean` (default `false`)
- `nonceLength: 12 | 16` for AES-GCM (default `16`)

## Ciphertext format

Hex-only transport:

- `secp256k1`: `ephemeralPublicKey(33/65) || nonce || encryptedPayload`
- `x25519`: `ephemeralPublicKey(32) || nonce || encryptedPayload`

`encryptedPayload` includes the AEAD tag for both AES-GCM and XChaCha20-Poly1305.

## Migration note

If you previously used older buggy XChaCha ciphertext encodings, do not assume compatibility. Re-encrypt with this format.

## Security and limitations

- ECIES encryption by itself does **not** authenticate sender identity.
- This implementation rejects unsupported curves/ciphers (for example `ed25519`).
- JavaScript/BigInt operations are not guaranteed constant-time.
- This repository does **not** claim this standalone port itself is audited.

## Development

```bash
npm test
```
