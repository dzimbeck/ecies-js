# ecies-js (standalone single file)

This repository provides one top-level implementation file: `./ecies-min.js`.

- Uses vendored, pinned `@noble/curves` and `@noble/hashes` files committed in this repository
- No package install from npm is required at runtime
- Works in browsers via ES modules and an import map when Web Crypto is available

## Browser usage

```html
<script type="importmap">
{
  "imports": {
    "@noble/curves/": "./node_modules/@noble/curves/esm/",
    "@noble/hashes/": "./node_modules/@noble/hashes/esm/"
  }
}
</script>
<script type="module">
  import { ECIES } from './ecies-min.js';
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

- `curve: 'secp256k1' | 'x25519'` (default `secp256k1`)
- `cipher: 'aes-256-gcm' | 'xchacha20'` (default `aes-256-gcm`)
- `compressed: boolean` (default `false`)
- `hkdfCompressed: boolean` (default `false`, secp256k1 only)
- `nonceLength: 12 | 16` for AES-GCM (default `16`)

## Ciphertext format

Hex-only transport:

- `secp256k1`: `ephemeralPublicKey(33/65) || nonce || tag || ciphertext`
- `x25519`: `ephemeralPublicKey(32) || nonce || tag || ciphertext`

The transport and HKDF input (`senderPoint || sharedPoint`) match `ecies/js`.

## Migration note

If you previously used older buggy XChaCha ciphertext encodings, do not assume compatibility. Re-encrypt with this format.

## Security and limitations

- ECIES encryption by itself does **not** authenticate sender identity.
- For authentication one could also hash and sign/verify messages in production.
- This implementation rejects unsupported curves/ciphers (for example `ed25519`).
- JavaScript/BigInt operations are not guaranteed constant-time.
- This repository does **not** claim this standalone port itself is audited.