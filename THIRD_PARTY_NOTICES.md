# Third-party notices

This project is MIT-licensed and was prepared with API/behavior compatibility targets from:

- ecies/js (MIT): https://github.com/ecies/js

Cryptographic algorithm structures implemented in the standalone file are based on publicly
specified standards and commonly used open implementations of:

- secp256k1 (SEC1)
- X25519 (RFC 7748)
- HKDF-SHA256 (RFC 5869)
- AES-256-GCM (NIST SP 800-38D)
- ChaCha20/Poly1305 and XChaCha20 (RFC 8439 and XChaCha construction)

No claim is made that this standalone consolidated file is itself audited.

## Vendored libraries in noble-crypto.js

`noble-crypto.js` bundles the following MIT-licensed packages by Paul Miller
(license headers preserved in the file):

- `@noble/secp256k1` v3.2.0 — https://github.com/paulmillr/noble-secp256k1
- `@noble/ed25519` v3.2.0 — https://github.com/paulmillr/noble-ed25519
- `@noble/hashes` v2.4.0 (`sha512` only) — https://github.com/paulmillr/noble-hashes
