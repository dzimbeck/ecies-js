# Provenance and transformation notes

## Upstream references inspected

- ecies/js repository: https://github.com/ecies/js
- Reference commit reviewed: `9e01b9789a5f92feb412f433b828a3689efa8473`
- `package.json` at that commit reports version `0.5.1`
- Declared primitive dependencies at that commit:
  - `@ecies/ciphers` `^0.2.6`
  - `@noble/ciphers` `^1.3.0`
  - `@noble/curves` `^1.9.7`
  - `@noble/hashes` `^1.8.0`

## This repository's approach

The top-level `ecies-min.js` wrapper now imports vendored, pinned copies of `@noble/curves`
and `@noble/hashes` that are committed in this repository under `./node_modules/@noble/`.
The remaining transport, framing, Web Crypto AES-GCM, and XChaCha20-Poly1305 glue stay local.

## Important audit-scope caveat

Upstream projects and dependencies may have independent audits, but this standalone consolidation
introduces transformations and integration changes that require independent review. This repository
therefore does **not** claim audit equivalence or production-readiness by inheritance.
