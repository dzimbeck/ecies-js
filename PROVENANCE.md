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

The deliverable here is a readable `ecies-min.js` file with no runtime imports.
To satisfy that requirement, primitives needed by the `ECIES` API were consolidated into one file
using standard algorithm formulations (SEC1/RFC7748/RFC5869/RFC8439/XChaCha draft/SP 800-38D).

## Vendored noble bundle

`noble-crypto.js` is a vendored single-file IIFE bundle (built with esbuild, unminified) of:

- `@noble/secp256k1` `3.2.0` (MIT) — https://github.com/paulmillr/noble-secp256k1
- `@noble/ed25519` `3.2.0` (MIT) — https://github.com/paulmillr/noble-ed25519
- `@noble/hashes` `2.4.0` (MIT, `sha512` module only) — https://github.com/paulmillr/noble-hashes

These are the same audited implementations (via `@noble/curves` lineage) that upstream `ecies/js`
depends on. When the bundle is present, `ecies-min.js` routes secp256k1 and ed25519 scalar
multiplication through noble's constant-time hardened algorithms, addressing the timing
side-channel of the internal variable-time BigInt fallback.

## Important audit-scope caveat

Upstream projects and dependencies may have independent audits, but this standalone consolidation
introduces transformations and integration changes that require independent review. This repository
therefore does **not** claim audit equivalence or production-readiness by inheritance.
