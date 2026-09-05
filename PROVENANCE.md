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

The deliverable here is a single readable `ecies-min.js` file with no runtime imports.
To satisfy that requirement, primitives needed by the `ECIES` API were consolidated into one file
using standard algorithm formulations (SEC1/RFC7748/RFC5869/RFC8439/XChaCha draft/SP 800-38D).

## Important audit-scope caveat

Upstream projects and dependencies may have independent audits, but this standalone consolidation
introduces transformations and integration changes that require independent review. This repository
therefore does **not** claim audit equivalence or production-readiness by inheritance.
