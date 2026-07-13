# CIGAR release packaging

This directory is the machine-readable contract for CIGAR distribution artifacts. It deliberately
separates an artifact that can be assembled on a developer workstation from an artifact that is
qualified for publication.

- `artifact-matrix.v1.json` lists every release artifact and the platform evidence it requires.
- `local-archives.v1.json` defines deterministic, source-derived archives that can be reproduced
  without credentials or network access.
- `contracts/` contains fail-closed content and archive contracts.
- `schemas/` contains the release evidence, provenance, signature, and exercise schemas.
- `release-requirements.v1.json` defines the evidence categories that a candidate must satisfy.
- `licenses/` records the declared project license and third-party inventory policy.

The scripts in `scripts/release/` use only the Python standard library, except for detached Ed25519
signing and verification, which intentionally delegates key operations to OpenSSL. Production keys
are never generated or accepted from environment variables by these scripts.

Developer archives are not release approval. A candidate is releasable only when offline
verification succeeds against a committed source revision, trusted public keys, all required
platform evidence, and a complete `release-evidence.json`.

The v1 assembler and offline verifier pin the canonical SHA-256 of both
`release-requirements.v1.json` and `qualification-category-map.v1.json`. Changing a category,
threshold, prohibited status, required signature, universal exact-artifact rule, or
artifact-to-check mapping therefore fails closed and requires an intentional policy/schema version
update rather than a mutable release-time override. The map requires live-operation evidence and a
final artifact scan for every release artifact, plus installed version/Context-ABI consistency for
all four SDK distributions.
