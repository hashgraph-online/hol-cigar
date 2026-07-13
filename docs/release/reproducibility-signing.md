# Reproducibility, SBOM, signing, and provenance

Release builders pin compilers, package managers, SDKs, generators, lock files, and builder images.
They set `SOURCE_DATE_EPOCH`, UTC, a fixed locale, remapped source paths, deterministic ordering,
timestamps, owners, and modes. Two isolated empty-cache workers build from the signed source archive
and compare unsigned payload SHA-256 values. Platform signing may wrap that payload but must prove the
envelope contains it.

SPDX and CycloneDX SBOMs are generated from final artifacts and include language dependencies, native
libraries, extension modules, plugin executables, installer contents, and OCI layers. License
expressions that are missing or outside policy require review. The checksum manifest, artifacts,
SBOMs, plugin manifest, conformance result, benchmark result, provenance, and release evidence are
signed with an approved isolated Ed25519 identity. Each domain-separated envelope signs its purpose,
signer principal, signing and optional expiry times, payload name, byte length, and digest along with
the payload identity; envelope metadata cannot be repurposed without invalidating the signature.

Offline verification consumes a separately distributed
[`cigar.release-trust-policy.v1`](../../packaging/schemas/release-trust-policy.v1.schema.json) document
and its adjacent public keys. The policy binds each key ID to a principal, allowed purposes,
activation time, and active, retired, or revoked status. A retired key may validate a signature made
while it was active; a revoked key is rejected. The signed envelope shape is published as
[`cigar.signature-envelope.v1`](../../packaging/schemas/signature-envelope.v1.schema.json).
Production private keys never enter the workspace or distribution.

Provenance binds source archive, revision, workflow, builder identity, lock digests, exact commands,
artifacts, and evidence. The generator requires every identity explicitly; it records network access
as `disabled` only when the isolated runner supplies its enforced no-egress marker. Local development
uses `unspecified` and cannot satisfy the production verifier. Local ephemeral-key tests prove
corrupted, repurposed, expired, and swapped-payload signatures
fail, but do not substitute for production signing or transparency/notarization receipts.
