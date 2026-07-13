# Blob corruption and authentication failure

## Preconditions

Treat a missing blob, digest mismatch, AEAD authentication failure, wrong wrapping-key reference, or
immutable-object overwrite as an integrity incident. Stop writes that could advance metadata past the
affected object set. Preserve the exact ciphertext and metadata; never retry by rewriting the same
final key or by substituting plaintext from a cache.

Capture only the blinded object identity, expected/observed digest, byte count, provider version,
key-reference digest, committed metadata revision, and content-free correlation ID. Do not place
ciphertext, plaintext, tenant IDs, paths, prompts, or credentials in the incident report.

## Recovery

Verify the journal and metadata roots first. Locate an independently verified backup whose signed
inventory contains the same object identity, ciphertext digest, wrapping-key reference, and source
revision. Restore into staging, verify byte length and digest while streaming, authenticate/decrypt
under the historical key, and publish only through the store's conditional immutable-object repair
operation. Re-read and authenticate from the final location before reopening readiness.

If no verified copy exists, quarantine the owning records and keep dependent compilation, replay, or
effect operations unavailable. Do not fabricate a tombstone or silently omit mandatory content.

## Stop conditions and evidence

Stop on metadata-root disagreement, backup signature failure, missing historical key, a second object
with the same identity but different bytes, conditional-write failure, or any repair that would alter
the semantic root. Escalate to [local storage recovery](../runbooks/local-storage-recovery.md) or the
[shared restore drill](../runbooks/shared-backup-restore.md). Record before/after roots, backup and
repair receipt digests, exact affected counts, and post-repair integrity/replay results.
