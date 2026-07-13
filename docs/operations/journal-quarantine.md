# Journal quarantine

## Preconditions

Close readiness and stop new effect dispatch for the affected scope. Preserve the database, WAL,
revision anchor, object bytes, and content-free diagnostics. Verify the latest signed backup before
attempting recovery.

## Exercise

1. Run deep integrity verification and identify the first invalid chain link by opaque event ID.
2. Quarantine corrupt or swapped ciphertext without deleting its metadata reference.
3. Restore the exact encrypted object from a verified backup into a new staging location.
4. Re-run AEAD authentication, chain verification, semantic-root checks, projection rebuild, and
   replay completeness before atomically restoring service.
5. If durable journal rows themselves differ, restore into a new database namespace and cut over;
   never rewrite history in place.

## Stop conditions

Stop if the signer, key reference, backup root, revision, tenant scope, or plaintext authentication
cannot be proven. Evidence may include digests, counts, revision, first-invalid sequence, and outcome,
but never content, credentials, raw paths, or tenant identifiers.
