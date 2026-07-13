# Key rotation

## Preconditions

Take and verify a signed backup. Inventory active and retired signing, wrapping, cursor, and operator
keys by opaque identifier; confirm the authority and tenant scope without recording key bytes. Stop
dispatch if authority state, backup, or key-service health is uncertain.

## Exercise

1. Add the new key as active for new writes while retaining every historical decrypt/verify key.
2. Write and read a new encrypted blob, sign and verify a receipt, and restart one replica.
3. Read samples created under every retained key and verify replay plus backup restore.
4. Retire the old key for new writes. Do not revoke it retroactively or delete it.
5. Rotate replicas one at a time and confirm identical key maps and readiness.

## Stop conditions and evidence

Stop on unknown key references, replica disagreement, authentication failure, signature-time policy
drift, or backup verification failure. Record opaque key IDs, transition state, sample counts,
semantic roots, and readiness—not plaintext, credentials, tenant identities, or paths. Destruction is
a separate retention/legal-hold operation and is forbidden while any live or retained object refers
to the key.
