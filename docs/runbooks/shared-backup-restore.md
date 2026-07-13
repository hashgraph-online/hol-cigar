# Shared backup and restore runbook

## Backup

Quiesce irreversible migrations and record the global repository revision. Use a dedicated
`NOSUPERUSER`, data-read-only PostgreSQL backup/GC role with `BYPASSRLS` and explicit `EXECUTE` on
`pg_control_system()` and `cigar_gc_lock_repository_revision()`, plus a separate writable backup
object prefix; runtime and migrator identities are intentionally insufficient. The security-definer
GC guard has a fixed system-only search path and grants no table mutation authority. Open one
read-only repeatable-read transaction, derive the source
identity from the cluster system identifier and database OID, enumerate the authoritative tenant set,
call `pg_export_snapshot()`, and keep that transaction open while
`pg_dump --format=custom --snapshot <token>` completes. Copy the metadata-reachable ciphertext set
from the live object prefix into an entirely empty backup prefix during the same callback. The copy
uses an incomplete marker, rolls back partial writes, and must end with an exact whole-prefix listing.
The exporter disables only the idle-in-transaction timeout and enforces the configured bounded backup
transaction timeout; ordinary runtime transaction timeouts remain unchanged.

The v2 signed CIGAR inventory binds the archive format, exact byte size and checksum, exported and
transaction snapshot digests, derived source database identity, complete revision history, every
migration row and checksum, the authoritative tenant set, ordered protected-state/projection/worker
roots, every retained ciphertext checksum and historical wrapping-key reference, and the verified
live-to-backup object receipt. Keep signing, wrapping, and database decryption keys in the approved
key service; the archive stores references, never key material. Separately retain a PostgreSQL
physical backup/WAL recovery point. Qualify it with
`pg_basebackup --wal-method=stream --manifest-checksums=SHA256` and `pg_verifybackup`; replication
promotion/rejoin exercises are the restore proof for that physical path.

Shared physical garbage collection uses the same PostgreSQL authority only to acquire the
security-definer revision guard after its exclusive backup/GC advisory lock. It scans every retained
tenant state before issuing an opaque, store-owned deletion capability to the object adapter. Give a
separate GC object identity delete authority over live object prefixes; never give the backup-copy
identity that authority. A backup holds the shared advisory lock through its verified object copy, so
GC waits until the exported snapshot closes.

Run streaming offline archive verification before creating a destination database. The verifier
returns an opaque archive capability; stream that same capability to `pg_restore` and require its
second consumption digest before activation. Size overflow, truncation, extension, mutation, or
checksum drift is a stop condition. Validate the cryptographic signature
before invoking current signer/key trust policy. Historical signatures made before a key's
retirement remain cryptographically verifiable, while a currently revoked principal/key is rejected
by policy. Verify every database/object checksum, inventory root, migration row, and semantic root.
Store the content-free verification receipt separately from the backup bytes.

## Restore drill

1. Allocate a new empty database using `TEMPLATE template0` and a new empty object prefix whose
   whole logical namespace is empty. Hash their content-free identities. Refuse an in-place,
   source-equal, or nonempty destination.
2. Stream the opaque verified archive directly into `pg_restore --exit-on-error`; do not reopen a
   pathname between verification and restore. Restore only the signed backup object prefix into a
   third prefix; never copy from the mutable live runtime prefix. Verify every protected ciphertext,
   historical key reference, AEAD decryption, and the exact final namespace.
3. Run packaged migrations only if the target image explicitly supports the restored schema. Because
   `pg_restore --no-acl` intentionally omits source-cluster grants, reapply the target privilege
   policy: revoke PUBLIC execution of `cigar_gc_lock_repository_revision()` and grant it only to the
   dedicated backup/GC role before any repository process connects.
4. Run database integrity, forced-RLS, migration checksum, object existence/decryption samples,
   journal-chain, semantic-root, outbox, unknown-effect, and replay-completeness checks.
5. Rebuild disposable indexes, then wait for their watermarks. Do not advance readiness while an
   index claims a sequence newer than committed metadata.
6. Start one isolated daemon against the restored namespace. Run local/shared semantic differential
   and a no-egress observational replay. Do not dispatch retained effects.
7. Run activation verification with the dedicated backup role, not the runtime role. It must derive
   the target cluster/database identity, prove it differs from the source, re-enumerate the complete
   tenant set, and match complete revision, state-history, projection, wakeup, claim, object, and key
   roots. Require both a database restore receipt and an object restore receipt. Their source identities,
   archive checksum/size/format, revision, migration root, tenant root, object count/bytes/root, and
   distinct destination identities must match the signed inventory. Cut over through a new endpoint
   only after restored-state checks and receipts match. Preserve the
   old namespace until the rollback window expires; deletion still requires retention, legal-hold,
   and completed-backup policy checks.

Record recovery point, recovery duration, object count/bytes, schema sequence, semantic roots,
verification receipt, rebuilt index watermarks, and every deviation. Never include protected
content, credentials, raw paths, prompts, or tenant/user identifiers in the drill report.
