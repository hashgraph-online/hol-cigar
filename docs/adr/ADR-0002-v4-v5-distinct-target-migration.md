# ADR-0002: V4-to-v5 distinct-target migration

- Status: Accepted for Honey 0.9.1 implementation
- Date: 2026-07-20
- Depends on: ADR-0001
- Applies to: offline local administration and migration evidence
- Prohibited path: automatic or in-place v4 data rewrite during `SqliteStore::open`

## Context

The evaluated v4 database is approximately 50 GB and did not reopen readiness during a controlled
five-minute restart. It is retained evidence and cannot be the first migration input or the only copy
touched by development. V4 stores complete residual snapshots plus normalized catalog authority,
external revision anchors, encrypted blob references, effects, idempotency records, handoffs,
spaces, bundles, source snapshots, service state, and outbox state.

Migration must preserve exact retained revision identity, semantic roots, catalog roots, and
repository behavior while changing the residual representation. A crash, disk exhaustion, path
substitution, stale source, or activation failure must never leave the source partially rewritten.

## Decision

Migration is an explicit offline workflow from an authenticated v4 source into a newly created v5
target. Source, verified backup, target, work directory, activation descriptor, and receipt paths are
distinct canonical owner-controlled identities. The workflow never mutates or deletes the v4 source
or its verified backup.

Ordinary repository open supports the current format only. When it sees a v4 source in a v5-only
configuration, it returns a stable migration-required result without mutation. A v4 binary presented
with v5 returns unsupported downgrade without mutation.

## Required command surfaces

Honey 0.9.1 provides local offline administrative surfaces, not new public v1 RPCs:

- migration preflight/preview;
- migration execute/resume;
- migration status/verify;
- activation preview/execute/status; and
- distinct-target rollback by restoring the active-store descriptor to the retained v4 identity.

The final CLI spelling is registered in `docs/commands.v1.json`. Every surface rejects daemon-active,
nonlocal, non-owner, symlink-substituted, aliased, missing, reused, or unsafe paths.

## Preflight authority

Preflight acquires an exclusive cross-process migration lock and proves:

1. the daemon and all writers are stopped;
2. source and backup are regular owner-only files/directories with stable device/inode identities;
3. the source v4 format, migration ledger, capacity profile, latest revision, revision anchor, SQLite
   integrity, and application compatibility authenticate;
4. the backup was created from the same frozen source head, verifies completely, and restores into a
   separate empty verification target;
5. the proposed v5 target and work paths do not exist and are not aliases of source, backup, blob,
   anchor, or active-store paths;
6. all retained v4 revision residual checksums and metadata can be enumerated without modification;
7. the effective retention/pin policy and expected retained range are frozen; and
8. free space exceeds a checked formula covering the new v5 target, temporary batch state, SQLite
   WAL/checkpoint headroom, receipt state, rollback reserve, and the profile's runtime reserve.

Preflight emits a signed canonical preview. Execute accepts only that exact preview and rejects any
source identity, size, mtime, head, anchor, backup, policy, free-space, target-existence, signer, or
tool-version drift.

The free-space formula uses checked integer arithmetic and an explicit worst-case estimate derived
from authenticated v4 byte counts and frozen v5 bounds. It must not assume immediate source deletion,
`VACUUM`, compression gain, sparse-file behavior, or reclaim of the verified backup.

## Target construction

Execute creates an owner-only work directory and target with create-new semantics. It initializes
only the v5 schema and writes a migration authority row in `building` state. That state contains no
secret or protected content beyond what the target database legitimately stores.

Migration proceeds in deterministic, restartable batches:

1. Authenticate the next v4 revision metadata and residual checksum.
2. Decode the canonical v4 catalog-free state under strict bounds.
3. For the first retained revision, emit a v5 checkpoint. For later revisions, derive a typed delta
   from the exact prior decoded state and current state; write a checkpoint instead only when the
   frozen v5 cadence requires it.
4. Copy or reconstruct normalized catalog records and lineage validity without changing their exact
   canonical record bytes, publication revisions, checksums, or ordered roots.
5. Apply the delta to the prior v5 state in memory and require byte-for-byte canonical state equality
   with the decoded v4 state.
6. Require the same revision, legacy state checksum, semantic root, catalog root, atom count, edge
   count, and referenced-blob byte count before committing the batch.
7. Commit the v5 records and an authenticated progress row in one `synchronous=FULL` transaction,
   then fsync the target and work-directory metadata required for resume.

Progress is monotonic and bound to source identity, source head, backup proof, target identity,
profile/tool version, v5 policy digest, last migrated revision, and v5 chain digest. Resume repeats
authentication and continues only from the last fully committed batch. Partial uncommitted work is
ignored by SQLite rollback. A mismatch requires explicit safe cleanup of the newly created target;
the tool never guesses or repairs the source.

## Post-migration verification

Before target activation, the workflow requires all of the following:

- SQLite structural integrity and foreign-key checks;
- exact v5 head, revision range, checkpoint/delta chain, and external target anchor verification;
- every migrated v4 revision's revision, state checksum, semantic root, and catalog root match;
- boundary revisions plus a fixed-seed random sample reconstruct exactly from checkpoint plus deltas;
- latest complete state, normalized catalog, lineage heads, effects, idempotency, outbox, blobs,
  bundles, snapshots, handoffs, spaces, service records, and worker state compare semantically;
- deep-integrity verification of every retained v5 checkpoint and delta;
- a backup of the v5 target is created, verified, and restored into another distinct empty target;
- clean start, clean restart, and crash-recovery start remain within the frozen readiness bound; and
- installed v1 conformance reads against the v5 target remain compatible.

A failure leaves the target non-active and the v4 source/backup unchanged.

## Migration receipt

Successful verification emits a signed canonical receipt binding:

- receipt schema/tool version and signer/provider identity;
- source canonical path commitment, device, inode, byte length, database digest, schema/format,
  capacity profile, frozen head, retained range, and external anchor digest;
- verified-backup identity, digest, manifest/root, source binding, and restore-verification receipt;
- target canonical path commitment, device, inode, byte length, database digest, v5 schema/profile,
  chain head, retained range, and target anchor digest;
- exact source-to-target revision/root comparison root and sample seed;
- effective retention/checkpoint policy digests;
- migration batch count, logical/encoded byte counts, checkpoint/delta counts, start/end monotonic
  durations, and content-free status;
- post-migration integrity, deep verification, backup/restore, readiness, and conformance results;
  and
- candidate source commit/tree and installed administrative binary SHA-256.

The receipt schema rejects arbitrary extension fields, duplicate JSON keys in interchange form,
NaN/Infinity, unsafe paths, unknown status, and missing bindings. Private absolute paths are stored
only in owner-private evidence; public summaries contain commitments and safe basenames.

## Activation

The active store is selected by a small owner-only canonical descriptor outside either database. Its
payload binds format, canonical target identity, database/anchor digests, verified migration receipt,
and generation. Activation:

1. reacquires exclusive daemon/migration locks;
2. reauthenticates v4 source, v5 target, receipt, target head, backup, and absence of writers;
3. writes a new descriptor to a create-new sibling temporary file;
4. fsyncs the file, atomically renames it over the active descriptor, and fsyncs the parent; and
5. performs a read-only open plus readiness verification through the active descriptor.

Failure before rename leaves v4 active. Failure after rename leaves a complete v5 descriptor and is
resolved by status verification. It never produces a half descriptor. The v4 source remains retained
after activation.

Rollback means atomically publishing a newly authenticated descriptor that selects the unchanged v4
source, after proving the v5 daemon is stopped and no post-activation writes would be lost. If v5 has
accepted writes, rollback is a separately planned recovery/export operation, not a silent pointer
flip.

## Downgrade and deletion

- In-place downgrade is rejected.
- An older binary may restore an authenticated compatible v4 backup only into a distinct empty
  target; it may not open or rewrite v5.
- Migration never deletes v4, its anchor, backup, or external blobs.
- V4 retirement requires a separate signed retention preview/execute/status flow after all holds,
  pins, backup, and rollback obligations are satisfied.
- Revision compaction and blob garbage collection remain separate plans and receipts.

## Failure behavior

Every boundary in the 0.9.1 failpoint matrix is exercised by process termination, not only returned
errors. On resume, the only allowed outcomes are:

- authenticated unchanged v4 source and a resumable complete-prefix v5 target;
- authenticated unchanged v4 source and an explicitly rejected/cleanable incomplete new target; or
- fully verified v5 target plus a complete old or new active descriptor.

No outcome may expose a hybrid revision, mutate the source/backup, fabricate a receipt, or open
readiness early.

## Consequences

Migration requires temporary disk substantially beyond the final v5 size and may take significant
time, but source preservation makes interruption and rollback tractable. The explicit descriptor adds
one authenticated indirection to startup. The workflow can be qualified first on generated inputs,
then on an authorized disposable verified copy, without risking the retained evidence store.

## Rejected alternatives

- **Automatic startup migration:** couples ordinary availability to a long destructive operation and
  makes a crash capable of stranding the only store.
- **In-place table rewrite:** cannot preserve a simple rollback boundary under exhaustion or
  interruption.
- **Copy without verified backup restore:** does not prove the recovery artifact is usable.
- **Activate by renaming database directories:** broadens destructive path scope and complicates
  blob/anchor identity; the small authenticated descriptor is safer.
- **Delete v4 after success:** removes rollback/evidence without a separately reviewed retention
  decision.

## Verification obligations

- Generated small, every boundary, generated Hiero-shaped, and then authorized verified-copy cases.
- Failpoints after backup verification, target creation, every batch, checkpoint, delta, chain/root
  verification, receipt write/sign, activation temp write/fsync/rename, and post-activation open.
- Source and verified backup device/inode/size/digest remain exact before and after every case.
- Repeated interrupted execution is idempotent resume or safe target-only cleanup.
- All retained revision/root comparisons and installed v1 conformance pass before activation.
