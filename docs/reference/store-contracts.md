# Repository transaction contracts

`cigar-store` exposes capability-bound transactions instead of an unscoped key/value interface.

- `AccessContext` fixes tenant and purpose when a transaction opens. Repository methods accept no later tenant override, preventing a handle from crossing tenant scope.
- `SnapshotSelection` chooses latest-at-open or an exact retained `StoreRevision`. An `AtomCursor` embeds that revision and fails with `MixedSnapshot` in another snapshot.
- `begin_write` binds an exact expected revision. Commit validates all staged protocol records, referential integrity, context/effect sequence and parent links, blob digest/size, derivation acyclicity, and outbox causality before one atomic state publication.
- `IdempotencyIdentity` binds operation scope and secret-safe caller key to the normalized request digest. Repeating that identity returns the original receipt even with a stale expected revision; reusing its key for different semantics fails closed.
- `CancellationToken` is checked before work and again at the publication boundary. Dropped, cancelled, stale, invalid, and failpoint-aborted writes expose no partial state.

The in-memory backend retains immutable whole-state revisions to make the oracle easy to reason about. Production backends can use database MVCC, but observable behavior must match the reusable conformance suite exactly.

Migration plans are append-only, checksum-addressed, application-version bounded, classified online/offline, and require explicit lock behavior, verification, and rollback-or-restore instructions.

## Durable local profile

`SqliteStore` verifies the bundled SQLite version and FTS5 capability at startup, then enables WAL, `synchronous=FULL`, foreign keys, defensive mode, secure delete, a 32 MiB page cache, a 30-second busy timeout, and bounded WAL checkpoints. The connection mutex is the single writer serializer. Database read locks exist only while a retained state is loaded; returned read transactions are detached immutable snapshots and therefore cannot pin the WAL indefinitely.

Every state revision has a SHA-256 checksum and an external fsynced revision anchor. A database behind its anchor is rejected, which prevents a truncated committed WAL from silently reopening an older revision. A database ahead of its anchor advances it during recovery, covering termination after database commit but before anchor replacement.

Production blob writes compose the database with `RepositoryBlobStore`. Encrypted bytes are fully written, flushed, fsynced, renamed, and parent-directory-synced before SQLite metadata commits. Failures before metadata commit leave no visible reference; startup reconciliation quarantines the orphan. Authentication failures and swaps create durable, bounded digest-only invalidation markers for downstream processing. SQLite state contains blob references only and never blob plaintext.

The atom and FTS5 tables are disposable projections. `rebuild_atom_projection` replaces both in one transaction from the durable repository state and honors cancellation. Exact tenant/version lookups use the composite primary key.

## Keys, backup, restore, and GC

`EncryptedDevelopmentKeystore` encrypts the complete private provider state with an Argon2id-derived key. `OsKeychainKeyProvider` obtains that file key from the native operating-system credential store. Rotation prevents new encryption with retired keys while retaining historical decryptability until destruction.

`create_backup` uses SQLite's online backup API and copies encrypted blob files into a temporary archive. Its signed CBOR manifest contains schema/repository versions, every file size and checksum, required opaque key references, and a deterministic root. `verify_backup` validates signature, inventory, checksums, root, schema, revision, SQLite structure, and state checksums. `restore_backup` accepts only a nonexistent or exactly empty target, verifies before copying, checks the restored database before activation, and atomically renames the result.

Physical blob GC requires satisfied retention, no legal hold, and completed backup policy. `SqliteStore::garbage_collect_blob_roots` derives the complete tenant mark set from its latest checksum-verified state and retains the writer lock through physical selection or deletion, so a concurrent blob-before-metadata publication cannot be collected. Dry-run and deletion use the same deterministic, tenant-qualified, bounded eligibility list; callers cannot supply their own live roots.
