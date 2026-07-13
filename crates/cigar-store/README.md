# cigar-store

Stability: kernel, pre-v1.

This crate owns backend-neutral transaction contracts, the in-memory MVCC behavioral oracle, and the durable local profile. Every transaction is opened with an immutable tenant/purpose capability, snapshot choice or expected revision, and cancellation token. Read transactions retain one committed whole-state revision; write transactions stage private changes and publish one new revision only after all repository invariants pass.

Each immutable tenant state carries atom-ID-to-version and current-lineage indexes. Ordered batch
lookup is bounded to 1,000 unique public IDs, preserves request order, returns per-item absence for
both missing and cross-tenant records, and never pages or scans the atom collection. Historical
MVCC states retain their own indexes. Legacy state index reconstruction is fail-closed above a hard
100,000-atom migration bound.

The reusable `conformance::run_repository_conformance` suite covers every repository method plus atomic commit/drop/abort, repeatable historical snapshots, cross-tenant isolation, request-bound idempotency, outbox causality, derivation-cycle rejection, revision races, snapshot-pinned cursors, limits, and cancellation. SQLite and PostgreSQL backends must implement `Repository` and `ConformanceRepository` and pass this same suite.

`ServiceRepository` is the object-safe embedded/daemon boundary. It stores bounded exact record bytes in immutable per-key version histories, publishes multi-record CAS batches atomically, persists request-digest-bound response bytes for exact idempotent replay, and lists records through tenant/query/revision-pinned cursors. It also exposes opaque effect and outbox recovery pages plus durable worker cursors, heartbeats, renewable leases, and monotonic fencing tokens. The effect kernel remains responsible for decoding and classifying opaque effect envelopes.

`SqliteStore` uses a bundled SQLite in WAL/FULL/defensive mode with foreign keys, a bounded page cache, checksum-verified append-only migrations, detached read snapshots, serialized writers, revision rollback anchors, rebuildable atom/FTS projections, and the same conformance suite. Production blob mutations require `open_with_blob_repository`; metadata commits become visible only after authenticated encrypted file publication.

Service records, idempotency receipts, and worker state are serde-defaulted fields in the existing checksum-protected whole-state MVCC snapshots. This preserves decoding of pre-service snapshots and does not modify the frozen `0001` migration.

`LocalBlobStore` uses per-blob random data keys, XChaCha20-Poly1305, provider-wrapped keys, tenant/digest/size associated data, same-filesystem rename, file and directory fsync, startup reconciliation, quarantine, and policy-gated bounded GC. The SQLite GC entry point derives exact live roots while holding its writer lock through tenant-qualified selection/deletion; operator callers never provide a potentially unsafe mark set. Signed backup APIs inventory and hash a consistent online SQLite copy plus encrypted blobs, verify offline, and restore only to an empty location. Shared PostgreSQL/object storage remains owned by WP18.
