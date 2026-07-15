# cigar-store

Stability: kernel, pre-v1.

This crate owns backend-neutral transaction contracts, the in-memory MVCC behavioral oracle, and the durable local profile. Every transaction is opened with an immutable tenant/purpose capability, snapshot choice or expected revision, and cancellation token. The oracle retains whole-state revisions; SQLite pins one catalog-free residual revision and serves atom/edge reads from normalized snapshot-visible indexes. Writes stage private changes and publish one new revision only after all repository invariants pass.

Ordered atom-ID lookup is bounded to 1,000 unique public IDs, preserves request order, returns
per-item absence for both missing and cross-tenant records, and uses tenant-scoped indexes.
Historical SQLite visibility is bound by each row's publication revision and lineage-head validity
interval; the graph is never hydrated to open a production read transaction.

The reusable `conformance::run_repository_conformance` suite covers every repository method plus atomic commit/drop/abort, repeatable historical snapshots, cross-tenant isolation, request-bound idempotency, outbox causality, derivation-cycle rejection, revision races, snapshot-pinned cursors, limits, and cancellation. SQLite and PostgreSQL backends must implement `Repository` and `ConformanceRepository` and pass this same suite.

`ServiceRepository` is the object-safe embedded/daemon boundary. It stores bounded exact record bytes in immutable per-key version histories, publishes multi-record CAS batches atomically, persists request-digest-bound response bytes for exact idempotent replay, and lists records through tenant/query/revision-pinned cursors. It also exposes opaque effect and outbox recovery pages plus durable worker cursors, heartbeats, renewable leases, and monotonic fencing tokens. The effect kernel remains responsible for decoding and classifying opaque effect envelopes.

`SqliteStore` uses bundled SQLite in WAL/FULL/defensive mode with foreign keys, a bounded page
cache, checksum-verified append-only migrations, independent snapshot-pinned readers, serialized
writers, revision rollback anchors, rebuildable atom/FTS projections, and the same conformance
suite. Schema v4 stores atoms, edges, lineage history, and 65,536 deterministic integrity buckets
separately from bounded residual MVCC records. New commits rewrite only residual state and touched
catalog buckets. Projection rebuild and full catalog verification stream ordered rows.

`SqliteCapacityProfile::Standard` remains the default 4 GiB database profile. `LargeLocal` is an
explicit, immutable database binding available only on native macOS arm64: it uses a 64 GiB
database cap, requires 300 GiB free on first activation and a 16 GiB reopen reserve, and rejects
more than 1.25 million atoms, 12.5 million edges, or 128 GiB of logical blob references. Selecting
the profile does not claim that a physical scale qualification has passed.

`LocalBlobStore` uses per-blob random data keys, XChaCha20-Poly1305, provider-wrapped keys, tenant/digest/size associated data, same-filesystem rename, file and directory fsync, startup reconciliation, quarantine, and policy-gated bounded GC. The SQLite GC entry point derives exact live roots while holding its writer lock through tenant-qualified selection/deletion; operator callers never provide a potentially unsafe mark set. Signed backup APIs inventory and hash a consistent online SQLite copy plus encrypted blobs, verify offline, and restore only to an empty location. Shared PostgreSQL/object storage remains owned by WP18.
