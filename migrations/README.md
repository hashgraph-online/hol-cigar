# Database migrations

The closed inventory in `authority-v1.json` is the append-only source authority for both migration
trees. Every row binds a contiguous sequence, stable name, exact SHA-256 source digest,
application-major interval, rolling classification, root source, and byte-identical
`cigar-store` crate mirror. Validate it with:

```sh
python3 scripts/migrations/validate_migration_authority.py --repo-root .
python3 -m unittest scripts.migrations.tests.test_validate_migration_authority
```

The validator rejects source or mirror edits, deletion, renaming, gaps, reordering, unlisted SQL,
duplicate/unknown authority fields, path escape, symlinks, metadata drift, and migration-owned
transaction control. Existing migration files are never edited to add behavior; a new change gets
the next sequence and a new authority row.

## SQLite

Sequence 1 is the retained original schema. Sequence 2 adds only compatibility metadata to its
migration ledger. Sequence 3 adds immutable atom/FTS generation tables, a singleton activation
pointer, authoritative revision/checksum watermarks, and no authoritative-state rewrite. Sequence
4 adds the normalized authoritative atom/edge catalog, catalog-free residual revisions, indexed
lineage intervals, deterministic 16-bit integrity buckets, and an immutable capacity-profile
authority singleton.
`cigar-store` applies each missing sequence in its own exclusive transaction, writes the ledger row
inside that transaction, and verifies the complete known prefix afterward. The retained-v1 fixture
is process-aborted at ledger bootstrap and at transaction begin, SQL applied, both sides of ledger
insertion, and both sides of commit for sequences 2 through 4 (19 interruption boundaries). Before
recovery, each database contains exactly the old prefix or the durably committed new row; restart
then converges idempotently. Startup performs the v4 data backfill in one separate immediate
transaction: every retained legacy revision is checksum-verified, atom/edge rows and lineage
intervals are normalized, catalog roots are streamed, catalog-free residuals are published, legacy
whole-state rows are deleted, and v4 authority is activated atomically. An interrupted transaction
rolls back to legacy authority and a restart repeats cleanly. Migrated semantic roots preserve the
legacy root; startup then builds and verifies the first disposable projection generation from the
normalized catalog.

Mixed-version operation is allowed only when every participating application embeds the exact same
immutable migration catalog and every installed row spans that application's major. The historical
sequence-one implementation used an exact row-count check and therefore refuses sequences two and
three and four; it is not claimed as a rolling participant. Compatibility-reader binaries also reject every
unknown future row, even when the database row self-declares itself online and version-compatible, because
database-owned metadata cannot authenticate unknown DDL. An unknown, offline, or
version-incompatible row is an explicit unsupported downgrade and startup fails closed without
repairing or mutating it.

## PostgreSQL

The four retained PostgreSQL sequences are byte-bound by the same authority. The dedicated
migrator takes one transaction-scoped advisory lock and applies every missing DDL statement plus
its ledger row in a serializable transaction. Runtime roles execute no DDL. Verification requires
the exact immutable embedded catalog, declared rolling compatibility, and an application-major
interval containing the running binary; an unknown suffix is never trusted and connection fails
closed.

`python3 scripts/migrations/qualify_postgres_tls.py` runs the macOS live gate against an isolated
PostgreSQL 18.2 container. It generates a fresh private CA and DNS-only `localhost` server
certificate, requires TLS 1.3, rejects plaintext TCP, binds an ephemeral loopback port, and removes
only its uniquely labelled container and temporary key directory. The real migrator is
process-aborted at all 12 ledger-bootstrap, advisory-lock, per-sequence SQL/ledger, and commit
boundaries. Each retained prefix must recover to the exact four-row ledger with an unchanged
populated semantic root. A sequence-one connection remains open through sequences two through
four, writes compatible state, and the current runtime reads and advances that state.

The same gate creates distinct owner/migrator and runtime roles. It removes PUBLIC schema,
database-create, and temporary-table authority; proves the runtime cannot migrate, assume the
migrator/database-owner identity, execute schema/table/function DDL, or mutate the ledger; and
proves permitted application DML still succeeds under forced RLS. Production configuration rejects
every caller-provided PostgreSQL `options` value and supplies a fixed
`public,pg_catalog,pg_temp` search path, so a hostile DSN or role default cannot redirect migration
objects. Wrong CA, wrong DNS identity, checksum tamper, unknown suffix, and incompatible downgrade
cases all fail closed. The harness requires Docker, OpenSSL, Cargo nextest, and the local image
`postgres:18.2-bookworm`; it does not pull or modify unrelated Docker resources.
