# ADR-0001: Incremental SQLite repository state v5

- Status: Accepted for Honey 0.9.2 implementation
- Date: 2026-07-20
- Decision owners: CIGAR Honey release authority
- Applies to: `cigar-store` durable local profile
- Supersedes: ordinary v4 per-revision `residual_state` persistence
- Does not supersede: repository API semantics, normalized catalog authority, durability, or v1 API

## Context

Honey 0.9.0 stores the atom/edge catalog in normalized immutable tables, but serializes the complete
catalog-free `CommittedState` into `cigar_repository_revisions_v4.residual_state` for every
repository mutation. The evaluated store retained 1,024 such revisions. Their payloads totalled
49,841,189,105 bytes, approximately 99.5% of a 50,084,237,312-byte database; the latest payload was
49,122,343 bytes. Latency rose with request order and restart did not reopen readiness in five
minutes.

The repository contract still requires exact retained-revision reads, deterministic canonical
encoding, one atomic durable state publication, request-bound idempotency, authenticated roots, and
safe recovery after ambiguous outcomes. A database-size ceiling, `VACUUM`, relaxed durability, or
shorter unprincipled retention would conceal rather than repair the write-amplification defect.

## Decision

Storage format v5 keeps SQLite as the authoritative local evidence store and preserves
`PRAGMA synchronous=FULL`. It replaces ordinary full residual snapshots with a canonical,
strictly-versioned `RepositoryDeltaV5` chain anchored by bounded full checkpoints.

The existing normalized immutable atom/edge authority remains authoritative. V5 incrementally
persists the catalog mutations and records the resulting catalog root on each revision. Catalog-free
domains are reconstructed from the newest authenticated checkpoint at or before a selected revision
plus its bounded consecutive delta suffix.

Qdrant or another vector engine may implement the existing optional `VectorAdapter` boundary, but
is a disposable retrieval projection. It never stores the authoritative revision chain, effects,
idempotency state, policy decisions, receipts, or provenance truth and is not required for v5
readiness.

## Canonical records

The implementation must isolate the following strict Rust records in focused modules. Every record
uses `serde(deny_unknown_fields)`, validates before encoding and after decoding, and is encoded with
the repository's deterministic canonical CBOR profile.

`RepositoryDeltaV5` contains:

- format version and exact parent/result revisions;
- one tenant and access-purpose commitment fixed by the write transaction;
- a bounded ordered list of typed mutations derived from staged repository or service mutations;
- the logical byte count and closed mutation-count summary used for telemetry;
- no arbitrary JSON, untyped map, path, prompt, source text copied solely for observability, or
  caller-controlled telemetry label.

The closed mutation variants cover the currently persisted catalog-free domains:

- immutable source snapshot insertion;
- immutable bundle insertion;
- append-only context commit;
- append-only effect journal event;
- monotonic effect-record replacement;
- immutable blob-reference insertion (never external blob plaintext);
- causal outbox append;
- request idempotency receipt insertion;
- service batch application and service idempotency receipt insertion; and
- worker-state transition.

Atom and edge insertions remain normalized catalog writes, but the revision envelope records their
ordered mutation digest and resulting catalog root. Adding a new durable mutation variant requires a
new delta format and explicit migration; an unknown variant fails closed.

`RepositoryCheckpointV5` contains the complete canonical catalog-free state at one revision. It is
permitted only at genesis, migration boundaries, explicit bounded checkpoint triggers, and
compaction output. A checkpoint is not written for every ordinary mutation.

## SQLite layout

The fresh-target schema includes at least these logical tables; exact SQL names remain generator
authority:

1. `repository_authority_v5`: singleton format/capacity identity, current head, active chain head,
   retention-policy digest, checkpoint policy, and activation state.
2. `repository_checkpoints_v5`: revision, format, canonical state bytes, state digest, catalog root,
   semantic root, chain digest, counts, encoded length, and creation reason.
3. `repository_deltas_v5`: unique revision, unique parent revision, format, canonical delta bytes,
   delta digest, result-state digest, catalog/semantic roots, prior/result chain digests, logical and
   encoded byte counts.
4. `repository_retention_pins_v5`: exact revision or closed range, closed reason, issuing authority
   digest, issue/expiry time where permitted, signed receipt digest, and active/released state.
5. Optional compaction execution state only when it is required to recover a destructive boundary
   and cannot be reconstructed from signed external receipts.

Foreign keys and unique constraints must make forks, gaps, duplicate revisions, invalid parent
links, and orphaned pins unrepresentable where SQLite can enforce them. Application verification
must cover cryptographic and cross-table invariants SQLite cannot express.

The v4 revision table remains readable only through explicit v4 compatibility and migration code.
`MAX_RETAINED_SQLITE_SNAPSHOTS` remains a v4 compatibility bound and is not reused as v5 policy.

## Digest and revision envelope

All hashes use explicit domain separation and length-delimited fields. At minimum:

- `CIGAR-REPOSITORY-V5-DELTA` authenticates the exact canonical delta;
- `CIGAR-REPOSITORY-V5-CHECKPOINT` authenticates checkpoint bytes and revision;
- `CIGAR-REPOSITORY-V5-STATE` authenticates the reconstructed catalog-free state;
- `CIGAR-REPOSITORY-V5-CHAIN` authenticates parent chain digest, revision, delta/checkpoint digest,
  resulting state digest, catalog root, semantic root, counts, and capacity profile; and
- `CIGAR-REPOSITORY-V5-RETENTION-PIN` authenticates every pin field.

Revision `r` must bind `r-1`, the exact delta or checkpoint digest, the resulting state digest,
catalog root, semantic root, atom/edge/blob counts, and previous chain digest. Reordered, removed,
duplicated, substituted, or replayed records fail authentication. Integer conversions and aggregate
counts are checked; no counter or length may wrap.

## Commit protocol

The writer performs these steps in deterministic order:

1. Acquire the existing single-writer serializer and measure monotonic lock wait.
2. Check cancellation and request-bound idempotency. A matching prior identity returns its receipt
   without a new delta; the same key with different normalized semantics fails closed.
3. Authenticate the expected head and load only the bounded state needed to validate the write.
4. Validate staged mutations using the same behavioral oracle and derive one `RepositoryDeltaV5`
   before the final database transaction.
5. Pre-encode and bound the delta; determine whether count and accumulated-byte thresholds require
   a checkpoint. A no-op semantic change may persist only a required execution/idempotency record.
6. Open one `BEGIN IMMEDIATE` transaction under `synchronous=FULL`.
7. Reverify parent/head, apply normalized catalog rows and other changed records, insert the delta,
   optionally insert the checkpoint, update roots/head/retention metadata, and insert the exact
   idempotency/outbox/effect records atomically.
8. Check cancellation at the existing publication boundary and commit.
9. Only after SQLite commit, atomically publish and fsync the external revision anchor. A failure in
   this interval remains an ambiguous outcome and is reconciled by authenticated revision and
   idempotency identity, never blind retry.

An ordinary mutation must not encode or insert a complete checkpoint unless a frozen checkpoint
trigger fires. Checkpoint decisions are deterministic from authenticated policy plus parent-chain
metadata, not wall-clock timing alone.

## Bounds and checkpoint policy

Configuration is one validated policy, not independent unsafe knobs. It includes:

- maximum delta operations and bytes;
- maximum checkpoint bytes;
- maximum deltas since checkpoint;
- maximum accumulated delta bytes since checkpoint;
- maximum replay work permitted during readiness;
- retained revision count, age, and physical byte ceilings;
- minimum reconstructable revision window; and
- legal-hold, backup, replay, and explicit pin behavior.

Zero, unbounded, internally inconsistent, or capacity-incompatible settings are rejected. Both the
delta-count and accumulated-byte trigger can force a checkpoint. A delta exceeding its own bound
fails before transaction publication; it is never silently converted into an unbounded record.
When active pins and required minimums make a byte ceiling impossible, writes or maintenance fail
with a stable content-free capacity result rather than deleting protected history.

The initial Honey qualification policy must be frozen before measurement and must satisfy the
10,000-mutation growth, bounded-chain, and 30-second startup gates. Threshold values become release
authority only after baseline measurement; changing them requires profile regeneration and review.

## Reads and recovery

`SnapshotSelection::Latest` authenticates the head and reconstructs from the latest usable
checkpoint plus its bounded suffix. `SnapshotSelection::Revision(r)` selects the latest retained
checkpoint at or before `r`, authenticates every consecutive delta through `r`, and verifies the
resulting state, catalog, semantic, and chain digests. Missing parents, forks, gaps, bound excess,
unknown formats, or digest mismatch fail closed.

Normal startup verifies path/configuration, migration authority, SQLite configuration, head
metadata, latest checkpoint, bounded suffix, latest catalog projection requirement, external
revision anchor, and blob reconciliation before readiness. It must not scan all retained history.
An explicit deep-integrity operation authenticates every retained checkpoint and delta. A signed
verified-prefix record may accelerate later deep checks only while its bound database identity,
chain head, verifier version, and policy remain exact.

## Retention and compaction

Logical retention and physical compaction are explicit maintenance, separate from blob GC. A signed
preview binds head revision, effective policy, verified backup, pins/holds, candidate range, expected
post-state roots/range, and required free space. Execute accepts only that exact preview, rechecks all
bindings under exclusive writer control, preserves every pinned/reconstructable revision, and emits
a signed receipt. Ordinary startup never performs destructive compaction.

## Compatibility and migration

V5 is created only in a distinct target by the offline workflow in ADR-0002. Ordinary
`SqliteStore::open` must not rewrite an existing v4 database to v5. V4 remains untouched through
migration and activation and is removed only by a later separately authorized retention action.

The public `cigar.context.v1` operation and payload registries do not change. Repository conformance
must remain observationally equivalent to the in-memory backend for every retained revision.

## Consequences

Benefits:

- ordinary write cost follows changed state rather than total state;
- startup work is bounded by checkpoint policy rather than retained full-state count;
- exact history, provenance, effects, and idempotency remain authoritative and replayable; and
- retrieval engines can evolve independently as derived projections.

Costs:

- commits, reads, migration, retention, and recovery have a more explicit chain protocol;
- periodic checkpoints still encode complete catalog-free state and therefore need strict cadence,
  size bounds, and qualification; and
- dual format support remains until v4 retirement is separately authorized.

## Rejected alternatives

- **Qdrant instead of SQLite:** improves approximate semantic retrieval but does not provide the
  required cross-domain authoritative revision transaction or knowledge graph. Persisting the same
  full states as payloads would retain the defect.
- **Full v4 snapshot with compression:** reduces bytes variably but leaves work proportional to
  total state and introduces content-dependent latency.
- **Increase the database limit or reduce durability:** masks the defect and violates release
  controls.
- **Retain only the latest state:** breaks exact revision replay, backup, audit, and pins.
- **In-place v4 rewrite:** makes interruption and rollback capable of destroying the only source.

## Verification obligations

- Canonical encode/decode, delta apply/compose, permutation, duplicate-application, and overflow
  properties.
- Reconstruct every retained revision identically across memory oracle, v4 fixtures, and v5.
- Process-kill failpoints at every boundary listed in the Honey 0.9.2 failpoint matrix.
- 10,000 serial mutations without 10,000 complete residual checkpoints and with less than 1 MiB
  steady-state growth per frozen Hiero-shaped compilation.
- Clean and crash-recovery readiness at or below 30 seconds at the retention ceiling.
- `synchronous=FULL`, secure-path, owner-only, anchor, backup/restore, and ambiguity tests remain
  mandatory.
