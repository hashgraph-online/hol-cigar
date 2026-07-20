# CIGAR Honey 0.9.1 efficiency and reliability release plan

Audience: Codex GPT-5.6 SOL implementation agent, CIGAR maintainers, qualification operators, and
release reviewers.

Status: planning checklist. An item is complete only when the named implementation, test, and
candidate-bound evidence exist. Source code alone does not close installed-byte or release gates.

Target identity:

- Marketing name: `CIGAR Honey v0.9.1`.
- Product version: `0.9.1-honey.1`.
- Git tag: `v0.9.1-honey.1`.
- Channel/state: `honey` / `developer-preview`.
- Context ABI: `cigar.context.v1`.
- Public v1 registry: exactly seven services, 45 operations, and 70 nominal payload types.
- Platform: `aarch64-apple-darwin`, embedded and local-sidecar modes.
- Machine claims remain `prerelease=true`, `supported=false`, and
  `production_qualified=false`.

Planning inputs:

- `docs/cigar-honey-release-efficiency-handoff.md`, evidence date 2026-07-20.
- Evaluated release `0.9.0-honey.1`.
- Raw paired benchmark SHA-256
  `776b84c8cce3b11915b53947f3bb21a86c8a9819fc43ef0d1c85362ca62a3455`.
- The 0.9.0 process in `todo-honey-v0.9.md`, `packaging/honey/`, and
  `scripts/release/qualify_honey_release.py`.
- Planning baseline commit `1ceea65e84fa59b3a4bff5027a0cced325cd2310`; this is not the future candidate
  commit.

Status legend: `[ ]` pending, `[~]` in progress, `[x]` verified, `[!]` blocked with recorded
evidence.

## 1. Release outcome and scope boundary

Honey 0.9.1 is a reliability repair, not a weakening of CIGAR governance. It must replace the
full-residual-snapshot write path, recover bounded startup, reduce duplicate selected content and
excess candidate flow, preserve the quality gains observed in the 200-iteration evaluation, and
repeat every mandatory 0.9.0 release gate on the new exact bytes.

The following controls are non-negotiable:

- deterministic canonical encoding and exact-revision replay;
- authenticated provenance, checksums, roots, signed receipts, and revalidation;
- request-bound idempotency and explicit `UNKNOWN` outcomes;
- `synchronous=FULL`, secure local paths, owner-only state, and verified backup/restore;
- fail-closed policy, authorization, disclosure, tokenizer, materializer, and budget checks;
- content-free telemetry and no hidden chain-of-thought storage; and
- no migration or destructive maintenance against the retained 50 GB Hiero evidence store.

### 1.1 Compatibility decision

- [x] Treat storage format v5, content-equivalence grouping, retrieval bounding, telemetry, and
  offline administration as the selected 0.9.1 repair surface.
- [x] Preserve `spec/api/operations-v1.json`, `spec/api/operation-payloads-v1.json`, and all
  generated v1 operation projections byte-for-byte except version-bearing metadata that the closed
  authority explicitly owns.
- [x] Do not add the proposed atomic compilation or revision-administration RPCs to the frozen v1
  registry.
- [x] Produce a versioned protocol proposal for those RPCs, but keep it out of the 0.9.1 artifact
  profile unless the release owner explicitly changes the target to a new protocol/product line.
- [ ] Keep every old granular v1 client working against 0.9.1.
- [x] Keep `production_qualified=false` even when all developer-preview gates pass.

Decision evidence (2026-07-20): both v1 operation authorities and all 12 generated TypeScript,
Python, and Go operation/model/error/capability projections are byte-identical to planning baseline
`1ceea65e84fa59b3a4bff5027a0cced325cd2310`; the non-mutating client generator check passes. The
closed product/profile/report authorities continue to require `production_qualified=false`.

If an owner requires the new RPCs in this release, stop before implementation and revise this plan,
the operation authority, compatibility window, SDK generation, schemas, conformance profiles, and
release identity together. Do not reinterpret or silently extend v1.

### 1.2 Promotion blockers

The candidate cannot be cut until all of these are true:

- [ ] No commit stores a complete catalog-free residual snapshot for every ordinary mutation.
- [ ] v4-to-v5 migration is distinct-target, backup-gated, interruption-safe, and root-equivalent.
- [ ] Clean and crash-recovery startup reach readiness within 30 seconds at the retention ceiling.
- [ ] The 100-request serial latency-slope gate and 10,000-mutation storage gate pass.
- [ ] Duplicate content, source diversity, candidate displacement, citation, and required-source
  gates pass.
- [ ] Every mandatory 0.9.0 gate passes again against exact 0.9.1 installed bytes.
- [ ] No failed, skipped, or unevaluated mandatory gate is summarized as passed.

## 2. Findings-to-work traceability

| Finding | Baseline evidence | 0.9.1 workstream | Blocking evidence |
|---|---:|---|---|
| Full residual snapshot per revision | 49.84 GB retained residuals; approximately 99.5% of DB | H91-200/H91-210 | v5 reconstruction, growth, and write-amplification report |
| Excess durable commits per compile | four mutation commits across eight calls | H91-220 plus future protocol proposal | per-operation commit telemetry; no more full-state rewrites |
| Startup/restart failure | readiness did not reopen in five minutes | H91-300 | clean/crash restart p95 and recovery report |
| Duplicate selected content | 27.15% overall; 80% JSON-RPC cohort | H91-400 | duplicate-content rate at most 5% with full provenance |
| Excess candidate flow | 50,310 displaced vs 534 selected | H91-410 | displaced:selected below 10:1 |
| Correlation prevents semantic reuse | run/job values alter complete request identity | H91-420/H91-500 | safe reuse report plus versioned design; no v1 semantic rewrite |
| CIGAR quality advantage | required-source 100%; citation resolvability 99% | H91-600 | non-regression quality report |
| Current operational latency | mean 45.10 s; slope about 558 ms/request | H91-600 | p95 and slope gates |

## 3. Global execution rules

- [x] Preserve unrelated work. The planning baseline currently has untracked handoff inputs; do not
  delete, reset, or hide them to manufacture a clean tree.
- [x] Inventory every modified, deleted, and untracked path before implementation and again before
  source freeze.
- [ ] Commit implementation in reviewable dependency order: measurement, persistence core,
  migration/recovery, context quality, qualification, then release integration.
- [ ] Keep generated files in generator authority. Update generators first, run generate once, and
  require check mode to be non-mutating.
- [ ] Build release artifacts only from one clean committed tree and the exact commit timestamp.
- [ ] Use create-new owner-only workspaces under canonical `/private/tmp` on macOS.
- [ ] Bind all qualification reports to source commit/tree, fixture digest, candidate manifest, and
  exact artifact SHA-256.
- [ ] Never use `VACUUM`, a larger database ceiling, reduced durability, manual row deletion, blind
  retry, early readiness, or added concurrency as the primary fix.
- [ ] Keep blob GC, revision compaction, migration, and backup as separate operations and receipts.
- [ ] Require explicit owner authorization before tagging, creating a GitHub prerelease, or
  uploading assets.

Dependency order:

```text
H91-000 intake and authority
  -> H91-100 measurement baseline
  -> H91-200 incremental persistence
  -> H91-300 migration, compaction, startup, deep verification
  -> H91-400 compiler/retrieval/reuse quality
  -> H91-500 next-protocol design (not selected in 0.9.1)
  -> H91-600 efficiency and reliability qualification
  -> H91-700 version, docs, demos, and release authority
  -> H91-800 source and contract gates
  -> H91-900 artifact build and assembly
  -> H91-1000 installed-byte qualification
  -> H91-1050 downstream Hiero shadow verification
  -> H91-1100 evidence, review, and authorized prerelease cut
```

## H91-000 — Intake, authority, and frozen decisions

### H91-010 — Preserve and authenticate the evidence

- [x] Record the exact SHA-256 and byte length of
  `docs/cigar-honey-release-efficiency-handoff.md` and the developer handoff ZIP without modifying
  either input.
- [x] Record the raw paired benchmark digest from the handoff in the 0.9.1 qualification profile.
- [x] Create a content-free finding ledger with one stable ID for every finding and required gate.
- [x] Mark the retained 50 GB Hiero state read-only evidence and explicitly exclude it from first
  migration, compaction, fuzz, and crash tests.
- [~] Identify a verified copied workload and generated scale fixtures as the only initial mutable
  test inputs.
- [x] Capture current Rust, Python, Node/pnpm, SQLite, macOS, CPU, filesystem, and storage identities
  for baseline comparability.
- [x] Record the external reproduction inputs named by the handoff without copying protected data
  into the Honey repository: `docs/cigar-workflow-efficacy-report.md`,
  `.hiero-audit/cigar/efficacy/workflow-context-paired-v1.json`,
  `docs/cigar-final-verification.md`, `hiero_audit_core/cigar_client.py`,
  `hiero_audit_core/context_compilers.py`, and the exact 0.9.0 source/schema/demo artifacts,
  release manifest, and checksums.

### H91-020 — Freeze architecture decisions before code changes

Create these reviewed documents:

- [x] `docs/adr/ADR-0xxx-incremental-sqlite-state-v5.md` covering typed deltas, checkpoints,
  revision authentication, exact replay, retention, pins, and compaction.
- [x] `docs/adr/ADR-0xxx-v4-v5-distinct-target-migration.md` covering backup, free-space proof,
  migration, activation, rollback, and downgrade rejection.
- [x] `docs/adr/ADR-0xxx-content-equivalence-and-provenance.md` covering grouping, representative
  order, requirement union, dependency closure, citations, and v1 disposition behavior.
- [x] `docs/adr/ADR-0xxx-retrieval-bounds-and-diversity.md` covering top-K derivation, mandatory
  bypass, caps, deterministic diversity, and fail-closed limits.
- [x] `docs/proposals/atomic-context-compilation-vNext.md` covering the future atomic RPC and
  semantic/execution identity split; label it non-selected for 0.9.1.
- [x] A failpoint matrix naming every durable boundary in commit, checkpoint, migration,
  compaction, activation, anchor publication, and recovery.
- [x] A threat model covering corrupt deltas, chain truncation/reordering, rollback, stale preview,
  forged pins, disk exhaustion, path substitution, same-user races, and receipt tampering.

Exit gate:

- [x] Reviewers can trace every handoff requirement to an ADR, implementation phase, test, and
  machine-readable release gate.

## H91-100 — Add measurements before changing persistence

Owned paths include:

- `crates/cigar-store/src/sqlite.rs` and new focused store telemetry types;
- `crates/cigar-daemon/src/telemetry.rs`;
- `crates/cigar-observe/src/lib.rs`;
- `crates/cigar-daemon/src/production_store.rs`;
- `crates/cigar-daemon/src/production_runtime.rs` and bootstrap/lifecycle surfaces;
- `crates/cigar-retrieval/src/{planner,index,executor}.rs`; and
- `crates/cigar-compiler/src/compiler.rs`.

### H91-110 — Repository commit and storage telemetry

- [x] Add a content-free `RepositoryCommitMetrics` result/observer containing monotonic durations
  for lock wait, repository load, residual decode, staged mutation, delta/full encode, catalog-root
  update, SQLite transaction, commit/fsync, and revision-anchor publication.
- [x] Record logical bytes changed, encoded delta bytes, checkpoint bytes when written, main DB/WAL
  growth, revision delta, retained checkpoint/delta counts, and write-amplification ratio.
- [x] Define write amplification as durable bytes added divided by nonzero logical bytes changed;
  separately represent zero-logical-byte receipt-only commits.
- [x] Use closed compiled labels only. Never label by tenant, source, path, task, request, run, job,
  trace, or arbitrary extension.
- [x] Add overflow-safe counters and bounded histograms/summaries; metric overflow must saturate or
  fail content-free, never wrap.
- [x] Extend `DAEMON_METRICS` and exact OpenMetrics catalog tests so undeclared labels or families
  fail.
- [x] Verify telemetry output contains no source text, prompts, tokens as text, credentials,
  provenance bodies, handoff bodies, private paths, or extensions.

Completion evidence (2026-07-20): `RepositoryCommitMetrics` is wired through all SQLite mutation
paths into the daemon's closed, currently 65-family/256-series catalog. Focused store (69), daemon (169), and
observe (1) unit tests passed offline; focused all-target Clippy passed with warnings denied; the
exact-catalog, saturation, store-observer, phase-execution, and content-canary tests cover this item.

### H91-120 — Startup timing

- [x] Measure path/config verification, SQLite open/configure, migration ledger verification,
  latest checkpoint read, checksum verification, delta replay, residual decode, catalog projection
  recovery/verification, revision-anchor verification, blob reconciliation, and readiness open.
- [x] Emit a single startup total and closed stage counters from monotonic time.
- [x] Keep liveness independent of readiness, but never open readiness until latest state,
  projections required for service, and anchors are authenticated.
- [x] Add tests proving an unavailable or corrupt stage keeps readiness closed and reports only a
  stable content-free reason.

Completion evidence (2026-07-20): local production startup now reports the ten authenticated SQLite
stages plus the terminal readiness transition into the closed, currently 65-family/256-series catalog. Corrupt
residual checksum and invalid durable-cursor tests fail closed, keep readiness closed, and expose
only closed stage/outcome labels. Focused store (71), daemon (169), and observe (1) tests and focused
all-target Clippy passed offline with warnings denied.

### H91-130 — Retrieval and compilation measurements

- [x] Count candidates before governance, after governance, after lineage/logical coalescing, after
  content-equivalence grouping, and after budget selection.
- [x] Count selected blocks, unique content keys, unique source versions, unique lineages,
  `budget_displaced` dispositions, mandatory candidates, and blocking requirements satisfied.
- [x] Extend compile phase timing only with closed phases; preserve the existing seven-phase series
  or version its label domain deliberately.
- [x] Record cache hit/miss/bypass for retrieval, plan, bundle, and materialization with closed
  reason codes such as policy mismatch, watermark mismatch, tokenizer mismatch, materializer
  mismatch, unknown semantic extension, and absent entry.

Completion evidence (2026-07-20): successful compilations now publish five candidate-reduction
checkpoints and seven selected/uniqueness/displacement/requirement counts. The original seven compile
phases remain unchanged. Four fixed cache-layer families share eight closed hit/miss/bypass reasons;
uncached layers report `not_configured` (or semantic-extension bypass), while materialization reports
validated hits and typed miss causes. The exact catalog remains capped at 256 series. Daemon (169)
and observe (1) tests and focused all-target Clippy passed offline with warnings denied.

### H91-140 — Baseline harness

- [x] Add a deterministic content-safe harness under `benches/honey-efficiency/` or an equivalent
  reviewed location.
- [x] Support generated small, threshold, and Hiero-shaped stores plus a separately selected
  verified-copy input.
- [x] Measure each stage and DB/WAL size without using `VACUUM` or deleting live rows.
- [x] Persist raw observations and a summary in distinct owner-only files; reports contain IDs,
  counts, sizes, timings, digests, and outcomes but no protected content.
- [x] Reproduce the 0.9.0 behavior before implementing v5 and bind that report as the before side of
  the final comparison.

Exit gate:

- [x] A candidate-bound-compatible baseline report attributes latency and bytes to named stages and
  reproduces snapshot growth without exposing content.

Completion evidence (2026-07-20): `benches/honey-efficiency/` now contains a standalone Rust
driver, three frozen generated profiles, verified-copy authentication/copy support, a fail-closed
Python runner/verifier, documentation, and five unit tests. The generated small baseline completed
48/48 serial commits and reproduced v4 full-snapshot encoding on every commit (zero delta/checkpoint
bytes), 593,280 bytes of WAL growth, 12,360 durable bytes per 118 logical bytes changed, and a
104.745762x measured write-amplification ratio. Raw observations, summary, and baseline manifest
were written as distinct mode-0400 files beneath a mode-0700 external directory and independently
verified. Their SHA-256 digests are bound in
`docs/release/honey-0.9.1/baseline-v4-evidence.md`. Driver release Clippy passed offline with
warnings denied; harness unit tests passed 5/5.

## H91-200 — Replace v4 full snapshots with bounded v5 incremental persistence

### H91-210 — Define canonical v5 records

Implement a normalized-record plus typed-delta/checkpoint design unless the ADR records stronger
benchmark evidence for content-addressed chunked state.

- [x] Add a fresh-target-only schema migration such as
  `crates/cigar-store/migrations/sqlite/0005_incremental_repository_state.sql`; never run it as an
  in-place v4 data rewrite.
- [x] Isolate canonical delta/checkpoint and migration logic in focused modules rather than adding
  another monolithic path to `sqlite.rs`; proposed locations are
  `crates/cigar-store/src/revision_delta.rs` and `crates/cigar-store/src/migrate_v5.rs`.
- [x] Add a v5 checkpoint table containing revision, format version, canonical state,
  state checksum, semantic root, catalog root, logical totals, and authenticated chain head.
- [x] Add a v5 delta table containing revision, parent revision, canonical typed delta, delta
  checksum, resulting state checksum, semantic root, catalog root, logical totals, and chain head.
- [x] Add a retention-pin table containing exact revision/range, bounded reason code, authority,
  policy identity, creation, expiry, and signature/verification material.
- [x] Add compaction-plan/receipt state only if it cannot be reconstructed safely from signed
  external receipts; never mix it with blob-GC authority.
- [x] Encode deltas with a strict versioned Rust type and canonical CBOR. Do not use unconstrained
  JSON Patch, SQL text, serialized closures, or arbitrary extensions.
- [x] Bound delta operation count, per-record bytes, total delta bytes, checkpoint bytes, chain
  length, and reconstructed state before allocation.
- [x] Domain-separate checkpoint, delta, state, and chain digests.
- [x] Bind each revision to its parent, delta/checkpoint digest, resulting semantic/catalog roots,
  logical totals, and format version.
- [x] Keep the normalized authoritative catalog and catalog roots consistent with reconstructed
  catalog-free state.

Progress evidence (2026-07-20): the unregistered fresh-target SQL defines revision envelopes,
checkpoints, deltas, signed retention pins, composite root/total/chain foreign keys, and no mixed
compaction/blob-GC state. `revision_delta.rs` implements exact-map canonical CBOR, ten closed typed
residual mutation variants, strict re-encoding, 4,096-operation/16 MiB-record/64 MiB-delta/256 MiB
checkpoint bounds, 256-delta/256 MiB replay bounds, overflow rejection, and four domain-separated
digests. `migrate_v5.rs` prepares only an empty distinct target and writes the immutable sequence-5
ledger row; it rejects a live v4 source without creating v5 tables. The v5 commit engine recomputes
the exact canonical atom/edge mutation commitment from rows published at the result revision,
rejects any mismatch, and binds the resulting live catalog root/totals into the same revision and
chain-head transaction. Seventeen focused record, migration, and engine tests pass; all-target store
Clippy passes offline with warnings denied.

### H91-220 — Commit protocol

- [x] Refactor staged mutations into a deterministic `RepositoryDeltaV5` before opening the final
  SQLite transaction.
- [x] Within one `synchronous=FULL` transaction, verify expected parent/revision, apply changed
  normalized rows, append the delta or checkpoint, update roots/totals, and commit.
- [x] Publish the external revision anchor only after SQLite commit; preserve ambiguous-outcome
  recovery by authenticating the committed chain on reopen.
- [x] Make request-bound idempotency return the prior receipt without writing a duplicate delta.
- [x] Make a no-op semantic mutation produce at most the required execution/idempotency receipt,
  not a rewritten state.
- [~] Trigger a full checkpoint on both a maximum delta-chain count and accumulated-delta-byte
  threshold relative to the prior checkpoint. Freeze exact defaults in the ADR after generated and
  verified-copy benchmarks; an interval-only policy is forbidden.
- [x] Preserve exact `SnapshotSelection::Revision` reconstruction for every retained revision.
- [x] Keep `MAX_RETAINED_SQLITE_SNAPSHOTS` only as a v4 compatibility bound; do not reuse a
  count-only bound as the v5 retention policy.

Progress evidence (2026-07-20): deterministic builders transform validated repository staging,
service results, worker transitions, request idempotency, and normalized catalog mutations into the
closed `RepositoryDeltaV5` model. `PreparedRepositoryDeltaV5` canonicalizes, bounds, and digests the
record before the final transaction. The isolated fresh-target `sqlite_v5` engine verifies
`synchronous=FULL`, the exact authority/parent/head, applies normalized-row work through the same
transaction, selects a delta or a count/byte-triggered checkpoint, binds live catalog roots/totals,
updates authority with compare-and-set, and commits. Matching idempotency returns the prior replayed
receipt without invoking the write closure or adding a revision. Anchor publication happens only
after SQLite commit; a simulated publication failure leaves a complete reconstructable revision,
and reopen authenticates that chain before advancing a missing/stale anchor while rejecting an
anchor ahead of authority. Bounded reconstruction authenticates the newest checkpoint and every
consecutive delta through an exact `SnapshotSelection::Revision` (or current authority for
`SnapshotSelection::Latest`); corruption, wrong parents, and rollback fail
closed. Nine focused engine tests cover activation, atomic commit, rollback, exact revision replay,
both checkpoint triggers, idempotent replay without a new full state, anchor ambiguity, catalog
commitment matching, and corruption. The engine remains
isolated from ordinary `SqliteStore::open`, so benchmark-frozen checkpoint defaults stay partial.
Full store (89), daemon (169), observe (1), and harness (5) tests pass; focused all-target Clippy
passes offline with warnings denied.

### H91-230 — Retention policy

- [~] Define configurable maximum retained count, maximum age, maximum physical retained bytes,
  minimum verified replay window, checkpoint cadence, and delta-byte threshold.
- [x] Validate configuration as one coherent policy; reject unsafe zero/unbounded values and byte
  ceilings incompatible with the selected capacity profile.
- [x] Preserve legal-hold, replay, backup, and explicit revision pins even when ordinary retention
  expires.
- [x] Fail writes or maintenance safely when pins and minimums make the configured byte ceiling
  impossible; never silently delete pinned history.
- [x] Expose content-free effective policy and reconstructable revision range through existing
  authenticated diagnostics without changing the v1 operation registry.

Progress evidence (2026-07-20): the v5 authority now authenticates one policy containing maximum
retained revisions, maximum age, maximum physical retained bytes, minimum reconstructable and
verified replay windows, checkpoint count/byte thresholds, and per-record bounds. Validation rejects
zero values, values above closed hard limits, noncanonical age encoding, replay/count inconsistencies,
insufficient checkpoint/WAL headroom, and a retained-byte ceiling beyond the selected 4 GiB standard
or 64 GiB large-local capacity. Active legal-hold/replay/backup/explicit pins are validated against
retained revisions, an authenticated chain head, the effective policy, bounded signature metadata,
and canonical times; their earliest range conservatively extends the minimum replay-protected
window until explicit release. Every commit recomputes authenticated retention statistics before
SQLite commit and returns `LimitExceeded` with full rollback if protected payload/headroom or logical
database pages exceed the physical ceiling. `SqliteStore::v5_retention_statistics_at` exposes only
policy, roots, ranges, counts, byte totals, pin reason counts, and capacity state through a secure
read-only path without adding an operation. Eleven focused engine tests include active/released pin
behavior and a 71 MB forced-capacity refusal with no new revision. Operator configuration wiring is
the remaining partial item.

### H91-240 — Store correctness tests

- [x] Extend reusable repository conformance to run against memory, v4 compatibility fixtures, and
  v5 SQLite.
- [x] Property-test arbitrary valid mutation sequences: reconstructing each retained revision must
  equal the canonical state and roots recorded at original commit.
- [x] Property-test permutation/canonicalization, delta compose/apply, duplicate application,
  missing parent, wrong parent, corrupt checksum, reordered chain, truncated chain, and oversized
  input.
- [x] Add failpoint process-kill tests before/after delta insert, checkpoint insert, root update,
  commit, fsync return, and anchor publication.
- [x] Require recovery to return either the prior authenticated revision or the complete committed
  revision, never a hybrid.
- [x] Keep `PRAGMA synchronous=FULL`, defensive mode, secure path identity, and owner-only mode
  assertions in every new test profile.

Exit gate:

- [x] Ten thousand representative mutations do not create ten thousand complete residual-state
  copies, and every retained revision remains exactly reconstructable.

Progress evidence (2026-07-20): the existing 21-method/19-invariant black-box repository
conformance suite now runs unchanged against memory, v4 SQLite, and an isolated fresh-target v5
SQLite adapter. The v5 path uses typed prepared deltas, normalized catalog rows in the same SQLite
transaction, encrypted external blob publication before metadata visibility, exact historical
reads, request-bound replay, concurrent optimistic writers, and an abort failpoint that remains
armed until a write passes semantic validation. Generated sequence tests vary count/byte checkpoint
thresholds and mixed residual/catalog mutations, capture original canonical state and authenticated
roots, then reconstruct every revision exactly. A second adversarial corpus covers 128 catalog
permutations, canonical round trips, sequential delta application, duplicate/wrong-parent
application, missing envelopes, reordered/truncated/corrupt chains, and oversized operation arrays.
A 12-boundary child-process abort matrix kills the writer before/after delta insert, checkpoint
insert, root update, SQLite commit/FULL-fsync return, and anchor publication; authenticated recovery
returns only revision 0 or the complete revision 1. Every v5 test connection asserts FULL
durability, foreign keys, SQLite defensive mode, stable secure file identity, and owner-only paths.
The explicit 10,000-mutation gate passed in 596.71 seconds with 10,001 revision envelopes, 9,962
deltas, 39 checkpoints including genesis, one unchanged v4 compatibility snapshot, and exact
structural reconstruction plus original root evidence for all 10,001 revisions. The routine store
suite passes offline (97 passed, 0 failed, 2 explicit qualification helpers ignored), and
all-target store Clippy passes offline with warnings denied.

## H91-300 — Migration, compaction, startup, and deep verification

### H91-310 — Distinct-target v4-to-v5 migration

- [x] Do not attach a destructive v4 rewrite to ordinary `SqliteStore::open` migrations.
- [x] Add an explicit offline local migration command/workflow that requires source, backup, and
  new target paths to be absolute, canonical, owner-controlled, non-overlapping, and link-free.
- [x] Require exclusive daemon shutdown/lock, verified backup identity, source revision freeze, and
  preflight free space before copying data.
- [x] Verify every retained v4 `residual_checksum`, semantic root, catalog root, and logical total
  before constructing v5.
- [x] Reconstruct the retained v4 revision sequence into v5 checkpoints/deltas without changing
  revision numbers or public semantic roots.
- [x] Run SQLite integrity, v5 chain verification, random/boundary exact-revision reconstruction,
  catalog projection verification, external blob verification, and effect-chain verification on
  the target.
- [x] Emit a signed canonical migration receipt binding source DB device/inode/size/digest,
  revision range, backup manifest/digest, target format and DB identity, source/target roots,
  tool/product version, failpoint-free completion, and post-verification status.
- [x] Define and generate
  `schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json`, add canonical valid/invalid vectors,
  and bind its digest into the migration authority.
- [x] Activate only by atomically replacing an owner-controlled, checksum-protected active-store
  descriptor or directory name. Do not activate through an unchecked symlink.
- [x] Retain v4 until a separate approved retention action; do not delete it during activation.
- [x] Block in-place downgrade. Restore old versions only into a distinct empty target.

Progress evidence (2026-07-20): v5 remains unreachable from ordinary `SqliteStore::open`.
`cigar migration preflight` accepts exactly one canonical source, signed verified-backup directory,
and absent distinct target; rejects links, overlap, unsafe ownership/modes, source/backup drift, and
insufficient checked free space; hashes a stable source file identity; and creates no target. Every
retained v4 residual and catalog revision is decoded and authenticated against its checksum,
semantic/catalog roots, and logical totals. Normal stores now hold a secure adjacent shared runtime
lock, while successful preflight holds the exclusive lock through its result lifetime; a live store
is proven to reject preflight with `RevisionConflict`. `cigar migration run ... --yes` now consumes
that preflight, creates a mode-0600 distinct target, takes a consistent SQLite copy, constructs one
authenticated migration checkpoint per retained revision, preserves revision numbers and public
semantic/catalog roots, retains exactly one v4 head compatibility row, and removes older redundant
v4 snapshots before compacting only the target. The verifier checks SQLite integrity, every v5
envelope/checkpoint/chain and exact reconstruction, every historical catalog root and total, the
latest catalog/FTS projection, residual effect journals and blob references, the cryptographically
verified backup blob set, and the effect checkpoint directly against the completed target. A
1,028-commit qualification proves the pruned range 5--1,028 migrates as 1,024 consecutive v5
revisions while the v4 source remains usable and the v5 target rejects the old open path. The run
then emits and self-verifies an Ed25519 operator receipt binding source and target filesystem/byte
identity, exact retained range, backup inventory and manifest digests, roots, v5 chain head,
tool/product version, and closed verification outcomes. The strict public JSON Schema is registered
in `schemas/generated-manifest.json`; its raw digest is authenticated by `repository_authority_v5`,
and the full structural vector set plus live sign/verify/tamper tests pass. Activation is still
pending the checksum-protected active-store descriptor and v5 runtime-open work; no run deletes v4,
and the sequence-5 ledger causes the old `SqliteStore::open` path to fail closed. The separate
`cigar migration activate ... --yes` surface now reacquires exclusive source and target runtime
locks, reauthenticates the exact retained source, signed backup and receipt, target byte identity,
v5 revision chain, roots, projection, and revision anchor, then publishes a generation-numbered
owner-only descriptor with a domain-separated payload checksum using create-new temporary-file,
file fsync, atomic rename, and parent-directory fsync. It reads the descriptor back without
following links and repeats a read-only full v5 verification through the selected target before
reporting activation. First publication and second-generation replacement pass; neither path
deletes or mutates v4 or its verified backup. H91-310 is complete.

### H91-320 — Migration failpoints

- [x] Inject failures after backup verification, target creation, each checkpoint/delta batch,
  target fsync, deep verification, receipt publication, activation intent, activation switch, and
  anchor publication.
- [x] Rerun each interrupted case and prove idempotent resume or explicit safe cleanup of only the
  incomplete target.
- [x] Prove no failpoint mutates v4, its verified backup, or the retained evidence copy.
- [~] Start with generated fixtures, then a generated 50 GB-equivalent logical workload, then a
  verified copy. The retained Hiero evidence store remains untouched.

Progress evidence (2026-07-20): the fault-injection feature now arms process aborts in the real
workflow after signed-backup verification, create-new target publication, every retained revision
batch, final deep verification, target and anchor fsync/publication, signed receipt publication,
activation intent, and descriptor rename. A generated three-revision subprocess campaign executes
all 11 boundaries. Before each kill it freezes exact source database, revision-anchor, and recursive
backup-tree digests. Every parent recovery proves those bytes and SQLite integrity unchanged.
Pre-receipt outcomes use `cigar migration cleanup ... --yes`, which reauthenticates source/backup,
rejects a signed or active target, removes only the closed target/WAL/SHM/journal/anchor/runtime-lock
set, fsyncs the parent, and rechecks source bytes; a fresh run then activates successfully.
Post-receipt outcomes reuse the signed evidence, and a post-rename kill reopens a complete generation
one descriptor before safely publishing generation two. The small matrix passed in 16.85 seconds.
A second generated fixture publishes 50 independently governed 1 GiB blob references and requires
the authenticated catalog total to remain exactly 53,687,091,200 bytes across nine representative
migration/receipt/activation kills; its cleanup/resume campaign passed in 17.91 seconds. Only the
authorized disposable verified-copy run remains pending; the retained approximately 50 GB Hiero
evidence store has not been opened or modified.

### H91-330 — Signed revision compaction

- [x] Add preview, execute, and status as local offline administration surfaces without adding v1
  service operations.
- [x] Preview must bind exact head revision, policy digest, backup proof, pins/holds, candidate
  checkpoints/deltas, retained range, estimated bytes, and expiry.
- [x] Execute must require the exact signed preview, reject head/policy/backup/pin drift and active
  writers, and emit a separate signed receipt.
- [x] Preserve enough checkpoints/deltas to reconstruct every retained and pinned revision.
- [x] Recover interruption before, during, and after physical reclamation without losing the last
  authenticated state.
- [x] Keep revision compaction and blob GC commands, policies, candidates, and receipts distinct.

Progress evidence (2026-07-20): `cigar compaction preview`, `execute`, and `status` are distinct
local-only commands. The expiring Ed25519 preview binds the active descriptor generation/checksum,
exact source identity and bytes, migration/backup proof, head and chain, retention policy and pin
set, candidate checkpoint/delta range, retained range, estimated reclaimable bytes, and distinct
target. Execution reacquires exclusive source/target locks, rejects all bound drift, copies into a
new target, reclaims only the authorized prefix, verifies SQLite plus every retained revision, and
publishes a purpose-separated signed compaction receipt before atomically advancing the active
descriptor. The compaction-origin record preserves the original chain boundary without weakening
historical chain authentication. A 1,024-revision workflow compacted revisions 5--1,028 to the
exact retained range 773--1,028 (256 revisions) with the chain head unchanged; an active pin
prevents its protected revision from entering a preview. A seven-boundary real-process abort
campaign covers preview verification, durable copy, logical reclamation, physical reclamation,
receipt publication, activation intent, and descriptor switch. Every case resumed the same signed
operation successfully in 39.49 seconds, retained the original migrated source and v4/backup
evidence byte-for-byte, and left receipt-authenticated target bytes unchanged on post-receipt
retries. Revision compaction has separate paths, schemas, signatures, receipts, and CLI surfaces
from blob GC. H91-330 is complete.

### H91-340 — Bounded startup and deep checks

- [x] Startup authenticates the latest checkpoint plus only the bounded delta suffix required for
  readiness.
- [x] Projection recovery starts from the authenticated latest state and does not iterate all
  historical states.
- [x] Ordinary readiness does not perform forced full retained-history verification.
- [x] Add an explicit deep-integrity mode that authenticates every retained checkpoint/delta and
  offers `--force-full`.
- [x] Add a signed verified-prefix record so later incremental deep checks can start after an
  unchanged authenticated prefix.
- [x] Invalidate the prefix when any bound DB identity, chain head, verifier version, or policy
  digest changes.
- [x] Prove clean and crash recovery reach ready within 30 seconds at the retention ceiling.

Progress evidence (2026-07-20): the v5 readiness path loads the current authority, selects only the
latest checkpoint, bounds the consecutive delta count/bytes/operations by the authenticated policy,
reconstructs the head, and verifies the current normalized catalog/projection. Projection recovery
first authenticates that same bounded latest state, rebuilds one immutable generation from current
normalized rows, atomically activates it, and repeats bounded verification; neither path scans old
payloads. In a generated store configured at its 301-revision retained-count ceiling, clean
readiness took 8 ms and recovery from a deleted projection activation took 16 ms in the debug test
profile, using checkpoint 257 plus 43 deltas. Both succeeded with an intentionally corrupted
revision-0 checkpoint, while explicit deep verification rejected that corruption. The local
`cigar integrity deep <v5-database> --yes` command runs SQLite integrity plus every retained payload
and catalog revision not already covered by an unchanged trusted prefix, verifies the current
projection, and atomically publishes an owner-only purpose-signed
`.cigar-verified-prefix.json`. The prefix binds database path/device/inode, retained origin,
through-revision and chain head, policy digest, verifier/product version, and completion claims.
Focused tests cover a 301-revision full check, zero-revision unchanged-prefix reuse, a three-revision
incremental suffix, chain drift, signature tampering, and `--force-full` repair. H91-340 is
complete.

Exit gate:

- [~] Generated and verified-copy v4 stores migrate without root/revision drift, interrupted cases
  recover safely, and both clean and crash restarts satisfy the objective.

## H91-400 — Context quality, retrieval bounds, and safe reuse

### H91-410 — Content-equivalence grouping with complete provenance

- [x] Add deterministic grouping after policy/lifecycle/representation eligibility and before
  budget packing, keyed at minimum by `(RepresentationKind, governed content_digest)`.
- [x] Define how candidates with multiple representations enter equivalence classes; do not merge
  candidates merely because one lossy alternative collides while required lossless content differs.
- [x] Select the representative using existing stable `candidate_order` plus version ID as final
  tie-breaker.
- [x] Union requirement indices, mandatory status, dependencies, version IDs, provenance digests,
  and citation aliases across the class before satisfying mandatory/blocking requirements.
- [x] Reject or keep separate members whose lane, policy outcome, authority requirements,
  transform receipt, or dependency semantics cannot be merged safely.
- [x] Charge tokens and item count once for the selected representation.
- [x] Put every equivalent version and dependency chain in the emitted `ContextBlock.provenance` in
  canonical order.
- [x] Resolve citations for every merged version to the selected block while preserving exact
  source/version lineage.
- [x] Compute required-source satisfaction across the complete equivalence class.
- [x] Keep one manifest entry per considered candidate. Mark non-representatives with the existing
  v1-compatible `budget_displaced` reason and internal content-equivalence diagnostics; do not add
  a new v1 enum value.
- [x] Update invalidation registration so a change to any member invalidates the selected block.
- [x] Property-test input permutation, representative ties, mandatory/nonmandatory mixtures,
  dependencies, claims, citations, and transform-receipt mismatches.

Progress evidence (2026-07-20): the compiler now builds deterministic protected equivalence classes
after lifecycle/logical/claim reconciliation and before mandatory closure. Honey 0.9.1 conservatively
requires the complete eligible representation set to match, including kind, governed digest, token
count, loss, and receipt, and also binds lane, policy, classification, instruction authority, and
claim semantics. It unions mandatory/requirement/entity/dependency obligations into the stable
`candidate_order` representative, splits direct member dependency classes, and falls back to the
original singleton graph if contraction would introduce a cycle. One selected block/item/token
charge carries canonical member and dependency provenance; every original manifest entry and
provenance digest remains, non-representatives use `budget_displaced`, and protected citation
resolution preserves the cited member identity. Invalidation and retained-daemon reauthorization now
cover every represented member rather than only plan representatives, while content-free telemetry
counts classes, unique `(kind, digest)` keys, source versions, lineages, and blocking coverage from
the complete class. The compiler-profile digest domain was advanced so pre-0.9.1 artifacts cannot be
reused under the changed semantics. Focused coverage exhausts all 24 four-candidate permutations and
tests representative ties, mixed mandatory/blocking sources, unioned dependency chains, citations,
claims, lossy collisions, lane/policy/classification/authority/receipt mismatches, redacted markers,
and unsafe dependency contraction. All 34 compiler unit/integration tests, nine catalog-context daemon
tests, and warnings-denied all-target Clippy for compiler and daemon pass offline. H91-410 is complete.

### H91-420 — Requirement-aware bounded retrieval

- [x] Derive per-requirement and per-lane candidate budgets from requested tokens, compiler lane
  limits, configured minimum evidence, and a bounded oversubscription factor.
- [x] Preserve exact, mandatory, policy, dependency, and higher-authority candidates outside
  ordinary top-K competition, while keeping a hard global safety bound.
- [x] Coalesce aliases resolving to the same governed version/content before compiler submission.
- [x] Apply deterministic per-source, per-lineage, and per-content-family caps.
- [x] Add a deterministic diversity stage such as quantized maximal marginal relevance; its
  similarity and tie-break rules must use content-free metadata and cannot displace mandatory
  evidence.
- [x] Apply governance before diversity and before any candidate identity is disclosed.
- [x] Preserve cancellation, revision pinning, partition isolation, and exact-query behavior.
- [x] Add adversarial tests for one-source flooding, alias flooding, duplicate content, mandatory
  evidence below ordinary rank, cross-tenant lineages, and score ties.
- [x] Target fewer than ten `budget_displaced` candidates for every selected block on the frozen
  Hiero-shaped cohort.

Progress evidence (2026-07-20): context compilation now uses a fingerprinted bounded query plan
whose per-requirement/per-lane allowances derive from exact lane tokens, compiler item maxima/minima,
and a frozen oversubscription profile. Authorized stage results are same-version/content coalesced,
source/lineage/content capped, and selected with checked integer MMR-style penalties before content
loading. Exact, blocking, policy, and project/system-authority candidates receive protected stage
headroom and bypass ordinary caps; dependency expansion bypasses competition but shares the 512-item
absolute compiler ceiling. Every bound and diversity constant is in the v2 retrieval-plan digest.
Generated tests cover stage/result permutations, equal-score ties, source and alias floods, duplicate
content, low-ranked exact/policy evidence, protected-limit failure, cancellation and plan drift; the
existing tenant-lineage isolation suite remains green. A fixed 100-request Hiero-shaped synthetic
cohort admits at most eight candidates per conservatively assumed selected block, keeping the
worst-case displaced:selected ratio below 10:1. All 56 retrieval unit tests, three public channel
qualification tests, nine daemon catalog-context tests, and warnings-denied all-target Clippy pass
offline. H91-420 is complete.

### H91-430 — Reuse without changing v1 semantics

- [x] Do not change the existing v1 `contract_digest` to ignore arbitrary extensions; that would
  reinterpret frozen semantic identity.
- [x] Document and test that execution-only run/job/trace correlation belongs in execution
  receipts/transport metadata, not `ContextContract.extensions` or caller idempotency material.
- [x] Add SDK/downstream examples for constructing a stable semantic request key from normalized
  need, catalog watermark, authorization/disclosure domain, policy, target, tokenizer,
  materializer, and compiler version.
- [x] Bind every execution receipt to the reused/new artifact digest and its unique correlation.
- [x] Require exact authorization, disclosure, policy, watermark, tokenizer, materializer, and
  compiler matches before reuse.
- [x] Bypass reuse on unknown semantic extensions or uncertain authority rather than guessing.
- [x] Emit only content-free hit/miss/bypass reasons.

Progress evidence (2026-07-20): the Rust SDK now exposes a domain-separated downstream semantic key
whose input type contains all nine semantic/governance/component pins and cannot accept execution
correlation or mutation idempotency. Reuse requires an authenticated stored key plus exact pin
equality; unknown extensions and uncertain authority return closed bypass decisions, and miss or
bypass results disclose no candidate key or artifact digest. A separately domain-separated
execution commitment binds the stable key, exact generated/reused artifact digest, fresh UUIDv7 and
trace correlation, optional protected run/job digests, outcome, and closed reason. The helper is
explicitly an unsigned downstream compatibility value, not a new v1 operation or the future signed
receipt. The compiler regression proves that changing an arbitrary current v1 extension still
changes `contract_digest`. Six SDK vectors cover all pin changes/mismatches, absent/bypass paths,
content-free labels, correlation and artifact binding, and invalid receipt claims. The complete
remote-only SDK suite and warnings-denied all-target Clippy pass; the focused compiler regression and
compiler all-target Clippy also pass. The frozen-cohort exit gate remains assigned to H91-640.

Exit gate:

- [ ] The frozen cohort meets duplicate-content, diversity, displacement, citation, and
  required-source objectives without changing the v1 registry or weakening policy.

## H91-500 — Design the next protocol without smuggling it into 0.9.1

These are required design deliverables but not selected public 0.9.1 operations.

### H91-510 — Atomic context compilation proposal

- [x] Specify one mutation accepting normalized governed contract, target/materialization profile,
  validation policy, and one idempotency identity.
- [x] Specify one transaction that plans, compiles, seals bundle/manifest, materializes, and
  revalidates.
- [x] Specify response records for plan, bundle, manifest, materialization, revalidation, revision,
  parent receipt, and deterministic child receipts.
- [x] Specify reconciliation by idempotency identity after ambiguous transport outcomes.
- [x] Preserve granular v1 operations for compatibility and diagnostics.
- [x] Model commit-count and cache-hit expectations: at most one repository commit on miss and no
  artifact rewrite on valid hit, while still recording the execution receipt.

### H91-520 — Semantic/execution identity proposal

- [x] Define the canonical semantic compilation identity and explicit excluded correlation fields.
- [x] Define a signed execution receipt binding run/job/trace/time/authority to the semantic
  artifact.
- [x] Define cache reuse, invalidation, bypass, privacy-domain, and unknown-extension rules.
- [x] Include negative vectors for policy, watermark, authorization, tokenizer, materializer,
  compiler, and disclosure mismatches.

### H91-530 — Revision administration proposal

- [x] Specify authenticated preview/execute/status operations and stable errors for missing backup,
  legal hold, insufficient space, active writer, revision drift, and failed post-verification.
- [x] Specify diagnostics for effective retention count/age/bytes, pins, checkpoint cadence, and
  reconstructable range.
- [x] Identify the future operation/schema version, generator changes, SDK changes, conformance
  cases, and compatibility contract.

Exit gate:

- [x] Release material labels all three proposals future/non-selected, and v1 generator checks still
  prove exactly 45 operations and 70 payloads.

Progress evidence (2026-07-20):
[`atomic-context-compilation-vNext.md`](docs/proposals/atomic-context-compilation-vNext.md) now
specifies the governed request (including validation policy), one transaction, typed artifact and
revalidation result records, deterministic parent/child receipts, idempotency reconciliation, exact
miss/hit commit expectations, semantic/execution identities, mismatch and bypass vectors, and
authenticated revision preview/execute/status behavior with closed errors and diagnostics. The
release disposition labels atomic compilation, semantic/signed execution identity, and revision
administration future/non-selected. No v1 operation or payload was added. The reviewed development
baseline was reconciled only for the already-generated internal v4-to-v5 migration-receipt schema;
its semantic registry still proves exactly 45 operations and 70 nominal payloads. All ten baseline
authority tests, the non-mutating baseline check, and all six typed payload contract tests pass.

## H91-600 — Build the efficiency and reliability qualification

### H91-610 — Frozen fixtures and report schema

- [x] Create generated small, boundary, and Hiero-shaped fixtures with fixed seeds and digests.
- [x] Create a verified-copy input descriptor that names only content-free store identity and
  digest; never package private Hiero data.
- [x] Freeze workload order, warmups, repetitions, concurrency, retention policy, capacity profile,
  hardware identity, filesystem, and power conditions before the candidate run.
- [x] Add a strict machine-readable qualification schema and validator.
- [x] Record raw-observation attachment SHA-256, not raw protected content, in the summary.
- [x] Make every mandatory gate `pass` or fail the candidate; `skipped`, `waived`, `unknown`, or
  absent is not pass.

Progress evidence (2026-07-20):
`benches/honey-efficiency/qualification-fixtures.v1.json` freezes three canonical generator recipes,
nonzero seeds and recipe digests, exact workload order, five warmups, one 100-request serial cohort,
10,000 serial mutations, a 4-by-2,500 mixed-concurrency cohort, standard v5 retention/capacity, and
the M3 Ultra/macOS arm64/APFS/AC-power/no-network conditions. The repository verified-copy
descriptor is content-free, unbound, and non-executable; an external bound form permits only store
and copy-receipt digests, bytes, and source revision after generated gates pass. The strict report
schema and `honey_efficiency_contract.py` authenticate source/tree, candidate and installed bytes,
fixture/profile/schema authorities, tool/environment identity, frozen execution, stage metrics,
all 23 gates, five workflows, and a separate raw-observation SHA-256/byte binding. Status is
recomputed from typed thresholds; absent, duplicate, skipped, waived, unknown, unevaluated, or
misstated results fail validation. Six authority/report negative and positive tests pass, as does
the non-mutating authority check.

### H91-620 — Persistence and recovery gates

- [x] Every retained v4 revision migrated to v5 has the same revision, state checksum, semantic
  root, and catalog root.
- [x] Boundary plus deterministic random v5 revisions reconstruct identically from checkpoint plus
  deltas.
- [x] Every failpoint recovers to prior or committed revision, never a hybrid.
- [x] Backup/create/verify, distinct-target restore, and downgrade rejection pass.
- [x] Compaction preserves pins and rejects preview/head/policy drift.
- [x] Forced deep verification authenticates every retained checkpoint/delta and external bound
  record.

Progress evidence (2026-07-20): the complete `cigar-store` suite passes 102 unit tests plus all
enabled integration tests. It covers a pruned 1,024-revision v4 range through signed backup,
distinct-target v5 migration, revision/root equality, activation, signed compaction to the protected
256-revision range, exact reconstruction, downgrade rejection, pin/hold protection, and forced full
deep verification of retained history and bound migration/compaction authority records. Generated
mutation permutations reconstruct every state/root, corrupt/reordered/truncated chains fail closed,
and the in-process commit matrix never publishes a hybrid. The release-only
`migration-fault-injection` suite also passes all five top-level tests: every named migration and
compaction durable boundary resumes exactly, including the logical 50-GiB generated campaign. The
separate 10,000-mutation performance campaign remains deliberately ignored here and is executed in
H91-630.

### H91-630 — Scale and latency gates

- [x] Run at least 10,000 representative serial mutations and a separate mixed-concurrency soak.
- [ ] Measure steady-state physical growth as `(final main+WAL bytes - initial main+WAL bytes) /
  completed context compilations` after the same bounded checkpoint procedure; require less than
  1 MiB per Hiero-sized compilation.
- [ ] Run the frozen 100-request serial cohort. Compute an OLS latency slope and a deterministic
  moving-block bootstrap 95% interval over request order; require the point estimate and upper
  interval bound to be at most 10 ms/request.
- [ ] Require context compile p95 below 10 seconds or no more than two times the paired local p95,
  using the stricter applicable objective recorded before execution.
- [ ] Require clean and crash-recovery readiness within 30 seconds at the configured retention
  ceiling.
- [x] Require bounded checkpoint/delta chain length and byte size at the end of the 10,000-mutation
  campaign.
- [ ] Record commit count per existing granular operation. Do not claim the future one-commit atomic
  RPC gate for 0.9.1.

Progress evidence (2026-07-20): the ignored exact source qualification tests both pass. The serial
campaign committed 10,000 representative mutations and reconstructed all 10,001 revisions with
their original state, semantic, catalog, and chain evidence in 597.96 seconds. The independent
4-by-2,500 mixed-concurrency campaign committed all 10,000 uniquely identified mutations after
26,880 revision-conflict reconciliations, then passed exact head reconstruction, retention
statistics, startup recovery, and bounded readiness in 1,537.23 seconds. It retained 39 checkpoints
and 9,962 deltas (26,109,562 checkpoint bytes and 12,116,835 delta bytes); readiness replayed only
the final 234 deltas totaling 284,661 bytes, within the authenticated 256-delta/268,435,456-byte
policy. These are generated source correctness/shape results, not installed-byte physical-growth,
latency, timed-readiness, or granular-v1-operation evidence; those gates remain open.

### H91-640 — Context-quality gates

- [ ] Completion is 100% for the 100-request cohort.
- [ ] Duplicate selected content is at most 5%, keyed by representation kind and content digest.
- [ ] Unique selected source/lineage diversity is non-regressive against the paired local context
  for comparable requirements. Freeze the per-request metric as distinct governed lineage IDs
  represented by selected provenance classes, counting content-equivalent members once per
  lineage; require the paired aggregate delta and every workflow delta to be nonnegative.
- [ ] `budget_displaced:selected` is below 10:1 globally and reported per workflow.
- [ ] Citation resolvability is at least 99%.
- [ ] Required-source coverage is 100%.
- [ ] Required, policy, security, provenance, tokenizer, materializer, and budget validation all
  remain fail closed.
- [ ] Report any workflow-specific regression even when the aggregate passes.

### H91-650 — Qualification implementation and evidence integration

- [x] Add owner-private, create-new producer
  `scripts/release/qualify_honey_efficiency.py` and output
  `honey-efficiency-reliability-report.json`; do not append ad hoc output to
  `build_honey_gate_reports.py` without a strict report contract.
- [x] Define schema ID `cigar.honey-efficiency-reliability-qualification.v1` at
  `packaging/honey/schemas/honey-efficiency-reliability-qualification.v1.schema.json`.
- [x] Require the report to contain source commit/tree, candidate-manifest SHA-256, installed
  runtime SHA-256, fixture/raw-observation digests, environment/tool identities, retention policy,
  cohort sizes, stage metrics, gate thresholds, measured values, per-workflow results, and one
  closed overall status.
- [x] Add release-script unit tests for duplicate JSON keys, unsafe paths, missing raw attachment,
  stale source/candidate binding, threshold weakening, NaN/Infinity, empty cohorts, and overwrite.
- [x] Add new mandatory release gates: `storage-format-v5`, `v4-v5-migration`,
  `revision-recovery`, `storage-amplification`, `serial-latency`, `startup-readiness`, and
  `context-quality-efficiency`.
- [x] Add the efficiency/reliability report to `packaging/honey/artifact-matrix.v1.json` as an
  internal input, not a public attachment.
- [x] Add closed evidence ID `efficiency-reliability-report` and extend
  `build_honey_evidence.py` accepted schema, artifact binding,
  capability binding, and gate policy.
- [x] Extend `qualify_honey_release.py` so `qualify` runs the new producer on exact installed bytes
  before the private evidence ledger is assembled.
- [x] Extend non-mutating `verify` to reconstruct and validate every new gate and digest.

Progress evidence (2026-07-20): `qualify_honey_efficiency.py` strictly validates the frozen raw
cohort, computes integer OLS and a deterministic 10,000-resample moving-block bootstrap interval,
derives all scale/context-quality ratios, and writes one create-new owner-private report. The
validator now pins the exact name, operator, unit, and value of every threshold, so a generic pass
boolean or threshold weakening fails. It also rejects duplicate/non-finite JSON, unsafe or stale
source/candidate/runtime bindings, incomplete/empty cohorts, and overwrite. The Honey authority now
contains the seven additional mandatory gates and an internal-only efficiency report; the evidence
ledger binds it to the macOS runtime and release manifest. Installed `qualify` runs the producer
before ledger assembly, while non-mutating `verify` requires the same external raw attachment and
recomputes its digest and every report status. The ledger now also cross-binds the report's
installed `cigar` SHA-256 to the independently validated installed-runtime report, so an
archive-bound but different executable fails closed. Seventeen focused contract/producer tests, all
16 Honey evidence tests, all 15 orchestration tests, authority generation/check, Python
compilation, and diff checks pass. The exit gate remains pending until H91-1000 runs these
mechanics against one clean, installed 0.9.1 candidate and produces the canonical passing report.

Exit gate:

- [ ] One canonical report proves every section 4 gate from the handoff against the exact candidate
  or fails closed with a stable reason.

## H91-700 — Version, authority, documentation, and demos

### H91-710 — Propagate 0.9.1 through closed authority

- [x] Update `packaging/product-version.v1.json` to `0.9.1-honey.1`, target release `0.9.1`, and tag
  `v0.9.1-honey.1`.
- [x] Update `HONEY_TARGET_RELEASE` and all closed version validators in
  `scripts/release/product_version.py`; do not perform repository-wide blind replacement.
- [x] Run `python3 scripts/release/product_version.py generate`, review every changed path, then
  require `check` to be clean and non-mutating.
- [x] Update workspace crates and exact internal dependency pins to `=0.9.1-honey.1`.
- [x] Update TypeScript/Rust/plugin/archive version to `0.9.1-honey.1` and Python distribution
  version to `0.9.1.dev1`.
- [x] Update SDK/crate release records, lockfiles, producer constants, contracts, demos, docs, and
  qualification expected versions through their authorities.
- [x] Preserve beta/history fixtures and the 0.9.0 handoff archive as historical evidence.

Progress evidence (2026-07-20): the closed product authority is now `0.9.1-honey.1` / target
`0.9.1` / tag `v0.9.1-honey.1`. Its generator propagated the exact Rust, TypeScript, plugin,
archive, and `0.9.1.dev1` Python identities through 66 managed files, including internal Cargo
pins, lockfiles, SDK release records, package contracts, demos, and active guides. The generated
storage-migration POC raises the closed inventory to 67 managed files. Generate/check
is deterministic, Cargo metadata resolves offline, and active release consumers contain no stale
0.9.0 Honey filename. Historical beta/0.9.0 plans, the authenticated handoff inputs, and old release
notes remain unchanged as history. The original handoff ZIP remains byte-identical in owner-only
external storage and is represented in source authority only by artifact name, byte length, and
SHA-256.

### H91-720 — Update the Honey profile and requirements

- [x] Keep the same 13 public artifact IDs and update filenames/contracts to 0.9.1.
- [x] Refresh authority SHA-256 bindings only through `honey_profile.py generate` after review.
- [x] Add the seven new mandatory gates and the internal efficiency/reliability evidence input.
- [x] Keep all 0.9.0 mandatory gates; none may be replaced by a performance report.
- [x] Keep prohibited production, support, notarization, cross-platform, and GA claims.
- [x] Keep longevity, full chaos, cross-platform, notarization, and two-builder gates visibly
  deferred; performance/efficiency for this bounded workload is no longer deferred.
- [x] Require `honey_profile.py check`, `development_protocol_baseline.py check`, and client
  generator check to pass without changing the 45/70 v1 inventory.

Progress evidence (2026-07-20): the regenerated Honey authorities retain the same 13 ordered public
artifact IDs, now with exact 0.9.1 filenames, and add only the private efficiency report input.
All 17 prior mandatory gates remain and the seven 0.9.1 gates raise the closed mandatory total to
24. Unsupported/production claims remain false; longevity, chaos, large-scale, notarization, and
two-builder work remains explicitly non-passing/deferred. Honey profile check passes. The reviewed
protocol baseline changed only for the bound product-version digest—its semantic contract remains
identical—and baseline/client checks still prove exactly 45 v1 operations and 70 payload types.

### H91-730 — Exact public attachment set

The candidate contains exactly:

1. `cigar-0.9.1-honey.1-source.tar.gz`.
2. `cigar-0.9.1-honey.1-docs.tar.gz`.
3. `cigar-0.9.1-honey.1-schemas-conformance.tar.gz`.
4. `cigar-0.9.1-honey.1-aarch64-apple-darwin.tar.gz`.
5. `cigar-sdk-0.9.1-honey.1.tgz`.
6. `cigar_sdk-0.9.1.dev1-py3-none-any.whl`.
7. `cigar_sdk-0.9.1.dev1.tar.gz`.
8. `cigar-rust-sdk-0.9.1-honey.1-local-registry.tar.gz`.
9. `cigar-claude-code-0.9.1-honey.1.tar.gz`.
10. `cigar-honey-demos-0.9.1-honey.1.tar.gz`.
11. `RELEASE_NOTES_HONEY_v0.9.1.md`.
12. `honey-release-manifest.json`.
13. `SHA256SUMS`.

- [x] Update local archive manifests, package contracts, artifact matrix, assembler, verifier, docs
  variables, and producer tests to this exact set.
- [x] Reject an old 0.9.0 filename, extra file, missing file, duplicate artifact, or renamed bytes.

Progress evidence (2026-07-20): the regenerated local-archive authority, contracts, matrix,
assembler/verifier constants, guides, and producer expectations name exactly the 13 listed 0.9.1
attachments. Profile generation enforces ordered IDs and filenames, assembly rejects portable
collisions, and public verification reads the exact inventory before validating row order,
filename, size, and digest. A new stale-0.9.0 regression plus Honey profile/assembly (17) and secure
workspace (13) tests pass.

### H91-740 — Documentation and migration UX

- [x] Create `RELEASE_NOTES_HONEY_v0.9.1.md` with findings, storage-format change, expected migration
  duration/free space, backup requirement, activation, rollback, retention, compaction, performance
  evidence, API compatibility, and known limits.
- [x] Update `README_HONEY.md` and install/upgrade/troubleshooting/security guides.
- [x] Document that v4 remains untouched until separately removed and downgrade restores into a
  distinct empty target.
- [x] Document storage statistics and content-free telemetry interpretation.
- [x] Document local compaction preview/execute/status and its backup/legal-hold requirements.
- [x] Document that atomic compilation and retention RPCs are future proposals, not 0.9.1 v1
  operations.
- [x] Register every executable command in `docs/commands.v1.json` or mark it illustrative.
- [x] Add all pages to `docs/site-manifest.v1.json` and run deterministic link/command checks.

Progress evidence (2026-07-20): the 0.9.1 release notes and active Honey guides now cover the v5
repair, preflight space/duration method, distinct-target migration/activation/rollback, retention,
signed compaction preview/execute/status, deep integrity, bounded startup, closed telemetry,
compatibility, and known POC limits. `honey-storage-v5.md` registers every shell block as
illustrative and is a required site page. The non-mutating docs checker passes 69 published pages,
109 links, and 47 classified code blocks with no undeclared executable command.

### H91-750 — Demos and fixtures

- [x] Extend the offline context demo with duplicate-content sources and prove one emitted block
  retains all provenance/citation aliases.
- [x] Add a bounded v4-to-v5 migration demo using generated non-sensitive state and a separate
  backup/target.
- [x] Add a restart-after-migration and deep-integrity step.
- [x] Preserve two-agent authority, effect `UNKNOWN` recovery, no-egress replay, prompt-injection,
  secret-canary, and project nondisclosure assertions.
- [ ] Run each installed demo twice from clean state and compare semantic identities.
- [x] Keep fixtures deterministic, credential-free, network-free, and bounded.

Progress evidence (2026-07-20): the digest-bound offline-context fixture now supplies two governed
versions of one selected representation and requires exactly one emitted block with both provenance
aliases and two resolved explanation/citation identities. Its mapped real compiler equivalence test
passes, and the complete source demo returns `release_demo_qualified=true` under the macOS no-egress
boundary. Honey/demo producer tests (9), manifest validation, fixed seeds, no-egress/credential
claims, and all pre-existing two-agent/effect/replay/injection/canary components remain intact. The
installed projection of the generated v4-to-v5 demo and exact two-run candidate receipt remain
pending.

The source-only `demos/storage-migration/run.py` POC runs the real store workflow twice from clean
generated state. Each pass creates 1,028 v4 revisions, a separate signed and verified backup, a
distinct v5 target, activation and compaction to 256 revisions, a close/reopen bounded-readiness
check, full and prefix-reused deep checks, tamper rejection, and forced repair while preserving the
source and backup. Both clean runs returned the same semantic identity. This closes the generated
migration/restart demo items but deliberately does not close the installed-candidate two-run
receipt. The complete source demo test suite passes 19 tests, including two create-new,
repeat-identity, and offline-environment tests for the storage-migration runner.

Exit gate:

- [ ] One non-mutating authority command set proves version, profile, exact artifact inventory,
  v1 compatibility, docs, and generated clients have zero drift.

## H91-800 — Source, contract, compatibility, and safety gates

Run on the clean intended candidate commit before artifact construction:

- [ ] `cargo fmt --all -- --check`.
- [ ] Strict offline Clippy for the selected full CLI, daemon, MCP, store, compiler, retrieval,
  protocol, API, and all modified targets with `-D warnings`.
- [ ] Focused offline tests for catalog, compiler, policy, store, space, handoff, effects, replay,
  API, daemon, CLI, MCP, and Claude hook.
- [ ] Store v5 unit, property, conformance, migration, failpoint, backup, compaction, and recovery
  suites.
- [ ] Compiler content-equivalence and retrieval-flooding/adversarial suites.
- [ ] Existing 24-case conformance suite and all canonical valid/invalid/differential vectors.
- [ ] `python3 scripts/release/product_version.py check`.
- [ ] `python3 scripts/release/honey_profile.py check`.
- [ ] `python3 scripts/release/development_protocol_baseline.py check`.
- [ ] `python3 sdk/generate_clients.py --check`.
- [ ] Release-script unit tests, including Honey assembly, qualification, evidence, and verifier
  tests.
- [ ] TypeScript, Python, and Rust producer/clean-consumer tests.
- [ ] Policy nondisclosure, effect ambiguity/idempotency, replay no-egress, malformed API/MCP,
  package-negative, and local-admin-loopback tests from the 0.9.0 bounded gate report.
- [ ] New generated-fixture efficiency smoke with thresholds relaxed only for sample size, never
  redefined metrics.
- [ ] `git status --porcelain=v1 --untracked-files=all` is empty after all check modes.

Exit gate:

- [ ] `build_honey_gate_reports.py` and the new efficiency producer pass from the same source tree,
  and no source test is represented as installed-byte proof.

Pre-freeze evidence (2026-07-20; boxes remain open until repeated on a clean candidate commit):
format and diff checks pass; warnings-denied offline all-target Clippy passes for the full CLI,
daemon, MCP, store, compiler, retrieval, protocol, and API selections; the complete focused Rust
command passes catalog/compiler/policy/store/space/effects/replay/API/daemon/MCP, full CLI, and
conformance suites; the four non-mutating authority/client checks pass; documentation checks pass;
the direct source SDK suites pass 23 TypeScript, 21 Python, and 40 Rust tests; and the generated Go
client passes its offline suite under the cached exact Go 1.26.5 toolchain. The complete release-tool
suite passes 411 tests with 31 declared platform skips. A status inventory records 209
intended/historical paths before source reconciliation, so the clean-tree gate is correctly still
open.

## H91-900 — Build and assemble the exact candidate

### H91-910 — Freeze one source commit

- [x] Reconcile intended files and obtain owner direction for any overlap/unrelated work.
- [ ] Commit the complete reviewed source; record commit ID, tree ID, lockfile digests, toolchain
  identities, and commit timestamp.
- [ ] Require a clean tree and no Git replacement objects.
- [ ] Set `SOURCE_DATE_EPOCH` to the exact candidate commit timestamp; reject any other value.
- [ ] Select a create-new owner-only root such as
  `/private/tmp/cigar-honey-0.9.1-honey.1-<candidate-id>`.

Progress evidence (2026-07-20): the release owner authorized all 209 non-ZIP changes as the 0.9.1
source candidate and directed that the historical 0.9.0 handoff archive remain external. The
116,927,188-byte archive was moved intact to owner-only sibling evidence storage, made read-only,
and reauthenticated as
`53f484ae7e2be6a51a0dd613731986bfda926688b0dcff21462a2bdb8da7f421`. The qualification
authority is now path-free and binds only its external artifact name, byte length, and digest;
focused authority/producer tests pass and no unrelated path was deleted or hidden.

### H91-920 — Run the same producer topology as 0.9.0

- [ ] Build portable source/docs/schema-conformance archives.
- [ ] Build the Apple-silicon runtime containing exact `cigar`, `cigard`, `cigar-mcp`, and
  `cigar-claude-hook` bytes.
- [ ] Build the internal conformance/install qualification tool archive.
- [ ] Build TypeScript npm tarball and clean offline consumer.
- [ ] Build Python wheel/sdist and separate clean offline consumers.
- [ ] Build Rust local-registry kit and clean external consumer.
- [ ] Build Claude plugin from exact runtime MCP/hook bytes.
- [ ] Build the exact Honey demo archive.
- [ ] Verify every producer receipt, package contract, source binding, authority digest, target,
  version, ABI, inventory, mode, and checksum.

Preferred orchestrator command after source freeze:

```sh
candidate_epoch=$(git show -s --format=%ct HEAD)
python3 scripts/release/qualify_honey_release.py \
  --evidence-root /private/tmp/cigar-honey-0.9.1-honey.1-candidate \
  --source-date-epoch "$candidate_epoch" \
  build
```

- [ ] Confirm the orchestrator creates exactly 13 public candidate attachments and reports only
  `built-unqualified`.
- [ ] Run `verify_honey_release.py` independently against the candidate; require
  `passed-artifact-integrity`.
- [ ] Prove source commit/tree did not change during any producer or assembly step.

Exit gate:

- [ ] One immutable candidate directory contains exactly the selected 0.9.1 attachments and passes
  independent offline artifact verification without claiming installed qualification.

## H91-1000 — Qualify exact installed bytes

### H91-1010 — Required environment

- [ ] Use a disposable dedicated standard non-admin Apple-silicon macOS account/VM.
- [ ] Enforce no egress outside the process before setting `CIGAR_NO_EGRESS_ENFORCED=1`.
- [ ] Keep the candidate and evidence roots owner-private and destroy the disposable environment
  after extracting approved evidence.
- [ ] Do not bypass the existing root/admin-group rejection.

### H91-1020 — Repeat every 0.9.0 installed gate

- [ ] Verify checksums/contracts before extraction.
- [ ] Install from a path containing spaces and Unicode.
- [ ] Probe help/version/schema for all four runtime binaries.
- [ ] Run init/ingest/query/compile/materialize/checkpoint.
- [ ] Run daemon readiness and two restart cycles.
- [ ] Run MCP against the installed daemon.
- [ ] Clean-install exact TypeScript, Python wheel, Python sdist, and Rust local-registry artifacts.
- [ ] Run Claude plugin install/doctor/lifecycle/uninstall.
- [ ] Run all installed demos twice.
- [ ] Run backup/create/verify/restore into a distinct empty target.
- [ ] Uninstall without unexpectedly deleting retained state.
- [ ] Re-run all 0.9.0 negative safety assertions.

### H91-1030 — Add installed persistence/efficiency gates

- [ ] Create a v4 generated store with boundary revisions, pins, effects, blobs, idempotency,
  handoffs, spaces, bundles, and source snapshots using 0.9.0-compatible bytes.
- [ ] Migrate using only installed 0.9.1 public/admin surfaces and verify the signed receipt.
- [ ] Compare every retained root/revision before and after migration.
- [ ] Restart cleanly and through crash failpoints; require readiness within 30 seconds.
- [ ] Run 10,000 serial mutations, the mixed-concurrency soak, and the frozen 100-request cohort.
- [ ] Run the verified-copy cohort only after generated cases pass and only against a disposable
  verified copy.
- [ ] Require all H91-620/H91-630/H91-640 thresholds.
- [ ] Run compaction preview/execute/status with pinned and unpinned revisions and verify separate
  blob-GC state remains unchanged.

Qualification command from the standard-user environment:

```sh
candidate_epoch=$(git -C /absolute/path/to/cigar-honey show -s --format=%ct HEAD)
CIGAR_NO_EGRESS_ENFORCED=1 \
python3 /absolute/path/to/cigar-honey/scripts/release/qualify_honey_release.py \
  --root /absolute/path/to/cigar-honey \
  --evidence-root /private/tmp/cigar-honey-0.9.1-honey.1-candidate \
  --source-date-epoch "$candidate_epoch" \
  qualify
```

Exit gate:

- [ ] The orchestrator returns `passed-developer-preview`, all old and new mandatory gates are
  passed, and claims still say unpublished, unsupported, and not production-qualified.

## H91-1050 — Coordinate the downstream Hiero shadow verification

This phase occurs only after exact installed 0.9.1 bytes exist. It validates the integration seam
that produced the feedback; it does not authorize Honey to modify the retained evidence store.

- [ ] Keep `HIERO_AUDIT_CIGAR_MODE=shadow` throughout qualification.
- [ ] Update `hiero_audit_core/cigar_client.py::CigarHoneyClient.compile_context` to reuse a
  persistent SDK client/connection pool.
- [ ] Cache immutable version information for process lifetime and use a short authenticated
  readiness lease instead of issuing liveness, readiness, and version for every compile.
- [ ] Keep the eight-call v1 compilation sequence for 0.9.1 compatibility; do not emulate an atomic
  result client-side. Replace it only after the versioned atomic operation ships.
- [ ] Update `hiero_audit_core/context_compilers.py::CigarContextCompiler.compile` so run/job/trace
  correlation is excluded from the semantic request identity and retained only in the execution
  receipt/artifact correlation.
- [ ] Keep `max_attempts=1` for mutations unless a shipped operation exposes explicit supported
  reconciliation.
- [ ] Bind the installed Honey artifact SHA-256, migration state, semantic request identity, and
  returned execution receipt to Hiero's content-free result record.
- [ ] Rerun the exact paired five-workflow by 20-trial benchmark using the command recorded in the
  handoff, then run the frozen downstream model/harness cohorts.
- [ ] Verify the 100-request completion, latency slope/p95, duplicate-content, diversity,
  displacement, citation, and required-source gates from H91-630/H91-640.
- [ ] Emit a content-free downstream verification report with raw input digest, harness/source
  revision, environment, installed artifact digest, paired order, and per-workflow results.
- [ ] Do not claim vulnerability-finding efficacy from this context comparison. Any such claim
  requires separately frozen downstream outcome labels and methods.
- [ ] Do not leave shadow mode until the relevant upstream and downstream promotion gates pass.

Exit gate:

- [ ] The exact 0.9.1 installed candidate removes progressive latency/storage growth on the same
  integration seam while preserving the measured context-quality floor.

## H91-1100 — Evidence, residual risk, and authorized prerelease cut

### H91-1110 — Private evidence and non-mutating verification

- [ ] Bind source descriptor, all 13 attachments, producer receipts, installed report, SDK reports,
  Claude report, demo reports, docs report, bounded safety report, efficiency/reliability report,
  license inventory, offline dependency report, and secret scan into the closed Honey ledger.
- [ ] Verify the ledger schema, exact evidence IDs, accepted report schemas, artifact/capability/gate
  bindings, aggregate evidence root, and prohibited claims.
- [ ] Run orchestrator `verify`; it must reconstruct public integrity and private evidence without
  mutation.
- [ ] Run the offline verifier from a clean checkout with only candidate bytes, source descriptor,
  trusted Honey policy, and required private evidence inputs.
- [ ] Produce a concise residual-risk statement covering developer-preview status, one observed
  external cohort, Apple-silicon only, unsigned/unnotarized bytes, no longevity/full chaos, and no
  independent new-task efficacy claim.
- [ ] Obtain maintainer review of migration safety, performance methods, release wording, licenses,
  security limitations, and exact attachment list.

### H91-1120 — Final cut checklist

- [ ] All mandatory 0.9.0 gates pass: authority drift, protocol drift, clean committed source,
  focused tests, conformance, archive contracts, installed runtime, SDK clean installs, Claude
  lifecycle, two-agent authority, policy nondisclosure, effect unknown recovery, offline replay,
  prompt-injection defense, docs commands/links, license/notice, and artifact checksums.
- [ ] All new 0.9.1 gates pass: storage format v5, v4-v5 migration, revision recovery, storage
  amplification, serial latency, startup readiness, and context quality/efficiency.
- [ ] Candidate public verifier returns `passed-artifact-integrity`.
- [ ] Private evidence verifier returns `passed-developer-preview`.
- [ ] Exact 13 filenames, sizes, and SHA-256 values are frozen.
- [ ] Release notes and security limitations match the machine evidence.
- [ ] No mandatory gate is failed, skipped, waived, unknown, or absent.
- [ ] Working tree remains clean and candidate source descriptor still names `HEAD`/`HEAD^{tree}`.

### H91-1130 — Publish only with explicit owner approval

- [ ] Obtain explicit approval in the publication turn; prior plan approval is not publication
  approval.
- [ ] Tag the exact candidate commit `v0.9.1-honey.1`.
- [ ] Create GitHub prerelease `CIGAR Honey v0.9.1 — 0.9.1-honey.1`.
- [ ] Upload only manifest-selected attachments; never upload private evidence or qualification
  inputs.
- [ ] Download all attachments into a new empty directory and compare filename, size, and SHA-256
  with `honey-release-manifest.json` and `SHA256SUMS`.
- [ ] Run the offline verifier against downloaded bytes.
- [ ] Follow downloaded install, migration, quickstart, two-agent, SDK, MCP/Claude, compaction, and
  uninstall documentation on a clean standard-user machine.
- [ ] Keep `supported=false` and `production_qualified=false` after publication.
- [ ] Never replace bytes under the same version. Withdraw and cut a new prerelease on material
  failure.

Final exit gate:

- [ ] A new user can verify/install 0.9.1, migrate a generated v4 store safely, compile bounded
  governed context without progressive storage/latency failure, resolve merged citations, run all
  existing Honey workflows, inspect evidence, and uninstall using only downloaded materials.
- [ ] Every public claim is supported by exact candidate-bound developer-preview evidence.

## 4. Required deliverables

- [ ] Five reviewed ADR/proposal documents from H91-020/H91-500.
- [ ] Before/after stage profile on identical generated and verified-copy workloads.
- [ ] v5 schema, canonical delta/checkpoint implementation, retention policy, and compaction flow.
- [ ] v4-to-v5 migration threat model, failpoint matrix, and signed receipt schema.
- [ ] Deterministic content-equivalence implementation and provenance/citation tests.
- [ ] Retrieval bounding/diversity implementation and mandatory-evidence tests.
- [ ] Content-free storage/startup/retrieval/cache telemetry.
- [ ] Machine-readable efficiency/reliability qualification with raw-observation digest.
- [ ] Updated version authority, artifact contracts, SDK records, docs, demos, and release notes.
- [ ] Exact 13-file candidate, private evidence ledger, qualification result, and residual-risk
  statement.

## 5. Required non-fixes and stop conditions

Stop and record `[!]` evidence if implementation would require any of these:

- lowering SQLite durability, checksum, signature, provenance, revalidation, or authorization;
- modifying or deleting the only v4 copy;
- treating a backup as valid without restore/integrity verification;
- deleting history without pins, legal holds, replay, exact revision, and backup checks;
- using `VACUUM` or a larger maximum DB size as the storage repair;
- opening readiness before authenticated recovery;
- discarding provenance/source identity to deduplicate content;
- allowing ordinary top-K/diversity logic to remove mandatory evidence;
- ignoring execution correlation inside the existing v1 contract digest;
- adding public operations under the frozen v1 compatibility claim;
- retrying ambiguous mutations blindly;
- testing first against the retained Hiero evidence state; or
- claiming downstream penetration-testing efficacy from a context-only or storage benchmark.

## 6. Recommended execution checkpoints

1. **Architecture review:** H91-000 and H91-100 complete; baseline reproduced.
2. **Persistence review:** H91-200 passes generated conformance and failpoints.
3. **Migration/recovery review:** H91-300 passes generated and verified-copy cases.
4. **Context-quality review:** H91-400 passes frozen quality thresholds.
5. **Qualification freeze:** H91-500/H91-600 schemas, metrics, thresholds, and fixtures frozen.
6. **Source freeze:** H91-700/H91-800 complete on one clean commit.
7. **Exact-byte review:** H91-900 candidate integrity passes.
8. **Installed qualification review:** H91-1000 passes on the required standard-user host.
9. **Downstream shadow review:** H91-1050 reproduces the fixed cohort on exact candidate bytes.
10. **Release review:** H91-1100 evidence and wording approved.
11. **Publication:** H91-1130 only after explicit owner authorization.

Do not combine persistence design, migration activation, compiler selection changes, protocol
authority, version propagation, and release-evidence changes in one opaque commit. Each checkpoint
must leave a reviewable, tested, fail-closed state.
