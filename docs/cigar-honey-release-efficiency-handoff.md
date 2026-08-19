# CIGAR Honey release efficiency and reliability handoff

Audience: GPT-5.6 Sol acting as the CIGAR Honey release owner
Evidence date: 2026-07-20
Evaluated release: `0.9.0-honey.1`
Context ABI: `cigar.context.v1`
Recommendation: **keep CIGAR in developer-preview/shadow qualification until the P0 gates in this
document pass**

This is an implementation handoff, not a request to weaken CIGAR's governance model. Preserve
determinism, authenticated provenance, signed receipts, fail-closed validation, idempotency,
revalidation, `synchronous=FULL`, secure local state, backup verification, and exact-revision replay.
The principal performance problem is the representation and mutation frequency of durable state,
not those controls.

Status legend: `[ ]` pending, `[~]` in progress, `[x]` verified, `[!]` blocked with evidence.

## 1. Release decision

Do not promote the current Honey build as operationally qualified for sustained context compilation.
The release demonstrated useful citation and required-source behavior, but it also demonstrated
unbounded practical cost under a small serial cohort:

- 99 of 100 CIGAR context compilations completed; local context completed 100 of 100.
- Mean CIGAR latency was 45.10 seconds versus 4.96 seconds locally, a regression of 810.18%.
- CIGAR latency increased approximately 558 milliseconds for every sequential benchmark trial.
- The first ten CIGAR trials averaged 18.83 seconds; the final ten averaged 71.35 seconds.
- Every workflow had positive within-workflow CIGAR latency growth while its local comparison was
  flat or slightly faster.
- A controlled restart did not reopen liveness or readiness within five minutes.
- Required-source coverage improved from 94% to 100%, and citation resolvability improved from 94%
  to 99%.
- Selected evidence contained 27.15% duplicate content and source diversity fell 51.45%.

The release should remain `production_qualified=false`. A new candidate may be cut for engineering
qualification after the P0 work is complete, but it should not be called production-qualified until
the full release gates pass.

## 2. Root-cause diagnosis

### 2.1 P0: complete residual-state snapshots dominate the database

The inspected SQLite state contained:

| Measurement | Value |
| --- | ---: |
| Main database bytes | 50,084,237,312 |
| Retained revisions | 1,024 |
| Sum of retained `residual_state` payloads | 49,841,189,105 bytes |
| Latest `residual_state` | 49,122,343 bytes |
| SQLite freelist | 47,132,672 bytes |
| Payload share attributable to retained residual snapshots | approximately 99.5% |

`crates/cigar-store/src/sqlite.rs` hardcodes
`MAX_RETAINED_SQLITE_SNAPSHOTS = 1_024`. Every repository commit loads the latest residual state,
applies staged mutations, serializes the complete catalog-free state, inserts it into
`cigar_repository_revisions_v4`, and retains the newest 1,024 copies. The residual includes bundles,
source snapshots, context commits, effects, blob metadata, outbox records, idempotency records,
service records, and other tenant state.

This creates both space and write amplification. At the observed state size, one small logical
mutation can encode and write approximately 49 MB. Keeping 1,024 such states explains essentially
the entire database. `VACUUM` is not the fix: less than 0.1% of the database was free.

Confidence: **high**. This is directly supported by the retained table contents and the release
source.

### 2.2 P0: one user-level compilation creates too many durable mutations

The Hiero integration exercises the frozen operations in this order:

1. liveness;
2. readiness;
3. version;
4. create context plan — mutation;
5. compile context bundle — mutation;
6. get bundle manifest;
7. materialize bundle — mutation;
8. revalidate bundle — mutation.

That is eight sequential requests and four mutation commits for one context compilation. With the
current store, each mutation can produce another full residual snapshot. Combining four safe,
idempotent mutations into one atomic server-side operation would theoretically remove up to 75% of
these commit boundaries, but batching alone will not repair 49 MB snapshot writes.

Confidence: **high** for the request/commit count; **medium** for isolated batching benefit because
per-stage profiling is not yet exposed.

### 2.3 P1: compiler selection does not collapse content-equivalent candidates

`crates/cigar-compiler/src/compiler.rs` groups competing candidates by `logical_id`. It validates
representation identity within one candidate using `(kind, content_digest)`, but it does not
collapse identical selected representations across different logical IDs. A `ContextBlock` already
supports a provenance vector, so CIGAR can retain every source/version identity while emitting the
same governed content only once.

Confidence: **high**. The benchmark measured a 27.15% duplicate-content rate, including 80% for the
JSON-RPC cohort.

### 2.4 P1: candidate volume is far above the useful selection set

Across 99 successful CIGAR compilations, 50,310 candidates were marked `budget_displaced` while 534
evidence items were selected. That is approximately 94 displaced candidates for each selected item,
or 503 displaced candidates per trial.

Confidence: **high** for the measured ratio. The relative cost of retrieval versus compilation needs
new stage telemetry.

### 2.5 P1: semantic reuse is coupled to per-execution correlation

The downstream integration computes plan idempotency from the complete request. Run and job
correlation values enter the CIGAR contract extensions, so semantically identical context requests
receive different identities. The compiler contains governed cache primitives for retrieval, plan,
bundle, and materialization layers, but unstable execution correlation prevents effective reuse.

Traceability must remain unique per execution. The reusable semantic artifact and the execution
receipt should therefore have separate, cryptographically bound identities.

Confidence: **medium-high**. Repeated Solo and JSON-RPC queries demonstrate the opportunity, but the
actual cache-hit improvement has not been measured.

## 3. Required release work, in order

### Track A — Honey patch that preserves `cigar.context.v1`

Do this work first. Do not add or reinterpret public v1 operations in this track.

#### A1. Add measurements before changing persistence

- [ ] Emit content-free per-operation timings for repository-load, residual decode, staged mutation,
  residual encode, catalog-root update, SQLite transaction, commit/fsync, and anchor publication.
- [ ] Emit logical bytes changed, encoded residual bytes, SQLite/WAL growth, revision delta, retained
  snapshot count, and write-amplification ratio.
- [ ] Split daemon-start timing into path/config verification, migration, latest residual read,
  checksum, decode, projection recovery/verification, blob reconciliation, and readiness-open.
- [ ] Emit retrieval candidate counts before governance, after governance, after logical grouping,
  after content grouping, and after budget selection.
- [ ] Keep telemetry content-free. Never emit source text, prompts, tokens, credentials, provenance
  bodies, handoff capsules, or arbitrary extensions.

Primary source surfaces:

- `crates/cigar-store/src/sqlite.rs`
- `crates/cigar-daemon/src/telemetry.rs`
- `crates/cigar-daemon/src/production_store.rs`
- `crates/cigar-daemon/src/production_runtime.rs`
- `crates/cigar-retrieval/src/planner.rs`
- `crates/cigar-compiler/src/compiler.rs`

#### A2. Replace full residual snapshots with bounded incremental persistence

- [ ] Write an ADR selecting one of these acceptable designs:
  1. normalized immutable records plus an append-only revision event/delta log and periodic complete
     checkpoints; or
  2. content-addressed/chunked residual snapshots that share every unchanged subtree.
- [ ] Prefer normalized records plus deltas and checkpoints unless benchmarks show reconstruction or
  verification is materially worse. The current normalized catalog is evidence that this design is
  compatible with CIGAR's root-verification model.
- [ ] Store a parent revision, canonical delta checksum, resulting semantic root, catalog root,
  logical totals, and format version for every revision.
- [ ] Create a full checkpoint on a bounded interval and when delta-chain bytes exceed a configured
  fraction of checkpoint bytes. Do not use an interval alone.
- [ ] Preserve exact revision selection for every retained revision. Replaying a delta chain must
  reproduce the same semantic root and canonical encoded state as the original revision.
- [ ] Make retention configurable by count, age, and total retained bytes, subject to a verified
  minimum and legal-hold/replay pins. A byte ceiling is required; count-only retention recreated the
  current failure.
- [ ] Add a supported, signed compaction plan with preview, exact revision guard, backup proof,
  legal-hold validation, execution receipt, interruption recovery, and post-compaction verification.
- [ ] Keep blob GC and revision compaction as distinct operations with distinct receipts.

A concrete schema direction is:

```text
cigar_repository_checkpoints_v5
  revision, state, state_checksum, semantic_root, catalog_root, logical totals

cigar_repository_deltas_v5
  revision, parent_revision, canonical_delta, delta_checksum,
  resulting_state_checksum, semantic_root, catalog_root, logical totals

cigar_repository_retention_pins_v5
  revision/range, reason code, authority, expiry, signed policy identity
```

The exact schema may differ, but the invariants may not.

#### A3. Provide a safe v4-to-v5 migration

- [ ] Never rewrite the only copy of a v4 store in place.
- [ ] Require a verified backup and sufficient free space before migration.
- [ ] Build v5 in a distinct state directory, verify all retained v4 snapshot checksums and semantic
  roots, reconstruct the same retained revision sequence in v5, then run deep integrity checks.
- [ ] Produce a signed migration receipt binding source database identity, source revision range,
  backup identity, target format, target semantic root, artifact digests, and verification result.
- [ ] Activate the new state only through an atomic owner-controlled pointer/directory switch.
- [ ] Retain the original v4 state until an explicit, separately approved retention action.
- [ ] Continue to block in-place downgrade. Restore old versions only into a distinct empty target.
- [ ] Add interruption tests at every migration, checkpoint, delta, compaction, activation, and
  revision-anchor boundary.

Do not migrate the 50 GB Hiero evidence store as the first test. Use generated fixtures, then a
verified copy, and touch the retained evidence only after the migration implementation passes its
qualification suite.

#### A4. Repair startup and deep-check scaling

- [ ] Startup should authenticate and reconstruct only the latest state needed for readiness.
- [ ] Projection recovery should use an authenticated checkpoint and bounded deltas, not replay all
  retained full states.
- [ ] Keep verification of every retained revision in an explicit deep-integrity operation.
- [ ] Make deep verification incremental by remembering a signed verified prefix/checkpoint; still
  offer a forced full pass.
- [ ] Bound startup by retained delta bytes rather than merely retained revision count.
- [ ] Prove that a clean and crash-recovery restart both become ready within the release objective.

#### A5. Deduplicate selected content without losing provenance

- [ ] Introduce deterministic content-equivalence grouping after representation eligibility is
  known, keyed at minimum by representation kind and governed content digest.
- [ ] Choose one deterministic representative using existing stable ordering.
- [ ] Merge all equivalent version IDs and dependency provenance into the emitted block's provenance
  vector.
- [ ] Ensure required-source satisfaction is computed across the merged equivalence class.
- [ ] Ensure citations to any merged version resolve to the single selected block and retain the
  exact source/version chain.
- [ ] Preserve manifest accounting for every candidate. In a v1-compatible patch, use an existing
  semantically valid non-selection reason such as `budget_displaced`; do not silently add a new v1
  enum value. A future ABI may add an explicit `content_equivalent` reason.
- [ ] Add deterministic property tests proving input permutation cannot change the result.

#### A6. Bound retrieval before compiler budget displacement

- [ ] Apply requirement-aware top-K bounds using the requested token budget and lane allocation.
- [ ] Coalesce aliases that resolve to the same governed atom/version before compiler submission.
- [ ] Add per-source, per-lineage, and per-content-family caps with deterministic tie-breaking.
- [ ] Preserve all mandatory, policy, dependency, and higher-authority candidates regardless of
  ordinary top-K limits.
- [ ] Add a diversity-aware selection term or deterministic MMR-style stage that cannot displace
  mandatory evidence.
- [ ] Target fewer than ten budget-displaced candidates per selected block on the Hiero cohort.

### Track B — versioned protocol/API work

The public Honey v1 registry is documented as a frozen 45-operation API. Do not smuggle these
changes into that registry under the same compatibility claim. Ship them under the next declared
compatible protocol/product version with regenerated SDKs, schemas, conformance vectors, and
operation-registry evidence.

#### B1. Add one atomic context-compilation operation

- [ ] Accept the governed contract, target/materialization profile, requested validation policy,
  and one mutation idempotency identity.
- [ ] Within one transaction, plan, compile, seal the bundle/manifest, materialize, and revalidate.
- [ ] Return the plan, bundle, manifest, materialization, revalidation result, revision, and one
  parent operation receipt.
- [ ] Preserve deterministic child identities and enough child receipts for existing audit/replay
  consumers.
- [ ] On an ambiguous transport outcome, make the operation reconcilable by the supplied idempotency
  identity. Do not require blind mutation retry.
- [ ] Keep the existing granular operations for compatibility and administrative/debug use.

#### B2. Separate semantic artifact identity from execution correlation

- [ ] Define a canonical semantic compilation identity from normalized requirements, governed
  project/catalog watermark, principal authorization/disclosure domain, policy digest, target,
  tokenizer, materializer, and compilation version.
- [ ] Exclude run ID, job ID, trace ID, timestamps, and transport correlation from that semantic
  identity.
- [ ] Define a separately signed execution receipt binding those correlation values to the reused or
  newly generated semantic artifact digest.
- [ ] Require authorization, disclosure, policy, catalog watermark, tokenizer, and materializer
  matches before any cache reuse.
- [ ] Surface content-free cache hit/miss/bypass reasons for retrieval, plan, bundle, and
  materialization layers.

The intended relationship is:

```text
semantic compilation identity
  = normalized context need + governed state + policy + target/compiler fingerprints

execution receipt
  = semantic artifact digest + run/job/trace correlation + authority + time + signature
```

This preserves unique traceability while allowing safe reuse of deterministic work.

#### B3. Add explicit revision-retention administration

- [ ] Expose signed preview/execute/status operations for revision compaction.
- [ ] Expose effective retention count, age, byte ceiling, pinned revisions, checkpoint cadence, and
  reconstructable revision range through authenticated diagnostics.
- [ ] Return stable content-free failure codes for missing backup, legal hold, insufficient space,
  active writer, revision drift, or failed post-verification.

## 4. Release qualification matrix

Do not judge the repair on a clean empty database alone. Run the following against generated stores
and a verified copy of the observed workload.

### Persistence and recovery

- [ ] Every retained v4 revision migrated to v5 has the same semantic and catalog roots.
- [ ] Random and boundary v5 revisions reconstruct deterministically from checkpoint plus deltas.
- [ ] Process-kill tests at every failpoint recover to the prior or committed revision, never a
  hybrid.
- [ ] Backup, verify, distinct-target restore, and downgrade rejection pass.
- [ ] Compaction preview and execution preserve pinned revisions and reject revision drift.
- [ ] Forced deep verification authenticates every retained checkpoint and delta.

### Scale and latency

- [ ] Run at least 10,000 representative serial mutations and a separate mixed-concurrency soak.
- [ ] Database growth is bounded by policy and is below 1 MB per steady-state context compilation
  for the Hiero-sized catalog.
- [ ] Sequential context latency slope is no greater than 10 ms per request over the 100-request
  qualification cohort; current slope is approximately 558 ms.
- [ ] Context compile p95 is below 10 seconds on the qualification host, or no more than twice the
  local comparison if the local baseline changes.
- [ ] Clean and crash-recovery restarts become ready within 30 seconds at the configured retention
  ceiling.
- [ ] Atomic compile performs no more than one repository commit on a cache miss and zero artifact
  rewrites on a fully valid cache hit, while still creating the required execution receipt.

### Context quality

- [ ] Completion is 100% for the 100-request cohort.
- [ ] Duplicate selected content is at most 5%.
- [ ] Source diversity is non-regressive against local context for comparable requirements.
- [ ] Budget-displaced:selected is below 10:1.
- [ ] Citation resolvability and required-source coverage remain at least 99% and 100% respectively.
- [ ] Required, policy, security, provenance, tokenizer, materializer, and budget validation remain
  fail closed.

### Compatibility and release evidence

- [ ] Exact artifact checksums, SBOM/license evidence, schemas, canonical vectors, negative vectors,
  SDK generation, installed-byte demos, no-egress tests, and clean-consumer tests pass.
- [ ] Python, TypeScript, Rust, CLI, daemon, MCP, and plugin consumers agree on product version and
  context ABI.
- [ ] Old granular API clients continue to work when the next protocol version advertises backward
  compatibility.
- [ ] Release notes state storage-format compatibility, migration duration/space needs, rollback,
  retention semantics, and known qualification limits precisely.

## 5. Changes that must not be used as performance fixes

Do not:

- disable `synchronous=FULL`, secure path/identity checks, checksums, signatures, revalidation, or
  provenance validation;
- increase the 68 GB large-local ceiling and call the issue fixed;
- use `VACUUM` as the primary repair when the database is almost entirely live rows;
- manually delete revision rows or teach operators to edit the CIGAR database;
- reduce retention without backup, legal-hold, replay, and exact-revision impact checks;
- retry ambiguous mutations blindly;
- make health checks report ready before state authentication and recovery complete;
- add workers or concurrency as the primary remedy—the failure reproduced serially and additional
  writers can worsen tail latency;
- deduplicate by discarding provenance or required-source identities;
- place execution correlation in a reusable semantic identity;
- claim downstream vulnerability-finding efficacy from a context-only benchmark.

## 6. Downstream Hiero coordination after an upstream candidate exists

These are integration tasks, not substitutes for the upstream storage repair:

- replace the eight-call compilation sequence with the atomic operation;
- reuse a persistent SDK client/connection pool;
- cache immutable version information for the process lifetime and use a short authenticated
  readiness lease instead of checking all three health/version operations for every compile;
- compute the semantic request identity without run/job correlation and persist the returned
  execution receipt with Hiero's artifact correlation;
- retain `max_attempts=1` for mutations unless the new operation exposes supported reconciliation;
- rerun the paired 20-by-five workflow benchmark and then frozen downstream model/harness cohorts;
- keep `HIERO_AUDIT_CIGAR_MODE=shadow` until all promotion gates pass.

The current Hiero request seam is `hiero_audit_core/cigar_client.py::CigarHoneyClient.compile_context`.
The current full-request plan identity is created in
`hiero_audit_core/context_compilers.py::CigarContextCompiler.compile`.

## 7. Required release-owner deliverables

- [ ] ADR for incremental state, checkpoints, retention, compaction, and exact-revision replay.
- [ ] Before/after stage profile using the same retained-state workload.
- [ ] v4-to-v5 migration design, threat model, failpoint matrix, and signed migration receipt schema.
- [ ] Deterministic content-equivalence design and provenance-preservation tests.
- [ ] Retrieval bounding and diversity design with mandatory-evidence invariants.
- [ ] Versioned atomic compile and semantic/execution identity protocol proposal.
- [ ] Updated schemas, conformance vectors, generated SDKs, documentation, demos, and release notes.
- [ ] Machine-readable qualification result containing every gate in section 4.
- [ ] A concise residual-risk statement. Do not mark the build production-qualified when a gate is
  failed, skipped, or not evaluated.

## 8. Evidence and reproduction inputs

Use these repository artifacts as the baseline:

- `docs/cigar-workflow-efficacy-report.md`
- `.hiero-audit/cigar/efficacy/workflow-context-paired-v1.json`
- `docs/cigar-final-verification.md`
- `hiero_audit_core/cigar_client.py`
- `hiero_audit_core/context_compilers.py`
- `cigar-honey-0.9.0/cigar-0.9.0-honey.1-source.tar.gz`
- `cigar-honey-0.9.0/cigar-0.9.0-honey.1-schemas-conformance.tar.gz`
- `cigar-honey-0.9.0/cigar-honey-demos-0.9.0-honey.1.tar.gz`
- `cigar-honey-0.9.0/honey-release-manifest.json`
- `cigar-honey-0.9.0/SHA256SUMS`

Raw paired benchmark SHA-256:
`776b84c8cce3b11915b53947f3bb21a86c8a9819fc43ef0d1c85362ca62a3455`.

The benchmark is reproduced with:

```bash
.venv/bin/python scripts/benchmark_cigar_workflow_context.py --trials 20
.venv/bin/python -m pytest -q \
  tests/test_context_compilers.py \
  tests/test_benchmark_cigar_workflow_context.py
```

Do not run the first storage migration or destructive maintenance exercise against the retained
Hiero state. The daemon did not recover readiness during the prior controlled five-minute restart,
and that state remains evidence. Work from generated fixtures and a verified copy until the
migration and recovery suite is complete.
