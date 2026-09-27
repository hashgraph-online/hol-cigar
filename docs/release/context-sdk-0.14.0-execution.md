# CIGAR 0.14.0 execution and release evidence

Status: implementation in progress; not released or qualified.

The objective is to execute the project examination roadmap and release CIGAR
0.14.0. The source baseline is the 0.13 alpha at
`c8117349fce37f932d14032219964253f0825110`; the supported compatibility baseline
is 0.12.0. This record must retain incomplete requirements rather than redefine
the release around whichever changes pass first.

Evaluation remains offline. No model-provider calls are authorized. Published
claims must distinguish source inspection, deterministic invariants, independent
task outcomes, recorded-answer replay, and new model-generated answer studies.

## Required work and completion evidence

| ID | Requirement | Evidence required | Status |
| --- | --- | --- | --- |
| S1 | Bind filesystem symlink admission to alias and resolved-target policy | Direct exclusion/ignore/identity regressions, legitimate symlink controls, catalog checks | Implemented; macOS verified; hosted platform checks pending |
| S2 | Reject special files without retaining blocking discovery capacity | Bounded FIFO/type-substitution/control-file tests and permit recovery; platform qualification | Implemented; macOS verified; hosted platform checks pending |
| S3 | Preserve TypeScript canonical map members and own-key semantics | Shared special-key vectors through public encoders/decoders and typed clients, unchanged valid bytes | Implemented; complete SDK suite passed locally |
| S4 | Enforce Python representation/transform-receipt semantics | Shared eight-case matrix across verifier, delta and model paths; unchanged valid fixture IDs | Implemented; complete SDK suite passed locally |
| S5 | Correct deployment and effective-resource discrepancies | Kubernetes CA input, systemd checkpoint permission and active-store backup/migration tests; installed smoke | Implemented; local deployment contracts and CLI regression suite passed; Linux runtime smoke pending |
| A1 | Make local installation and capability discovery unambiguous | Installed Python/npm ingest → compile → cite → replace → revalidate example, no services/credentials/network; doctor/capability schema | Live worker feature report and packaged guidance implemented; installed artifact matrix pending |
| A2 | Preserve existing API and all valid 0.12 behavior | Public exports/signatures/types, exact canonical fixtures, errors and legacy workflows | Existing 0.11/0.12 API snapshots pass; final candidate conformance pending |
| B1 | Share one graph across independent agent processes | Supported broker/client API in both SDKs, authenticated caller-to-view binding, host-only policy/reviewer controls | Native authority and both SDKs implemented; 1/5/12 independent Python/Node and mixed-language processes pass locally; installed/platform qualification pending |
| B2 | Bound shared-agent resource use and conflicting writes | Per-agent quotas, bounded fair admission, cancellation/uncertain mutation semantics, source revision conflict tests | Native quotas, source CAS, fair queue/cancellation and bounded transport implemented; installed load/fairness measurements pending |
| B3 | Restore context safely after restart | Atomic versioned journal/checkpoint restore, new authority epoch, rejected old handles/reviews, retention/withdrawal tests | Unix store locally verified; Windows NTFS protection implemented and cross-checked; hosted runtime/fault qualification and performance acceptance pending |
| P1 | Admit evidence with meaningful provenance | Host-owned source identity/version/time/trust and derivation lineage; unverified proposals remain untrusted | Native host admission, transitive invalidation and SDK integration implemented; Unix durable integration locally verified; hosted qualification pending |
| P2 | Integrate review and execution authority | Reviewer port and complete displayed-claim coverage; bind checked context to existing Honey effects/HUMIDOR adapter, no blind retry | Native binding and SDK Honey adapter implemented; 12 Python/Node HTTP/SQLite scenarios pass locally; HUMIDOR adoption and hosted qualification pending |
| R1 | Improve retrieval and explanation through optional adapters | Scoped hybrid/reranking input, syntax-aware ingestion, safe selection explanation, tokenizer identity; held-out evidence tests at equal budget | Selected-only explanation and parser-boundary ingestion implemented; broader ranking adapters and held-out efficacy still pending |
| R2 | Remove measured ingestion/throughput bottlenecks | Profile source/scope hashing and IPC; transactional batches and bounded APIs; paired latency/RSS evidence | Checkpoint-buffer, ordered-scope lookup and transactional batch ingestion measured locally; full throughput/platform qualification pending |
| E1 | One auditable evaluation result contract | Versioned schema with exact artifact/corpus/treatment/task identities and reproducible raw observations | Verifier and shared-view/answer/Hiero producers implemented; historical Hiero import and exact re-import pass locally; hosted three-OS checks pending |
| E2 | Prove efficacy against meaningful baselines | Independent gold task/evidence labels, Hiero terminal oracles, matched-budget retrieval/task comparisons and confidence intervals; replay separated from generation claims | Pending |
| E3 | Qualify 1/5/12-agent operation | Shared/private/overlapping scopes, hostile source content, lost update, revoke, restart, saturation and short fault schedules; subsequent 24-hour 12-agent soak | Local 18-cell Python/Node/mixed memory/SQLite fault matrix passes 3,879 checks; corrected repeated load study running; hosted faults and 24-hour soak pending |
| Q1 | Preserve performance and reliability | Existing 10% median latency and 20% RSS guardrails plus preregistered tail/fairness limits, total host+worker RSS | Pending |
| Q2 | Qualify exact distributions | Two independent builds, seven native targets, minimum/current supported runtimes, network-denied installed consumers, metadata/licenses/SBOM/advisories/attestations | Pending |
| Q3 | Release 0.14.0 and verify public bytes | Consistent release identity/docs, required CI and release approvals, npm/PyPI publication, registry readback/hash comparison and clean install | Pending |

## Implementation order

1. Fix S1–S4 at their shared enforcement boundaries, with an independent
   investigation and one independent candidate review. Preserve valid inputs.
2. Resolve deployment/product identity gaps and establish A1/A2/E1 gates.
3. Implement and qualify B1–B3, then P1/P2 and the retrieval/ingestion adapters.
4. Run independent efficacy, fault and load comparisons against 0.12 and the
   retained alpha. Measure optimizations before accepting them.
5. Freeze source, qualify exact release artifacts, publish and verify readback.

Protocol v2, embedded bindings and parallel reads are conditional optimizations:
they require profiling evidence and preserved determinism before adoption. A
decision to retain the existing transport must include the relevant measurements.
New Python/Node/platform support may be advertised only after qualification.

## Authority and compatibility

The trusted host owns root mutation, scope creation/revocation, evidence admission,
review verdicts and execution policy. Agents receive a restricted view/client.
One graph can serve multiple agents within an appropriate privacy domain;
unrelated hostile tenants remain isolated. HUMIDOR owns orchestration and model
routing; existing CIGAR/Honey capability, handoff, effect and replay meanings
remain authoritative.

The frozen remote ABI, context ABI and valid canonical identities must remain
compatible. Unsafe-input rejection is documented explicitly. Never regenerate a
valid fixture merely to make a changed implementation pass. A timeout after an
uncertain mutation must not cause blind automatic redispatch.

## Promotion stop conditions

Any scope leak, lost authorized update, stale authority acceptance, blind effect
retry, valid identity drift, unqualified advertised target, missing release
evidence, or unsupported efficacy claim prevents promotion. Green tests count
only when their exercised behavior covers the corresponding requirement above.

## Execution record

- Created an isolated `codex/cigar-0.14.0` worktree from the clean examined alpha.
- Re-read HOL Guard and applicable fix-finding instructions. Began independent
  read-only investigation of the four source-validated defects.
- Implemented S1–S4 and shared Rust/Python/TypeScript semantic boundary fixtures.
  Original alias-policy and FIFO regressions failed before remediation. The FIFO
  test also exposed a blocking leaf open inside capability canonicalization;
  resolution now canonicalizes directories only and opens file content with
  nonblocking, regular-file checks. Policy matching uses actual entry spelling.
- Independent candidate review identified incomplete Windows directory-entry
  identity metadata; capability stat now supplies the required fields, with a
  platform-neutral regression test. No other concrete bypass was reported.
- Local validation on macOS ARM64: 54 catalog tests, 55 protocol tests, 192 daemon
  unit tests, 357 Python tests plus 39 subtests, and 87 TypeScript tests passed.
  The two ignored Rust subprocess helpers are invoked by bounded parent tests.
  Strict Clippy, Python lint/mypy, changed-file formatting, generated-client
  drift and generated-local-asset checks passed. The independent review also
  probed all twelve Object.prototype names and Python semantic boundaries.
- Python and Rust loopback transport tests required execution outside the local
  sandbox; no model provider was called. A pinned, SHA-256-verified protoc 33.2
  was staged temporarily for the daemon build.
- Full Python formatting inspection found five pre-existing unformatted files
  (README, generated native platform metadata, and three older test files).
  They are outside this boundary patch and remain a Q1 cleanup item. Linux and
  Windows execution, efficacy/performance comparisons, installed artifacts and
  release qualification are still pending. No publication or efficacy gain is
  claimed by this stage.
- Corrected the systemd checkpoint directory permission/writable-path contract
  and Kubernetes telemetry CA preparation. Eight deployment contract tests pass.
  CLI maintenance paths that only implement legacy v4 storage now reject an
  active v5 descriptor instead of reading the retained v4 database. Named backup
  verification/restore and explicit v5 maintenance remain available. The new
  regression proves ten commands fail before creating outputs or modifying the
  retained database, checkpoint or descriptor. All 46 CLI library tests and
  strict daemon/CLI Clippy checks pass. This is an explicit unsupported-operation
  boundary, not a new v5 backup implementation. Installed Linux deployment
  smoke tests remain required.
- Added a copy-safe, versioned `graph.capabilities()` handshake report in both
  SDKs. Doctor reports live features separately from worker-file inspection and
  successful compilation. A legacy hello cannot imply unsupported features;
  closed graphs cannot report themselves as live. Packaged agent guidance now
  explains these distinctions and avoids the stale version in its title.
  Eight Python tests plus seven platform subtests, seven TypeScript tests and
  three native worker protocol tests pass. Published Python API snapshots retain
  every existing field/signature. Changed-file lint/format and generator checks
  pass. The normal strict mypy command exposed generated dictionary expansion
  errors; the generator now emits typed named arguments with identical operation
  values. Strict mypy passes all 20 handwritten source files with their imports.
- Added the closed `cigar.context-evaluation-*.v1` evidence contract and verifier.
  It binds artifact, corpus, task, oracle, harness and evaluator bytes; recomputes
  metrics from paired raw observations; preserves missing/unsupported/failed
  outcomes; handles zero denominators; and resamples declared clusters instead
  of individual repeated calls. Reports retain strata and separate authored
  invariants, replay, model-output, executable-task and performance evidence.
  Twenty-two regression tests pass, including changed artifacts/evaluator,
  malformed data, package mismatch, unpaired observations, rate denominators,
  repeated-call weighting and hidden stratum regressions. CI now runs this
  stdlib-only contract suite on three operating systems; hosted runs are pending.
- Extended the existing shared-view harness to 1/5/12 scoped clients and retained
  raw timings/outcomes plus simultaneous host-and-worker RSS samples. Local
  1/5/12-client smoke studies ran against the retained installed 0.12/0.13 alpha
  environments. In the 12-client run, views preserved all 66 unaffected releases
  and rejected six stale contexts. The shared-root control invalidated those 66
  unaffected contexts; private graphs preserved them. Both legacy root paths
  retained identical output hashes. These are authored, single-host pipeline
  smoke results, not 0.14 benefit or independent-process qualification claims.
  The adapter verified the installed source/worker bytes against the supplied
  wheels and recomputed 1,940 observations across eight operations. Two cohorts
  are insufficient for a performance interval. Evidence is outside the source
  worktree under `CIGAR/releases/cigar-0.14.0-development`.
- Recorded the broker's ownership, authenticated loopback transport, per-agent
  quotas/fair dispatch, proposal-only model writes, source revision conflicts,
  recovery epoch and review/effect integration contract in
  `docs/proposals/context-broker-0.14.0.md`. This remains implementation work;
  the capability report does not advertise a broker yet.
- Added the opt-in native `broker` feature with fresh random epochs/credentials,
  server-owned scopes, bounded expiring tickets, proposal-only agent writes,
  host admission, monotonic source CAS and retained proposal receipts. Source
  withdrawal/change-back cannot reset versions. Host provenance changes and
  expired/stale transitive inputs invalidate dependent evidence. Broker source
  authority is bound into the existing snapshot/review-key chain, so metadata-only
  changes and restart epochs cannot reuse old reviews. Ordinary view IDs/shapes
  retain their existing path. Exact answer submissions cannot supply reviews or
  append unchecked prose through this API.
  Fifteen native broker regressions pass, including five/twelve scoped callers,
  competing proposals, invalid-input atomicity, cross-owner tickets, revocation,
  expiry, quotas, change-back, derivation cycles and old-review replay. The full
  context crate has 70 passing tests plus its doctest with `bpe,broker`; strict
  all-target Clippy passes. This is a single-owner core, not independent-process
  qualification: no listener, scheduler, journal or SDK broker is shipped yet.
- Implemented a native bounded scheduler with per-grant job/byte limits, separate
  host capacity, round-robin agent dispatch and alternating host opportunities.
  Cancellation uses an atomic queued-to-dispatched boundary: a cancelled queued
  operation cannot run, while a dispatched/completed operation cannot be declared
  safely unexecuted. Revocation and expiry return explicit pre-dispatch failures.
  Six scheduler regressions pass, including a twelve-agent saturated queue,
  host admission during agent saturation, epoch/credential rejection, replaced
  grants, drop cleanup and 100 cancellation/dispatch races. Strict all-target
  Clippy passes. The existing three-OS `scripts/dev.py context` job already selects
  all Cargo features and will exercise these tests; hosted execution and actual
  independent-client queue-delay/fairness measurements remain pending.
- Added host relationship mutation with exact affected-source CAS, symmetric
  contradiction handling, version advancement on edge change-back and bounded
  retained endpoint ownership. A different source cannot reuse an ID while old
  relations still refer to it; explicit unlink works after withdrawal and frees
  that ownership. Three additional regressions pass, including failed-admission
  atomicity, required counterevidence and scope checks. The complete local
  `scripts/dev.py context` gate passes formatting, strict Clippy, 79 all-feature
  tests, the doctest and 48 core-only test/doctest invocations. Complete logs are
  retained in `CIGAR/releases/cigar-0.14.0-development/broker-core-source-checks`.
  These remain source-level invariants, not a broker transport/load qualification.
- Added closed, disjoint host/agent protocol types and bounded big-endian length
  framing. Agent decoding cannot produce a host mutation, grant or review command;
  duplicate fields and authority overrides are rejected. Source versions are
  canonical decimal strings to avoid JavaScript precision loss. Six protocol
  regressions cover authority separation, malformed envelopes, exact frame limits,
  truncated prefixes/bodies, rejection before oversized allocation, allowlisted
  replies and u64 version boundaries. All 30 broker/core/scheduler/protocol tests
  and all-feature/all-target strict Clippy pass locally. The transport still needs
  to connect these contracts to actual private stdio and loopback channels.
- Connected the native authority/scheduler to an explicit `--broker` worker mode:
  private host JSONL, literal IPv4 loopback, one length-framed agent request per
  connection and one graph owner. Added total input/output deadlines, aggregate
  byte reservations, per-grant/global connection limits, pre-dispatch disconnect
  cancellation, host EOF/close cleanup and a lost-wakeup shutdown regression.
  The ordinary worker mode still creates no listener.
- Added mutual per-connection HMAC-SHA256 proofs before command transfer. Agent
  credentials never appear in a loopback request; its authenticated identity is
  supplied internally. Fresh client/server challenges reject replay and separate
  proof domains reject reflection. Current grant authority is checked during
  handshake, admission and dispatch. A fixed public vector agrees with Python
  hashlib/hmac, Node crypto and the Rust implementation. These local peer proofs
  are not encryption, remote TLS or a sandbox against host-privileged code.
- The complete local context gate passes formatting, strict all-target Clippy,
  99 all-feature tests, one doctest and 48 core-only test/doctest invocations.
  Nine real worker/loopback tests include twelve scoped clients, competing
  proposals, malformed/oversized frames, lost clients, shutdown, replay/reflection,
  mid-handshake revocation and per-agent connection saturation. Logs are retained
  under `CIGAR/releases/cigar-0.14.0-development/broker-authenticated-worker-source-checks`.
  Those clients are Rust driver threads, not independent installed Python/Node
  agent processes. SDK facades, durable recovery, hosted platform execution,
  performance/fairness measurements and the 24-hour soak remain pending.
- Added public Python and Node `LocalContextBroker`, `LocalContextClient`, grant
  connection and wire types. Both SDKs reuse their existing worker lifecycle and
  keep legacy graph constructors/behavior. Connection exports require explicit
  protected IPC; ordinary representation is redacted. Clients authenticate the
  server before disclosing context, enforce a total deadline and bounded pending
  calls, and preserve definite versus unknown dispatch outcomes without retries.
- Independent 1/5/12-agent process tests now run in Python, Node and mixed-language
  configurations. They check shared/private scopes, cross-owner ticket denial,
  stale versus unaffected work, proposal admission/CAS, exact submission review,
  grant revocation and invalid-client isolation. Fault tests cover malformed host
  replies, incompatible workers, impersonating peers, partial/oversized frames,
  lost post-dispatch replies and cleanup. A new partial-prefix test exposed Node
  reader starvation of timeout callbacks; consuming partial bytes before waiting
  fixes it, with valid fragmented-response and deadline regressions.
- Full local SDK validation: 394 Python tests plus 39 subtests, and 102 Node tests
  pass. Python coverage is 93.21% statements and 86.32% branches; the new broker
  module is 100% on both and has a mandatory 95%/90% gate. Existing critical-module
  thresholds pass. Strict Python typing, changed-file lint and local-asset drift
  checks pass. Twenty-one release distribution/input/policy tests pass after
  replacing the policy test's stale 0.12 literal with the release identity.
- Native validation again passes formatting, strict Clippy, 99 all-feature tests,
  one doctest and 48 core-only test/doctest invocations. Logs are retained under
  `CIGAR/releases/cigar-0.14.0-development/broker-sdk-native-source-checks`; Python
  coverage is retained alongside them. Native distribution builds now select
  `bpe,broker`, and distribution CI runs Node before mixed-language Python tests.
  The SDK guide documents authority, provenance, review limits and uncertainty.
  No new artifact, cross-platform, performance, durability or release claim is
  implied by these source tests.
- Generated-client drift checks pass using the retained local Go formatter.
  Expanding the release tests to all five distribution modules exposed older
  version coupling: eight legacy stable tests reject the current alpha identity
  through the explicit handoff allowlist, and one platform-inventory assertion
  still names a 0.12 wheel. The other 33 tests pass. These remain Q2/Q3 release
  tooling work; the allowlist has not been weakened to label an alpha as stable.
- Added an opaque, bounded Rust evidence checkpoint codec and fresh-authority
  restoration. It preserves source versions, provenance/lineage, withdrawal
  tombstones and dangling/symmetric relations without retaining grants, tickets,
  proposals, drafts or reviews. Restore checks the intended domain, current graph
  and retention limits, canonical encoding/digest, endpoint ownership and acyclic
  lineage. Saved remaining lifetime caps restored expiry, and a clock preceding
  checkpoint capture is rejected. Checkpoints are private evidence, not signed
  authority or rollback protection.
- Eight recovery regressions pass, including old-credential/review rejection,
  stale/expired derivations, reserved withdrawn node IDs, contradiction reference
  counts, tampered and structurally forged checkpoints, current limits and exact
  byte bounds. Atomic storage, journal durability, kill/restart fault injection
  and the SDK persistence path remain B3 work; no crash-recovery claim is made.
- The complete native checkpoint gate passes formatting, strict Clippy, 107
  all-feature tests, one doctest and 48 core-only test/doctest invocations. Logs
  are retained in `broker-checkpoint-source-checks` under the development evidence
  directory. Existing Python/Node behavior is unaffected by this Rust-only codec;
  neither SDK advertises a persistence capability yet.
- Implemented opt-in Unix evidence storage behind `broker-persistence`, using the
  already-pinned embedded SQLite dependency. An exclusive writer commits the
  bounded checkpoint and rolling, hash-chained revision receipt together before
  acknowledging source replacement, proposal admission or relationship changes.
  Effective durability/resource settings are verified, and each restart records
  a fresh epoch before exposing a listener. Grants, proposals, tickets, drafts,
  reviews and execution permissions remain transient.
- The store requires a private host-owned directory, protected ancestry, regular
  single-link database files and safe sidecars. It rejects path replacement,
  unsafe permissions, unknown schemas, corrupted chains and oversized records.
  It never repairs these conditions by resetting the graph. Failed durability
  after memory mutation terminates the owner without a success or definite-failure
  receipt. Both SDKs expose explicit storage options and reject a worker that
  silently ignores requested persistence.
- Seven native storage regressions cover exclusive ownership, bounded receipt
  retention, withdrawal, corrupt stores, full/over-limit writes, path aliasing,
  maximum escaped source locators and exhausted forged sequence numbers. The
  crash parent invokes its otherwise-ignored child at four transaction boundaries,
  forcing dirty-page spill and abrupt process exit. Recovery returns the old
  committed state before commit and the new complete state after commit. These
  are process-crash tests, not power-loss qualification.
- Complete local validation passes 401 Python tests plus 39 subtests, all 104
  Node tests, and the native context gate with 114 all-feature tests, one doctest
  and 48 core-only test/doctest invocations. The seven Python and two Node storage
  cases were rerun against the final bounded native implementation; they include
  killed-worker recovery, old grant/ticket/review rejection, admitted proposals,
  edges, withdrawal, owner exclusion and uncertain-write closure. Python coverage
  is 93.23% statements/86.38% branches overall and 100%/100% for the broker facade.
  Strict typing, lint/format, generators, current-version consistency, all-target
  Clippy with and without storage, and 21 distribution/input/policy tests pass.
  Final native logs are in `broker-durable-bounds-source-checks`; SDK logs and
  coverage use the `broker-durable-` prefix in the development evidence directory.
- Windows storage is deliberately unavailable until its private-directory and
  file-identity boundary is implemented and qualified. The full-image storage
  prototype still needs paired CPU/RSS/disk/latency profiling and hosted filesystem
  fault tests. Defaults remain in memory, ordinary graph behavior is unchanged,
  and no performance, independent efficacy, platform or release qualification is
  claimed. The earlier release-profile test failures remain Q2/Q3 work. Source
  versions remain at the development alpha identity; no v0.14 publication occurs.
- Added the Windows storage boundary in the existing audited `cigar-windows-ipc`
  adapter. It checks the process owner, a protected inheritable owner-only DACL,
  local fixed NTFS, single-link regular files and unchanged file identities.
  Live directory handles omit write/delete sharing; the database handle prevents
  replacement. UNC paths, junctions/reparse points and alternate streams fail
  closed. The context crate retains `unsafe_code = "forbid"`. The adapter's
  optional named-pipe feature preserves the existing Honey consumer while keeping
  Tokio out of the standalone context dependency closure.
- Added explicit `create_directory` to Rust, Python and Node host options. It
  creates only a final private directory, requires an existing parent and never
  rewrites existing permissions. Added Windows ACL/inheritance, replacement,
  hardlink, junction and invalid-path tests, and made the common SQLite crash/
  corruption/limit tests and both SDK recovery suites run on Windows.
- Local validation passes 401 Python tests plus 39 subtests, 104 Node tests with
  no skips, and the complete native gate: 115 all-feature tests, one doctest and
  48 core-only invocations. The bounded crash parent exercises four abrupt-exit
  boundaries. Strict typing and generated-local-asset checks pass. Native logs
  are in `broker-windows-source-checks`; SDK results use the
  `broker-windows-` prefix in the development evidence directory.
- A SHA-256-verified Rust 1.92 Windows standard library allowed cross-target
  compilation and strict Clippy of the Windows adapter and tests, with and without
  named-pipe support. This does not execute Windows kernel behavior. The three-OS
  source workflow now includes those adapter tests and independent Python/Node
  broker consumers, followed by related-crate archive verification. Hosted results
  remain required before claiming Windows storage support.
- Local related-crate archive verification succeeds with the public crates.io
  index available. Cargo 1.92's offline package verification hit an internal
  "no hash listed" failure for its temporary registry; both failed diagnostics
  and the successful online verification are retained. No model provider was
  called, and packaging uploaded no source. Exact installed distribution,
  performance, power-loss and release qualification remain incomplete.
- Profiled the full-image store with eight paired fresh-process cohorts at
  100/1,000/5,000 documents. Repeated digest/encoding allocations caused macOS to
  retain freed large buffers. Checkpoint hashing now streams identical canonical
  bytes and the store reuses one bounded encoding buffer. The follow-up paired
  comparison reduced 5,000-document combined sampled RSS from 294 MB to 158 MB
  (about 46%). Update latency remained near 35 ms and compile latency rose about
  3.4%; no general speed or release non-regression claim is made.
- All 96 comparison processes returned matching rendered context, including 48
  durable restore checks. The native gate passes 116 all-feature tests, one doctest
  and 48 core-only invocations. Seven Python and two Node persistence tests pass
  against the release worker. Six harness tests check failure retention, process
  weighting and output equivalence. Exact-byte/boundary tests cover buffer reuse.
  See [the storage profile](context-sdk-0.14.0-storage-profile.md) for raw-evidence
  identities, limitations and the unresolved full-image write cost. B3/R2/Q1 and
  hosted/installed qualification remain incomplete.
- Added a bounded, host-only execution binding in the native broker and both SDKs.
  It commits to an exact already-prepared effect intent, complete reviewed
  submission, current source/view authority and host reviewer-policy revision.
  Fresh revalidation precedes a single successful take; changed source/provenance,
  policy, verdict, submission, epoch, effect identity or expiry is rejected.
  Replacing a draft invalidates its binding and checkpoints retain no execution
  permission. The record does not grant tool authority, dispatch, sign a receipt,
  or replace Honey's effect journal/reconciliation semantics.
- Local validation passes 410 Python tests plus 39 subtests and all 113 Node
  tests. Native formatting/strict Clippy pass with 122 all-feature tests, one
  doctest and 48 core-only invocations. Six new native tests include all-field
  substitution, single consumption, quota/byte limits, host-only command decoding
  and restart rejection. SDK tests exercise the actual worker, current-state
  changes and explicit capability refusal. Python coverage is 93.26% statements
  and 86.42% branches overall; broker coverage remains 100%/100%. Strict mypy
  and local asset checks pass. Logs use the `broker-execution-` prefix under the
  development evidence directory. This completes a context-side primitive, not
  P2's Honey/HUMIDOR integration or the final cross-platform/release gates.
- Added an opt-in SDK bridge using only the existing `getEffectStatus` and
  `dispatchEffect` operations. It validates exact effect/intent identity and
  authorized state, resolves current host review after the read, consumes the
  native binding, and sends with the exact observed u64 revision and supplied
  idempotency key. Each call has one attempt. Post-consumption failures retain a
  content-safe uncertainty error with explicit access to the handoff; no alternate
  effect, approval, polling loop or retry journal is created.
- Both generated clients now exercise the actual Honey HTTP handlers, SQLite
  effect engine and worker through separate native context processes. Twelve
  local scenarios cover success, a lost acknowledgement after durable claim,
  stale context, intent substitution, worker authorization revocation and an
  ambiguous connector observation followed by reconciliation. Rejected cases
  make no dispatch call; accepted cases make one; reconciliation makes no second
  connector send. Independent SQLite connections verify the retained outcome.
  The connector and trusted authority are deterministic fixtures, so this proves
  execution-path invariants rather than independent task efficacy or production
  deployment policy. Full logs are in `context-effect-honey-integration-02.log`
  under the development evidence directory. The first run's expired fixture
  clock failure is retained in `-01.log`; production timeout checks were unchanged.
- Context is checked before Honey queue admission, without a lock across later
  worker execution. Execution-critical source freshness must also be enforced by
  the effect's existing preconditions. HUMIDOR must explicitly adopt the bridge
  through its existing generated-client boundary; its excluded ContextGraph
  profile has not been enabled. P2 and final release qualification remain open.
- Full regression validation for this bridge passes 452 Python tests plus 39
  subtests, all 146 Node tests and 192 ordinary daemon library tests. The two
  default-ignored Rust entries were exercised separately: the special-file helper
  by its bounded parent and the new SDK test explicitly with all twelve scenarios.
  Strict daemon Clippy and Python typing pass. Python coverage is 93.42%
  statements / 86.57% branches overall; `context_effects.py` and `broker.py` are
  both 100% / 100%. The new module has a mandatory 95% / 90% gate. Coverage-policy
  tests, changed-file lint/format and local-asset checks pass. Regression logs and
  coverage use `context-effect-adapter-` under the development evidence directory.
- HUMIDOR adoption has a concrete dependency boundary: the current Core
  `services/cigar_sdk_identity.py` and `config/cigar-composition.v1.json` require
  the exact 0.9.4 SDK and artifact hashes. CEDAR's product authority also excludes
  Context Graph from the HOL-Cluster profile. Do not disable either check or
  enable that profile to make a test pass. Qualify a separate generic HUMIDOR
  composition against frozen candidate artifacts and record its packet receipt
  before claiming adoption. The existing Core/CEDAR working changes were left
  untouched. Native and SDK Honey integration does not close this requirement.
- Added opt-in current-state selection explanations to the native graph, views
  and broker, with Python and Node facades. The original request/snapshot shapes
  and selector are unchanged; an observer records only successful selection
  steps, complete added IDs and retrieval signals. Explanations name the exact
  tokenizer and original snapshot, recheck whole-scope freshness/provenance, and
  disclose no rejected IDs or source/query text. Selected IDs remain sensitive.
  This provides inspectability, not a semantic truth judgment or efficacy gain.
- Local explanation validation passes 128 all-feature native tests, one doctest
  and 53 core-only test/doctest invocations, with formatting and strict Clippy.
  All 459 Python tests plus 39 subtests and all 153 Node tests pass. Independent
  1/5/12-agent and mixed-language consumers now also compare the explanation's
  added IDs to their selected citation IDs. Full coverage is 93.45% statements /
  86.64% branches; the broker and effect adapter remain 100% / 100%. Strict typing,
  changed-file Python formatting/lint and generated local assets pass. Evidence
  uses `selection-explanation-` under the development evidence directory. Hosted
  execution, independent task-quality comparisons and full performance gates
  remain pending; this does not close R1.
- Added an explicit parser-boundary partitioner to the native document API and
  both SDKs, including host-only broker preprocessing. It preserves every UTF-8
  byte and LF/CRLF boundary, returns absolute citation lines, bounds input/chunk
  counts and rejects invalid partitions. It introduces no parser dependency,
  file access, graph mutation or evidence admission. A packaged Python AST
  example preserves top-level decorated/async units and adds explicit fixture
  dependencies; it makes no general dependency-inference or sandbox claim.
- Local ingestion validation passes 131 all-feature native tests, one doctest
  and 56 core-only test/doctest invocations, with formatting and strict Clippy.
  All 470 Python tests plus 39 subtests and all 156 Node tests pass. Coverage is
  93.54% statements / 86.74% branches; all critical-module gates pass. Strict
  typing, changed-file lint/format and generated local assets pass. Evidence uses
  `syntax-ingestion-` under the development evidence directory. The twelve real
  Python/Node Honey scenarios also pass again after these changes; readback is
  retained in `context-adapters-honey-integration-01.log`. Parser boundaries and
  selection explanations still need independent matched-budget task comparisons;
  R1 and final platform/artifact/performance qualification remain incomplete.
- Added a recorded-answer producer for the common evaluation contract. Exact
  measured artifact identities, producer/model identities, displayed text, claim
  spans and original corpus/oracle annotations are retained. Twenty-two metrics
  preserve denominators, failure outcomes, useful-answer yield and independent
  task clusters. Re-importing the retained originals reproduces the report.
  The adapter does not judge claims, prove annotation independence or run models.
  Authored unit cases remain invariant evidence, not hallucination prevalence.
- All 34 common-evaluation tests and seven existing answer-metric tests pass,
  including hand-calculated scores, old/new metric agreement, lost/reused answers,
  identity drift, incomplete annotations, unknown confidence, zero denominators,
  failed/unsupported pairs and hidden stratum regressions. Changed-file lint and
  formatting pass; `answer-import-tests-01.log` retains the results outside the
  worktree. The existing three-OS evaluation job discovers these tests. Actual
  independent labeled answer studies and Hiero terminal-oracle import remain
  outstanding; E1/E2 and release efficacy gates are not complete.
- Profiled root, one-source and full-scope compilation at 100/1,000/5,000 cold
  documents. Native samples identify repeated ordered-tree lookups during scope
  commitment and authorized-document counting. Dense scopes now merge ordered
  collections; sparse scopes retain direct lookups. No authority is cached and
  exact scope/snapshot identities remain unchanged. Native formatting and strict
  Clippy pass with 132 all-feature tests, one doctest and 57 core-only invocations.
- The paired before/after comparison retains 144 successful process runs and
  identical complete results. Full-scope median compilation falls 12.7%, 28.7%
  and 41.8% at the three corpus sizes. The 5,000-document paired RSS change is
  +0.50%. The 1,000-document one-source and 5,000-document root controls regress
  7.2% and 6.4% respectively; no measured cell exceeds the existing latency/RSS
  guardrails. This is a source optimization diagnostic, not a version-wide
  non-regression or task-quality claim. Twelve benchmark-reducer tests pass.
  [The scope profile](context-sdk-0.14.0-scope-profile.md) records exact identities,
  uncertainty, regressions and limitations. Full R2/Q1 qualification stays open.
- Complete SDK regression tests against the optimized worker pass 470 Python
  tests plus 39 subtests and all 156 Node tests. Statement/branch coverage remains
  93.54%/86.74% overall; all critical-module coverage gates pass. Logs and coverage
  use `scope-intersection-` under the development evidence directory.
- Added the offline Hiero campaign producer with distinct process completion,
  declared context checks and terminal field-oracle outcomes. Complete readbacks
  bind exact execution, task, target revision, oracle and reader identities;
  missing/partial/synthetic readbacks remain unavailable. Raw iteration receipts
  cannot be omitted, duplicated or reused. The importer executes no supplied
  code and does not infer reader independence from its hash.
- Reprocessed the retained 50-campaign v0.11/v0.12 archive after checking all
  308 original Hiero source hashes. Both versions completed 20/25 campaigns;
  all EVM campaigns stopped early. Independent terminal outcomes are unavailable
  for every attempt. The 500-observation common report preserves those gaps and
  reproduces byte-identical manifest/results from its copied originals. This is
  historical invariant evidence, not a v0.14 quality or performance comparison.
  [The evidence audit](context-sdk-0.14.0-hiero-evidence.md) records hashes and
  limitations. All 47 common-evaluation and seven answer-metric tests pass,
  including thirteen new Hiero cases; lint/format pass. Prospective independent
  task oracles and the E2 release comparison remain outstanding.
- Added bounded host-only source transactions and Python/Node iterable convenience
  APIs. Old evidence remains current during staging; one commit rechecks existing
  source CAS, ownership, provenance, derivation and graph limits. Four expiring
  staging slots share existing retention bounds. Invalid batches never publish
  partial input; pending stages are absent from checkpoints and cannot survive
  a new authority epoch. Durable failure keeps the existing unknown-outcome
  shutdown contract. Both SDKs preserve the original error and never retry a write.
- A 34 MiB source plus a probe (137 documents) now crosses the unchanged host
  frame limit using 35 batches. Both SDKs reject the complete-list request before
  dispatch and successfully commit batches; Node verifies every document's text
  and citations before and after recovery. Eight paired ingestion cohorts retain
  96 observations. At 8 MiB, sampled total RSS falls 23.7% in memory mode and
  19.3% with SQLite, with median latency increases of 1.6% and 0.7%. A 74.970 ms
  1 MiB SQLite outlier remains reported; there is no general speed or tail claim.
  [The batch report](context-sdk-0.14.0-batch-ingestion.md) records bounds, hashes,
  rejected initial diagnostic configurations and the full measurement limitations.
- Batch validation passes 140 all-feature native tests, one doctest, 57 core-only
  invocations, strict Clippy/formatting, 480 Python tests plus 39 subtests and all
  164 Node tests. Coverage is 93.60% statements / 86.80% branches overall, with all
  critical-module gates met; broker/effect modules remain 100% / 100%. Sixteen
  benchmark tests, strict typing, changed-file lint/format and both generator
  checks pass. R2/Q1 still require full workload and hosted/platform qualification.
- Added independent process load/fault harnesses and retained-data verification.
  The local 18-cell fault matrix passes 3,879 checks across 1/5/12 Python, Node
  and mixed clients, memory/SQLite, scope isolation, CAS proposals, revocation,
  quotas, incomplete authenticated connections, abandoned clients and crash
  recovery. Nine SQLite cells recheck 13,878 document instances across views.
  Thirty-four benchmark reducer tests pass. This is authored source qualification,
  not independent answer quality or a 24-hour reliability result.
- Preserved an incomplete first load study: four of 180 completed cells failed
  its complete-window gate, which incorrectly compared a monotonic workload with
  wall time. None of those 180 cells recorded an API failure. Explicit monotonic
  window observations and regression tests correct the harness without changing
  limits. A new frozen eight-cohort, 288-cell study is running; old cells are not
  pooled into it. See the [broker qualification report](context-sdk-0.14.0-broker-qualification.md).
- Pushed the approved source branch through `059c0155385da5b2012b361d99a1ff8730e39199`.
  The [first hosted run](https://github.com/hashgraph-online/hol-cigar/actions/runs/36331345626)
  passes the common evaluation suite on all three operating systems and the
  compiler job. Linux/macOS SDK steps fail because the nested build script cannot
  find the pnpm shim; CI now enables Corepack before running it. Windows persistence
  tests return `Unavailable`; a staged SQLite interoperability test and earlier
  Windows adapter checks will locate that failure. No Windows storage qualification
  is claimed while this remains unresolved.
