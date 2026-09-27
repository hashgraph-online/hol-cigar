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
| B1 | Share one graph across independent agent processes | Supported broker/client API in both SDKs, authenticated caller-to-view binding, host-only policy/reviewer controls | Pending |
| B2 | Bound shared-agent resource use and conflicting writes | Per-agent quotas, bounded fair admission, cancellation/uncertain mutation semantics, source revision conflict tests | Pending |
| B3 | Restore context safely after restart | Atomic versioned journal/checkpoint restore, new authority epoch, rejected old handles/reviews, retention/withdrawal tests | Pending |
| P1 | Admit evidence with meaningful provenance | Host-owned source identity/version/time/trust and derivation lineage; unverified proposals remain untrusted | Pending |
| P2 | Integrate review and execution authority | Reviewer port and complete displayed-claim coverage; bind checked context to existing Honey effects/HUMIDOR adapter, no blind retry | Pending |
| R1 | Improve retrieval and explanation through optional adapters | Scoped hybrid/reranking input, syntax-aware ingestion, safe selection explanation, tokenizer identity; held-out evidence tests at equal budget | Pending |
| R2 | Remove measured ingestion/throughput bottlenecks | Profile source/scope hashing and IPC; transactional batches and bounded APIs; paired latency/RSS evidence | Pending |
| E1 | One auditable evaluation result contract | Versioned schema with exact artifact/corpus/treatment/task identities and reproducible raw observations | Pending |
| E2 | Prove efficacy against meaningful baselines | Independent gold task/evidence labels, Hiero terminal oracles, matched-budget retrieval/task comparisons and confidence intervals; replay separated from generation claims | Pending |
| E3 | Qualify 1/5/12-agent operation | Shared/private/overlapping scopes, hostile source content, lost update, revoke, restart, saturation and short fault schedules; subsequent 24-hour 12-agent soak | Pending |
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
