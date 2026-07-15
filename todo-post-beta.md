# CIGAR post-beta development feature execution plan

Audience: Codex implementation agents, CIGAR maintainers, security reviewers, release engineers,
SDK maintainers, and operators

Observed source baseline: `56a5a1346bdfd362f67c279f4f8cd5d4ba7c46b2`; this hash identifies
the audited development snapshot only and is not a release candidate

Target: move every capability explicitly excluded from `0.1.0-beta.1` from development source to
an installed, qualified, published, and supportable full-product profile without weakening the
initial beta boundary

## Outcome and scope

The initial beta is intentionally limited to local workspace-metadata administration. This plan
covers every identifier in `packaging/beta/capability-policy.v1.json`, the full 45-operation service
and SDK contract, the Claude Code/MCP integration, the optional dashboard, and the operational work
described by the development documentation.

Most of the semantic kernel is already implemented in the development source tree. Therefore,
“implement” in this plan means all of the following:

1. close any remaining behavior or integration gap;
2. connect the behavior only through its reviewed authority and persistence boundaries;
3. add positive, negative, property, fault, compatibility, and installed-artifact tests;
4. package it in an exact, reproducible artifact;
5. qualify that artifact on every claimed platform and deployment profile;
6. publish the already-qualified bytes without rebuilding; and
7. change website availability only from authenticated publication evidence.

Source code, checked boxes in historical work packets, generated schemas, and passing workspace
tests are useful evidence, but none alone makes a capability beta-available or supported.

### Current execution scope — 2026-07-14

- [x] Limit this execution cohort to native Apple-silicon macOS
      (`aarch64-apple-darwin`). Intel macOS/Rosetta, Linux, Windows, and Linux OCI artifacts remain
      unqualified and must not inherit this cohort's evidence.
- [x] Preserve fuzz accumulation and soak as mandatory release gates while deferring their
      execution for this run. They remain open and are not represented as passing evidence.
- [x] Keep the post-beta cohort inventory-only until exact installed bytes advance through
      integration, packaging, qualification, publication, and support independently.

## Authority and relationship to existing plans

- `prd.md` remains the normative v1 behavior, invariant, and release specification.
- `packaging/beta/capability-policy.v1.json` remains the closed authority for
  `0.1.0-beta.1`. Do not broaden or reinterpret it.
- `IMPLEMENTATION_STATUS.md` and `docs/execution/work-packets.yaml` remain the durable packet
  status. WP00–WP18 are development-complete; WP19–WP21 are incomplete; WP22 has not started.
- `todo-launch.md` owns the detailed WP19–WP22 quality, packaging, signing, and promotion gates.
  This file is the feature-oriented dependency map into those gates, not a replacement.
- `todo-dashboard.md` and `docs/dashboard/post-main-integration-todo.md` own the optional dashboard
  control plane. This plan references them instead of creating a conflicting second backlog.
- The website is a presentation consumer. It must not become the source of implementation or
  availability truth.

Recommended release strategy: preserve `0.1.0-beta.1` as an immutable narrow lane, exercise the
post-beta capabilities through internal capability cohorts, and qualify the complete PRD-defined
surface as the selected full-product release. If the release owner does not select `1.0.0`, amend
the PRD and all version contracts before changing package metadata.

## State model for every capability

Every capability must move monotonically through this state model:

| State                | Required evidence                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------- |
| `specified`          | Versioned contract, authority boundary, limits, error semantics, and non-goals            |
| `implemented-source` | Real behavior with no placeholder success and owner-layer tests                           |
| `integrated`         | Production composition, persistence, cancellation, recovery, and adjacent-service tests   |
| `packaged`           | Exact artifact producer, allowlisted contents, SBOM, license inventory, and provenance    |
| `qualified`          | Installed-byte platform/profile tests, security review, faults, performance, and runbooks |
| `published`          | Signed immutable bytes and metadata read back from the public distribution endpoint       |
| `supported`          | Named owners, compatibility window, monitoring, incident/rollback path, and website claim |

Unknown, skipped, waived, stale, dirty, synthetic, or source-only evidence never advances a state.
The capability registry introduced by FULL-000 must record these states separately so that a source
implementation cannot accidentally activate a package, command, download, or website claim.

## Complete capability coverage

The following table accounts for all 29 closed beta exclusions. “Implemented” means development
source exists at the observed baseline; it does not mean qualified or supported.

| Beta exclusion       | Observed development state                                                                                                                          | Owning packet     |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `catalog-discovery`  | Git/filesystem discovery, preview, ignore/secret policy, snapshots, refresh, and invalidation implemented                                           | FULL-200          |
| `catalog-ingest`     | Atomization, provenance, lineage, tombstones, publication, and code intelligence implemented                                                        | FULL-200          |
| `catalog-query`      | Catalog query, atom batching, lifecycle filtering, and status operations implemented                                                                | FULL-200          |
| `context`            | Plan, compile, delta, get, manifest, explain, materialize, revalidate, caches, and materializers implemented; provider tokenizer gap remains        | FULL-200          |
| `retrieval`          | Exact, lexical/FTS, temporal, graph, active-state, consistency, partition, and fallback paths implemented                                           | FULL-200          |
| `handoff`            | Signed preview/create/accept/revoke/result/merge flow and attenuation implemented                                                                   | FULL-300          |
| `space`              | Create/fork/publish/log/events/checkpoints/conflicts/leases and project federation implemented                                                      | FULL-300          |
| `replay`             | Evidence, invocation, observational, completeness, recorded providers, and explicit tenant-bound local macOS live-comparison composition implemented | FULL-300          |
| `policy`             | Hard gates, rule DAG, capabilities, redaction, denied-existence views, cache, and revocation implemented                                            | FULL-200          |
| `daemon`             | Production service composition and lifecycle implemented in development source                                                                      | FULL-400          |
| `effects`            | Durable kernel plus disabled-by-default local macOS stock HTTPS and descriptor-confined filesystem transports implemented                            | FULL-300          |
| `extensions`         | Signed manifest, capability broker, WASI/subprocess hosts, remote bridge, and resource enforcement implemented                                      | FULL-400          |
| `installers`         | No supported installer exists; contracts and intended matrix are incomplete                                                                         | FULL-900          |
| `macos`              | Source builds and some checks exist; native archives, signing, notarization, and installed qualification are incomplete                             | FULL-900          |
| `mcp`                | Bounded MCP 2025-06-18 stdio server, ten tools, and eight resource families implemented                                                             | FULL-600          |
| `oci`                | Dockerfile and image contract exist; deterministic multi-architecture producer, signing, and installed qualification are incomplete                 | FULL-900          |
| `otlp`               | Optional bounded OTLP/gRPC pipeline has explicit CA roots, a complete 43-family/137-series closed schema, owning-subsystem instrumentation, and live collector qualification | FULL-400          |
| `plugin`             | Claude Code plugin lifecycle, hooks, MCP integration, skills, and compatibility record implemented                                                  | FULL-600          |
| `remote`             | HTTPS client/service contracts, authorization files, TLS, deadlines, and compatibility exist in development source                                  | FULL-400/FULL-500 |
| `sdk`                | Rust, TypeScript, Python, and Go implement 45 operations and 70 nominal types; supported ecosystem packages do not exist                            | FULL-600/FULL-900 |
| `shared`             | PostgreSQL, encrypted object storage, RLS, outbox, migrations, failover, and deployment assets implemented                                          | FULL-500          |
| `vector`             | Disabled-by-default provider-neutral local int8 backend is wired into the macOS local daemon with durable generations and partition-exact fallback-safe query approval | FULL-200/FULL-500 |
| `windows`            | Source and named-pipe implementation exist; native execution, ACL, signing, and installed qualification are incomplete                              | FULL-400/FULL-900 |
| `arm`                | Target support is represented, but native ARM artifacts and multi-architecture image qualification are incomplete                                   | FULL-900          |
| `backup`             | Signed local backup/verify/restore and shared backup design implemented; installed live exercises remain                                            | FULL-300/FULL-900 |
| `garbage-collection` | Store-owned plan/run, retention, legal-hold, and backup guards implemented; installed live exercise remains                                         | FULL-300/FULL-900 |
| `diagnostics`        | Readiness, metrics, security/deep doctor, and content-free support bundle implemented                                                               | FULL-400/FULL-900 |
| `serving`            | HTTP/JSON, gRPC, SSE, Unix socket, Windows named pipe, TLS/OIDC/mTLS, and quotas implemented                                                        | FULL-400/FULL-500 |
| `completion-man`     | Full CLI completion and manual-page generators exist; package/install qualification remains                                                         | FULL-400/FULL-900 |

## Additional development-only surfaces

| Surface                    | Current status                                                                                                                                             | Plan ownership                  |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| Context ABI and public API | `cigar.context.v1`, 45 operations, 70 payload types, OpenAPI, Protobuf, JSON Schema, and vectors exist                                                     | FULL-100                        |
| Claude Code adapter        | Development implementation; compatibility claim is currently one Claude Code version on Apple-silicon macOS                                                | FULL-600                        |
| Optional dashboard         | Observer plus three independently receipt-verified non-soak controls are integrated for native Apple-silicon macOS; fail-closed restart reconciliation, transactional byte ledgers, child CPU/core/file/FD limits, and polled RSS/process ceilings exist; escaped-child containment, soak, packaging, and full browser qualification remain | FULL-650 and dashboard backlogs |
| `cigar-soak`               | Plan/result generation and verification exist; production workload driver deliberately returns `DriverUnavailable`                                         | FULL-650/FULL-700               |
| Demos and SDK workflows    | Seven demos and four source/recorded SDK workflows exist                                                                                                   | FULL-800                        |
| CIGARBench                 | Harness and local dry-run evidence exist; independent corpus/evaluator qualification does not                                                              | FULL-800                        |
| Shared operations          | Runbooks and development manifests exist; managed identities, services, native filesystems, and live exercises remain external                             | FULL-500/FULL-900               |
| Website development lane   | Describes the source repository at a pinned revision; it is not availability evidence                                                                      | FULL-1000                       |

OpenAI/Codex, Gemini, Cursor, Copilot, and other provider-specific adapters are not checked-in
development features. They are future possibilities built on the provider-neutral API and MCP
contracts. Adding one requires a separate ADR/PRD, public host-surface contract, threat model,
compatibility record, artifact, and qualification lane; it is not silently included in this plan.

## Known greenfield or incomplete implementation gaps

These items require new production behavior, not only requalification:

- [x] Select and implement at least one production vector backend adapter, or explicitly remove
      vector support from the first full-product claim. The selected provider-neutral
      `cigar.local-quantized-vector.v1` adapter accepts only typed processor-approved int8 vectors,
      binds model artifact, dimension, preprocessing, distance, quantization, adapter, policy
      partition, processor, and index-generation fingerprints, and persists immutable macOS
      generations through descriptor-pinned atomic publication/activation and bounded recovery.
      FULL-200 now wires it into strict local-only daemon configuration while shared mode and the
      default profile keep it disabled.
- [x] Add exact tokenizer implementations for every claimed materialization target and keep all
      other provider targets unsupported. The macOS cohort claims only the two strict-UTF-8,
      provider-neutral reference profiles; their immutable algorithm/configuration fingerprints
      bind provider/model tuples, bundle/materialization provenance, caches, replay inputs, and
      restart behavior. Anthropic, OpenAI, and every unknown or cross-paired target fail closed
      without estimation or substitution.
- [x] Add a stock live HTTPS effect transport and credential boundary for each claimed connector.
      The only claimed stock live connector is the explicitly enabled local macOS
      `idempotent_http` profile. Its strict registry requires
      `cigar.idempotent-effect-http.v1`, one canonical HTTPS endpoint, sorted unique public address
      pins, bounded connect/request/response limits, and an owner-private credential handle bound
      to the exact origin/project/resource and validity window. The client uses direct resolver
      overrides with platform TLS chain/hostname verification and disables ambient DNS, redirects,
      proxies, referrers, retries, decompression, and idle reuse. Dispatch/lookup wire outcomes keep
      ambiguous success in `UNKNOWN`; shutdown and deadline cancellation are conservative; errors
      and debug views are secret/content-free. Registry, transport, and bootstrap regressions pass,
      including a real local two-certificate TLS hostname/trust/redirect test. The profile remains
      disabled by default, shared/non-macOS composition fails closed, and no third-party provider or
      installed artifact is claimed qualified.
- [x] Add an explicitly configured live replay/model-provider boundary if live comparison is a
      release claim. Keep recorded/non-live replay structurally unable to call it. The local macOS
      embedding API now requires the complete reviewed tenant-bound v1 profile while standalone
      `cigard` remains recorded-only; the full replay and focused daemon gates pass.
- [ ] Finish native Windows IPC execution and ACL enforcement; cross-compilation is not proof.
- [x] Finish complete PRD metric instrumentation for the local macOS runtime. One shared
      `cigar-observe` authority defines 43 families and exactly 137 maximum closed series; local
      OpenMetrics, the strict dashboard parser, and OTLP use identical names, help, kinds, label
      keys, and label domains. Catalog/compiler, mandatory-index, handoff, effect, repository-check,
      worker/lease, blocking-pool, transport-buffer, and process owners record direct observations;
      synthetic invalidation values were replaced by exact newly claimed catalog messages and real
      queue age. Authenticated API failures and actual full bounded HTTP/gRPC stream buffers are
      observed without operation or caller labels. The live loopback collector requires every
      family and series and rejects attributes outside the schema; private-CA HTTPS still rejects
      an unrelated valid CA. Local SQLite correctly leaves pool metrics at zero because it has no
      pool; live PostgreSQL pool observations remain FULL-500 ownership. Demo/benchmark outcomes
      remain signed evidence-document fields, not daemon labels. Focused owner regressions, complete
      affected crate suites, strict Clippy, warning-free Rustdoc, and content-canary gates are the
      evidence for this macOS-only item; fuzz and soak were intentionally skipped.
- [ ] Finish the optional dashboard process supervisor, verified evidence ingestor, allowlisted
      control dispatch, and real isolated `cigar-soak` workload/fault driver.
      Native Apple-silicon macOS now has fixed-ID/fixed-argv dispatch, startup-captured tool
      identities and version digests, private roots, cleared child environment, bounded content-opaque output,
      process-group cancellation, independently verified product receipts, and canonical supervisor
      receipts for three non-soak development profiles. SQLite v4 now provides fail-closed active-
      process reconciliation plus transactional aggregate output/evidence ledgers; child CPU/core/
      file/FD limits are hard, while RSS/process counts are polled every 100 ms. Automatic adoption,
      exhaustive escaped-child containment, kernel-hard memory/job-process limits, installed-
      artifact binding, and the soak driver remain open.
- [ ] Implement the remaining deterministic producers for the four deferred foreign native
      archives and the multi-architecture OCI index. Development-only producers now exist for all
      17 artifacts selected by the macOS profile, including every SDK distribution, both internal
      qualification tools, the Apple-silicon native archive, Homebrew tap/bottle, and Claude
      plugin, but none is candidate qualified, signed, notarized, published, or supported.

## Dependency order

```text
FULL-000 → FULL-100 → FULL-200 → FULL-300 → FULL-400
                                             ├─→ FULL-500 ─┐
                                             ├─→ FULL-600 ─┤
                                             └─→ FULL-650  │ optional artifact
                                                          ↓
FULL-700 → FULL-800 → FULL-900 → FULL-1000
```

Do not start long-running release-candidate campaigns until source-changing contract, integration,
producer, and command-plane work is frozen. A source fix during FULL-700 or later creates a new
candidate and invalidates affected and downstream evidence.

## FULL-000 — Establish one releasable development baseline

Dependencies: none

Owned paths: repository governance and status, `docs/execution/`, `packaging/`, `crates/xtask/`,
CI workflows, version metadata, external evidence tooling

- [x] Enumerate all 29 beta-excluded identifiers and map each to an owner packet.
- [x] Confirm that the development API registry contains 45 operations and 70 nominal payload
      types and that the website snapshot is pinned to the observed source revision.
- [x] Distinguish implemented-source capabilities from missing integration, packaging,
      qualification, publication, and support work.
- [ ] Preserve and reconcile the current dashboard, SDK, lockfile, documentation, and soak changes
      through ordinary review. Never freeze directly from the present dirty worktree.
- [x] Select `1.0.0` as the eventual PRD-defined release version and `1.0.0-dev.1` as the
      non-published development identity for the unfinished implementation run. Keep the immutable
      beta lane at `0.1.0-beta.1`.
- [x] Establish `packaging/product-version.v1.json` as the non-published version authority and
      propagate `1.0.0-dev.1` through the generator's first exact 44-file Cargo, SDK, plugin,
      artifact, archive, documentation-manifest, lockfile, and package-contract allowlist.
- [x] Close the remaining explicitly inventoried product-version consumers and Python PEP 440
      filename normalization in the same 63-file authority. Python artifacts and package-layout
      contracts derive `1.0.0.dev1` while embedded release records retain `1.0.0-dev.1`;
      intentional beta, protocol, compatibility, third-party, and fixture versions remain
      separate exact domains.
- [x] Add a machine-readable post-beta capability profile containing every ID above and separate
      `specified`, `implemented_source`, `integrated`, `packaged`, `qualified`, `published`, and
      `supported` fields. Keep the beta policy unchanged. The reviewed profile is
      `cigar.post-beta.macos-arm64.v1`; all states after `implemented_source` remain false.
- [x] Give every capability one code owner, authority boundary, persistence boundary, artifact set,
      platform/profile scope, test inventory, runbook, rollback/disable mechanism, and support
      owner. `packaging/post-beta-capability-ownership.v1.json` records all 29, explicitly marks the
      planned Homebrew tap and bottle artifacts, maps packaged MCP/hook bytes to the selected
      native-runtime archive, and defers Windows/OCI
      to separate profiles without a release or support claim.
- [x] Add `cigar.development.local.macos-aarch64.v1` as an exact 22-artifact projection for this
      run: 17 portable/macOS-arm64/SDK/plugin/qualification-tool artifacts remain planned, five
      foreign-platform artifacts are deferred, and no selected artifact lacks a checked contract
      and deterministic development producer. The conformance runner and CIGARBench tool are
      internal, unqualified harness artifacts only; fuzz, soak, benchmark efficacy, signing, and
      notarization stay unevidenced.
- [x] Compile the current development `cigar` and `cigard` sources with locked dependencies for
      `aarch64-apple-darwin`; verify native thin arm64 Mach-O outputs and the `1.0.0-dev.1` runtime
      identity. Keep this as compile-only evidence: no package, qualification, Developer ID
      signature, notarization, publication, or support state advances.
- [ ] Complete `todo-launch.md` LAUNCH-000 through LAUNCH-004: clean baseline, external evidence
      workspace, authoritative command plane, frozen release scope, and merge/nightly/weekly/RC CI.
- [ ] Make every release gate reject evidence written inside or rebound to the candidate, stale
      source descriptors, dirty/uncommitted source, empty attachments, non-finite metrics,
      prohibited result states, path escapes, and mutable evidence.

Exit gate:

- [ ] One clean committed integration baseline exists, but the artifact matrix still says
      `development`.
- [ ] Every PRD command dispatches to a distinct real gate and produces non-empty source-bound
      evidence.
- [x] No current beta command, dependency graph, artifact, or availability claim has expanded. The
      exact `beta-embedded` feature still exposes only the reviewed 12-command workspace-state
      surface, its 12 public-boundary tests pass, the neither/both feature combinations fail
      closed, the beta-only graph omits every post-beta CIGAR subsystem, and the descriptor-pinned
      beta/post-beta profile validators retain `0.1.0-beta.1` as a separate unqualified Linux
      lane. All full-product work remains inventory-only and cannot change beta availability.

## FULL-100 — Freeze protocol, compatibility, configuration, and migration contracts

Dependencies: FULL-000

Owned paths: `crates/cigar-protocol/`, `crates/cigar-canon/`, `crates/cigar-crypto/`, `spec/`,
`schemas/`, `sdk/capabilities-v1.json`, generated API/SDK/MCP/CLI metadata, migrations

- [ ] Freeze Context ABI `cigar.context.v1`, canonical JSON/CBOR, digest domains, UUID/key/signature
      behavior, errors, 45 operation IDs, 70 payload types, JSON Schema, Protobuf, OpenAPI, and
      conformance vectors.
- [x] Establish a development-only protocol drift baseline over the current 82-file generated and
      authoritative surface, with strict count/parity/path/digest validation and no release or
      clean-candidate freeze claim. Canonical behavior, cryptographic semantics, compatibility,
      migration, and cross-platform qualification remain open in FULL-100.
- [x] Generate CLI routes, API routes, SDK methods, MCP mappings, documentation tables, dashboard
      operation metadata, audit operation IDs, and retry classes from the same authoritative
      catalogs. The closed development projection binds 34 implemented CLI mappings and all ten
      MCP tools to the 45-operation registry; xtask generation now emits and validates the CLI,
      MCP, dashboard, API/SDK, audit, error/retry, and documentation consumers. The six projection
      authority/output files are part of the 82-file drift baseline, and hostile drift tests plus
      independent CLI, MCP, dashboard, API, and generator suites pass on macOS arm64.
- [x] Define additive-minor and breaking-major compatibility rules for schemas, errors, payloads,
      cursor/stream state, extensions, plugin compatibility, and stored records. The closed
      `cigar.protocol-compatibility-policy.v1` authority covers all 42 schemas, 45 operations,
      34 errors, 70 nominal payloads, cursor/stream state, the extension ABI/manifests, Claude
      compatibility, and SQLite/PostgreSQL records; its descriptor-pinned validator and 12-test
      hostile-filesystem suite pass without a release-freeze claim.
- [x] Add cross-language canonical-vector and differential tests for Rust, TypeScript, Python, and
      Go on every claimed architecture. The macOS-arm64-only cohort executes all four independent
      verifiers over 363 immutable valid/invalid vectors and the 100,000-record differential
      accumulator through `cargo xtask test vectors`; the gate passes on the claimed native host.
- [x] Add beta-to-full state fixtures. Prove the full binary reads beta-created administrative
      state without unintended mutation, preserves paths/IDs/generation, and either supports a safe
      downgrade or explicitly blocks it after a verified backup. The shared frozen decoder and the
      full-only `state inspect-beta`, `state import-beta`, and `state restore-beta` commands now
      validate hostile fixtures, emit only content-free receipts, preserve exact source bytes in a
      re-opened and digest-verified owner-private backup, explicitly map every path, identifier,
      link, active selection, and generation into an atomically published full-only schema, and
      restore exact beta bytes only into a distinct new empty recovery directory. Descriptor-pinned
      no-symlink walks, owner/mode/link-count bounds, no-replace publication, file/directory fsyncs,
      race/idempotency checks, and the imported schema enforce the in-place downgrade block while
      leaving the beta 12-command surface unchanged. The macOS source tests cover hostile inputs,
      tampering, containment, conflicts, dry-run/confirmation, partial staging cleanup, retry, and
      exact restore; installed process-kill and power-loss qualification remains a release gate and
      is not claimed here.
- [x] Keep SQLite and PostgreSQL migrations append-only. Test retained-version upgrade,
      interruption at every durable boundary, recovery, mixed-version operation, semantic-root
      equality, and unsupported downgrade behavior. The macOS-arm64 slice has a closed
      eight-logical-migration authority (four SQLite plus four PostgreSQL entries, each
      byte-identically mirrored in both migration trees), a real retained SQLite v1-to-v4 upgrade,
      and exact pre-recovery durable-prefix plus post-recovery semantic-root assertions after real
      process death at all 19 SQLite migration boundaries. Same-catalog compatibility and explicit
      unknown/incompatible/offline downgrade rejection never trust self-declared ledger metadata.
      The historical v1 exact-count reader correctly refuses v2/v3/v4 and is not claimed as rolling.
      A repeatable TLS-only PostgreSQL 18.2 harness generates a fresh private CA and DNS-only
      server identity, rejects plaintext/wrong-CA/wrong-name connections, and process-aborts the
      real migrator at all 12 bootstrap, lock, per-sequence SQL/ledger, and commit boundaries.
      Every retained prefix resumes to the exact four-row ledger while preserving populated
      semantic state. A sequence-one connection remains live across sequences two through four,
      publishes a compatible revision, and a current runtime reads and advances it. Separate
      owner/migrator and runtime roles prove the runtime cannot migrate, switch roles, execute DDL,
      or mutate the ledger while permitted FORCE-RLS application writes succeed. Caller-supplied
      connection options are rejected, a fixed search path defeats hostile role
      defaults, and checksum tamper, unknown suffix, and incompatible downgrade attempts fail
      without ledger mutation. `MIG-POSTGRES-LIVE-001` runs this macOS gate and cleans only its
      uniquely labelled disposable resources.
- [x] Freeze configuration precedence and secret-handle rules separately for embedded, local
      sidecar, remote client, and shared service profiles. The descriptor-pinned
      `cigar.configuration-authority.v1` covers four profiles, 113 settings, eight precedence
      layers, 15 source inventories, four file policies, ambient-authority prohibitions, and
      explicit remaining provider gaps for this macOS-arm64 development cohort. CLI, daemon,
      crypto, and Rust SDK readers now walk and validate every physical path ancestor with
      no-follow descriptors, pin ancestors through substitution, reject FIFOs/hard links/unsafe
      modes, and retain bounded final-file identity checks; the authority validator, 13 hostile
      metadata tests, focused runtime tests, docs check, and strict Clippy gates pass.

Exit gate:

- [x] Generated files have zero drift and all cross-language semantic digests agree. The macOS
      arm64 development cohort reruns `cargo xtask generate --check` and the four-language
      canonical-vector gate over 363 vectors plus 100,000 differential records; both pass against
      the current 82-file development protocol baseline. This is a source-tree development gate,
      not an installed-candidate or publication freeze claim.
- [ ] Every public operation has one identifier and compatible behavior across CLI, HTTP, gRPC,
      SDK, MCP, logs, metrics, and errors.
  - [x] Add the macOS-arm64 development-source `COMPAT-SURFACE-001` sentinel. It derives the exact
        45-operation/seven-service contract from the frozen operation and payload authorities and
        checks 27 bound sources: complete OpenAPI/HTTP, Proto/gRPC, Rust typed, dashboard, and
        four-SDK projections; the closed 34-entry/33-operation CLI and ten-operation MCP subsets;
        the exact eight-field Problem shared by all 45 routes and the 34-error SDK catalogs; one
        generated request-log identity; and the 43-family/137-series aggregate metric policy that
        forbids operation labels. Six deterministic test methods cover 20 hostile drift, duplicate,
        non-finite, and link cases. The source report still records `release_eligible=false` and
        `candidate_frozen=false`.
  - [ ] Rerun the same semantics against one clean immutable installed candidate and bind the
        result to external candidate evidence. Source parity and deliberate closed/aggregate
        projections do not complete an installed-artifact or publication freeze.
- [ ] Stored beta state and retained full-product states pass migration and recovery fixtures.

## FULL-200 — Promote the governed local context pipeline

Dependencies: FULL-100

Capabilities: `catalog-discovery`, `catalog-ingest`, `catalog-query`, `policy`, `retrieval`,
`context`, and the local portion of `vector`

Owned paths: `crates/cigar-store/`, `crates/cigar-catalog/`, `crates/cigar-code-intel/`,
`crates/cigar-policy/`, `crates/cigar-retrieval/`, `crates/cigar-compiler/`, local daemon adapters,
catalog/context schemas and docs

- [x] Integrate filesystem/Git discovery preview, exact immutable snapshots, secret/sensitive-file
      admission, ignore rules, atomization, provenance, lineage, invalidation, supersession, and
      tombstones through the production transaction boundary. The initial macOS cohort now binds
      each canonical built-in connector/root and ordered atomizer registry/profile at startup,
      revalidates accepted previews, seals filesystem bytes, disables Git replacement/lazy fetch,
      and applies bounded case-insensitive sensitive/control admission and ignore pruning. One
      atomic tenant/source-bound publication commits the exact snapshot, atoms, provenance,
      lineage, supersession/tombstones, and causal outbox identity; the active projection rebuilds
      on either commit or tombstone while preserving historical-as-of visibility across SQLite
      restart. Qualification passes all 58 catalog/code-intelligence tests, 46 retrieval tests,
      all 144 daemon targets, and strict Clippy; fuzz and soak execution remain intentionally
      excluded from this macOS-only run.
- [x] Make SQLite/FTS projections durable, generation-bound, watermarked, atomically activated,
      rebuildable, and recoverable after process death or corrupted/stale index state. SQLite
      sequence 3 persists immutable SQL/FTS generations, duplicated authoritative
      revision/checksum bindings, bounded counts, ordered-row roots, and one transactional
      activation pointer. Every projection read fails closed against newer authoritative state;
      startup fully verifies and reconstructs missing, stale, corrupt-row, corrupt-FTS, or corrupt
      metadata state. macOS qualification covers all eight in-process and all eight subprocess
      build/activation boundaries, concurrent WAL readers, bounded metadata amplification,
      deterministic backup/restore reconstruction, strict Clippy, and the complete store target
      suite without fuzz or soak execution.
- [x] Enforce policy before existence disclosure or scoring. Opaque engine-issued retrieval proofs
      bind principals, tenants, projects/source partitions, purposes, classification and instruction
      ceilings, processor/capability scope, exact bitemporal evaluation inputs,
      policy snapshot/revision, revocation epoch, and an engine-capped monotonic lifetime. The
      deterministic semantic partition identity separately omits request-instance observation and
      proof-expiry instants while retaining fixed grant validity/configuration, scope, policy, and
      revocation semantics; live proof and per-resource revalidation remain mandatory before work.
      Canonical record Metadata+Content(+Processor) policy is rechecked before candidate work,
      dependency payload/blob/tokenizer reads, retained bundle/body output, and final disclosure.
      Tenant-local watermarks, winner-first lineage resolution, authorized-only graph/vector work,
      partition-local document/edge roots, and vector-binding fingerprints prevent denied or
      unrelated tenant state from perturbing results or caller-visible identities. Revocation,
      stale proof, policy outage, cross-version governance composition, denied dependency reads,
      wildcard governance, and deterministic logical-work non-interference have macOS regression
      coverage; this is not a wall-clock constant-time claim.
- [x] Qualify exact, lexical, metadata, path, symbol, entity, temporal, graph, authority, and
      active-state retrieval. The macOS public-crate qualification covers exact version, atom,
      lineage, digest, canonical-URI, and source-revision identities; exact paths; independently
      asserted symbol/entity declared terms; lexical payload terms; bounded graph traversal; and
      authorized temporal, instruction-authority, and active-lineage augmentation. Non-vector
      stage shapes are now closed before index access: empty or cross-channel selectors and
      non-vector fallback flags fail as invalid metadata, while a valid blocking selector with no
      result fails `RequiredCandidateMissing`. Reversed generation input, rebuild identity, the
      complete 51-test retrieval suite, and strict Clippy are qualification gates. Graph and
      augmentation remain internal `Retriever` stages because the v1 `ContextRequirement` schema
      intentionally exposes only exact and query selectors; production dependency closure uses
      repository graph edges plus exact authorization rather than inventing an unversioned public
      selector.
- [ ] Integrate deterministic planning, dependency closure, conflict groups, lane budgets,
      feasibility, packing, stable ordering, manifests, explanations, materialization, caches,
      deltas, acknowledgements, and exact-base repair.
  - [x] Qualify the deterministic compiler/materialization kernel on macOS without fuzz or soak.
        Candidate requirement indices are bounded by the normalized contract; claim conflicts use
        documented temporal/authority ordering and cannot be hidden by a non-critical winner;
        dependency closure and local repair preserve token budgets, profile item limits, and
        blocking roots; every considered candidate receives a protected disposition; explanations
        are disclosure-filtered; five materializers verify exact bodies; six cache layers recheck
        policy/revocation/integrity; exact deltas reject wrong bases/tampering/target drift; opaque
        applied-delta evidence is required for acknowledgement; changed provider-present state must
        advance its observation sequence; and physical overflow creates an exact target-bound
        repair request. The 30-test compiler suite includes independent-process identity checks
        across input order, locale, timezone, hash-seed environment, and concurrent scheduling.
  - [x] Wire the safely derivable compiler runtime state into the daemon materialization and delta
        operations. Materialization cache keys bind tenant, authorized disclosure partition,
        bundle, target, tokenizer, materializer, framing profile, live policy digest, and revocation
        epoch; hits occur only after retained-body eligibility is rechecked and restart cold.
        Generated deltas are self-applied against the exact retained base and target before release.
        Actual framing overflow is derived from a validated materialization (never caller-authored)
        and retained as the tenant's latest fenced mutable worker checkpoint, avoiding record-key or
        immutable-history amplification while surviving SQLite restart. This checkpoint is the
        exact opaque input to the bounded trusted-adapter repair consumer below.
  - [x] Add a versioned authenticated provider-session/acknowledgement input and bounded repair
        consumer, then persist provider-present state and verified delta acknowledgements through
        that trusted adapter lifecycle. The frozen v1 45-operation registry has no provider session,
        compaction/reset, applied-delta acknowledgement, or repair-consumption payload and remains
        unchanged. The new crate-internal `cigar.trusted-provider-input.v1` boundary accepts only
        canonical 4 KiB HMAC-authenticated records bound to adapter key, tenant, opaque session,
        exact target generation, contiguous sequence, policy, revocation, and a maximum one-hour
        lifetime. A 32-session/60,000-byte tenant checkpoint uses fenced CAS; exact replay is
        idempotent, same-sequence competitors cannot both publish, reset/compaction require the next
        generation, and expired sessions alone are pruned. Acknowledgements are independently
        matched to opaque `AppliedDelta` evidence, never caller fields. Repair consumption binds the
        exact overflow worker version/digest, clears stale present state, rejects a second consumer,
        and retains a bounded replay receipt across restart and later overflow supersession. Nine
        hostile daemon tests cover tag/payload/noncanonical attacks, key/tenant/policy/revocation and
        expiry substitution, wrong delta evidence, SQLite restart, reset/compaction, injected
        checkpoint abort, concurrency/CAS, capacity, and exact-once repair. The aggregate parent
        remains open for installed-candidate adapter qualification; no public API revision is
        claimed here.
- [x] Close the provider-tokenizer decision and bind tokenizer/materializer versions to all output
      identities. The production bootstrap registers only two immutable exact reference profiles;
      complete provider/model/fingerprint tuple matching rejects substitution, materialization and
      retained-record revalidation require the same exact tokenizer, and estimates remain a
      type-separated non-materializing API. Provider-present accounting and delta repair retain
      their existing exact target and acknowledgement bindings.
- [x] Complete the vector decision. The macOS local daemon now wires the explicitly enabled
      `cigar.local-quantized-vector.v1` projection to canonical catalog rebuilds and an owner-private
      durable generation store. The crate-owned deterministic term processor produces bounded int8
      document vectors and, only after revalidating a live opaque authorization, query vectors in a
      separate partition-bound commitment domain. Raw vector construction is crate-private; vector
      request shape rejects cross-channel selectors and unapproved scoring. The adapter iterates
      only already-authorized versions, computes caller-visible vector bindings from only those
      versions, and uses checked integer scores. Missing, stale, corrupt, mismatched, or unavailable
      state falls back only when explicitly allowed; exact, metadata, lexical, graph, and temporal
      correctness remain independent. Strict config rejects shared enablement and unsafe roots.
      The native macOS qualification covers denied-vector noninterference, dynamic partitions,
      restart/corruption repair, storage outage, and durable crash boundaries. The exact green gate
      is `cargo test --locked -p cigar-retrieval --all-targets` (48 unit plus three integration tests)
      with `cargo clippy --locked -p cigar-retrieval --all-targets --all-features -- -D warnings`;
      daemon-owned focused regressions cover strict config and production restart/outage behavior.
      Fuzz and soak were explicitly skipped for this run.
- [x] Wire the full embedded CLI context/catalog routes without enabling daemon, remote, effects,
      or plugin surfaces in the initial beta build. The full/default CLI now requires an explicit
      strict local production configuration, starts the exact production facade listener-free, and
      closes it after each command. Independent macOS processes qualify approved-source refresh and
      inspection, idempotent ingestion/replay, catalog query, content-free policy denial,
      dry-run/committed planning, compile, explain, revalidate, materialize, and a distinct
      exact-base delta against durable private SQLite state; no configured socket is created.
      Ingestion revalidates discovery across bounded internal CAS retries, and strong reads use the
      tenant catalog causal watermark rather than unrelated global service revisions. The frozen
      full operation projection remains closed, while the separately compiled 12-command
      `beta-embedded` profile retains no catalog/context/daemon/remote/effect/plugin surface. This
      is macOS source-tree process evidence, not packaged installed-byte evidence; fuzz and soak
      were not run.

Required tests:

- [x] Path, link, rename, nested-repository, ignore, secret, size, media, Unicode, case-collision,
      snapshot substitution, and time-of-check/time-of-use adversarial fixtures. The macOS catalog
      suite rejects traversal plus case/NFC aliases; external, internal, control-file, and hard-link
      attacks; nested `.git` aliases; hostile and over-budget ignore inputs; detected secrets;
      oversized Git objects; unapproved media; substituted paths after a sealed snapshot; dirty
      worktree and Git replacement-object substitution; and stale-record reuse after refresh.
      Rename identity, watcher overflow, exact range reads, and committed-object isolation are also
      exercised. These fixtures are included in the green 58-test catalog/code-intelligence gate
      and strict Clippy result recorded above; no fuzz or soak execution was used.
- [x] Cross-project/tenant/purpose/classification/processor denial with no existence, query/cache
      identity, deterministic logical-work, metric, debug, or error leak. Wall-clock constant-time
      behavior is not claimed; bounded authorization-first algorithms and content-free diagnostics
      are the supported contract.
- [ ] Index rebuild, stale watermark, vector outage, crash/restart, invalidation, tombstone, and
      concurrent refresh models.
  - [x] Qualify the local-vector subset: deterministic canonical rebuild and activation, stale or
        missing generation fallback, every durable publication/activation crash boundary,
        corrupt-state quarantine/repair, daemon restart with the same binding, storage outage with
        the mandatory generation retained, and tombstone/revision rebuild integration. Evidence is
        the green 52-test retrieval gate plus the daemon
        `restart_corruption_repair_and_storage_outage_preserve_mandatory_generation` regression.
        The retrieval gate now also runs four concurrent readers for 1,000 reads each across an
        atomic generation activation and accepts only the exact complete old or complete new
        privacy-scoped batch. Installed process-crash qualification against packaged bytes keeps
        the aggregate open.
- [x] Determinism across process, input order, locale, timezone, hash seed, scheduling, and every
      claimed architecture. The current development claim is macOS only. The compiler's
      independent-process matrix varies input order, locale, timezone, hash-seed environment, and
      concurrent scheduling; the full embedded CLI process test additionally reopens durable state
      for every command and requires identical governed discovery, ingestion replay, catalog-query,
      dry-run/committed plan, bundle, manifest, and materialization identities. Live proof timing
      remains outside the stable semantic partition digest while fixed grant/scope/policy/revocation
      changes are regression-tested to produce distinct identities.
- [ ] Offline installed workflow: approved source → snapshot → atoms/provenance → query/retrieval →
      plan → bundle/manifest → materialization/delta.
  - [x] Qualify that workflow through independent source-built macOS CLI processes with persistent
        state, content-free denial, provenance, restart-safe replay, materialization, and delta.
  - [x] Implement the native Apple-silicon installed-byte driver and exercise locally staged full-
        profile release binaries under a real Seatbelt child boundary with enforced no-egress. Its
        content-free, artifact/source-bound diagnostic receipt passed all 23 workflow, denial,
        exact-help, provenance/disposition, restart, backup/restore, and retained-v1-to-v4 upgrade
        checks. This was an administrator-owned dirty-checkout diagnostic using unsigned,
        unnotarized staged bytes; it is not clean non-admin packaged-candidate evidence.
  - [ ] Repeat it from the exact packaged installed candidate and bind the receipt to those bytes.

Exit gate:

- [ ] Unauthorized selected blocks equal zero; every selected catalog-derived block has provenance
      and every considered eligible candidate has a disposition.
- [ ] Identical governed inputs produce identical semantic identities across processes and SDKs.
- [ ] The complete local read-only workflow works offline from installed bytes and survives restart.

## FULL-300 — Promote spaces, handoffs, effects, replay, backup, and GC

Dependencies: FULL-200

Capabilities: `space`, `handoff`, `effects`, `replay`, `backup`, `garbage-collection`

Owned paths: `crates/cigar-space/`, `crates/cigar-effects/`, `crates/cigar-replay/`,
`crates/cigar-store/`, connectors, daemon application adapters, coordination/effect/replay schemas

- [x] Integrate durable spaces, overlays, immutable commits, forks, focus branches, checkpoints,
      optimistic publication, conflicts, leases/fencing, bounded events, cursors, and project
      federation.
      Evidence: `cigar-space` owns the bounded semantic kernel; `DurableContextSpaceService`
      publishes authenticated tenant snapshots root-last; and `SpaceHandoffApplication` exposes all
      eight typed space operations with existing-resource project binding and per-poll stream
      reauthorization. The focused SQLite restart regression retains scoped resume state and a
      monotonically superseded lease fence.
- [x] Integrate handoff preview/create/accept/revoke/result/merge with capability intersection,
      sender/recipient/tenant binding, nonce/expiry, one-use acceptance, partial source
      reauthorization, descendant revocation, and transcript-free references.
      Evidence: `HandoffService`, `DurableHandoffService`, and the six typed handoff adapters bind
      issuer, resolved recipient, tenant key scope, audience, current policy, target, nonce, expiry,
      typed references, recipient compilation receipt, optimistic revision, and durable replay
      state. Capsule revocation blocks already-retained descendant result merge before and after
      SQLite restart; capability verification rejects a revoked leaf or ancestor grant.
- [x] Make durable effect intent and current authorization structurally unreachable to bypass before
      connector invocation. Preserve caller idempotency, expected revision, fencing, attempts,
      receipts, and journal hashes.
      Evidence: `EffectEngine::{prepare,claim_dispatch,resume_dispatch,dispatch}` and the sealed,
      non-cloneable `DispatchPermit`/kernel-only `DispatchContext` make connector entry contingent
      on an exact durable intent, version, attempt, monotonic fence, outbox claim, and current
      authorization. `dispatch` exclusively consumes connector ownership into `Unknown` before the
      remote call, while `EffectWorkerProcessor` reloads the exact claim, stages protected arguments
      only afterward, reauthorizes with fresh time, and crosses the shutdown gate immediately before
      the kernel repeats every pre-send check. SQLite restart retains the claim, receipt, and journal
      truth and duplicate worker delivery performs no second connector call.
- [x] Finish production connector transport controls for HTTPS, filesystem, and any broker profile:
      DNS rebinding, redirect/proxy prohibition, TLS identity, credential handles, ancestor swaps,
      body/time bounds, cancellation, ambiguous success, `UNKNOWN`, reconciliation, and linked
      compensation. The only claimed live network profile is the explicitly enabled stock HTTPS
      connector described below; the closed registry exposes no broker profile. The filesystem
      connector now pins its root and every traversed parent by no-follow directory descriptor,
      performs bounded reads and atomic temporary publication relative to that descriptor, binds
      the write fence to its original device/inode, and rejects root/parent/fence substitution,
      symlinks, unsafe owner/mode state, and multiply linked targets. Its eight focused native
      tests and the complete 46-test effects gate pass, including precondition races, ambiguous
      stale attempts, reconciliation, the 100,000-operation possible-commit campaign, and linked
      compensation state-machine cases; strict no-dependency effects Clippy is clean.
  - [x] HTTPS-scoped portion: the stock local macOS v1 transport is composed through one
        endpoint-bound factory per connector, uses explicit public pins without ambient DNS,
        descriptor-safe scoped credential rereads, strict TLS/redirect/proxy/retry controls,
        bounded I/O/time, conservative cancellation and request-loss classification, and a
        lookup-only reconciliation wire contract. Five transport, four registry, and eight
        bootstrap tests pass; strict daemon all-feature library Clippy is clean.
  - [x] Filesystem-scoped portion: the local macOS write connector uses an owner-controlled,
        descriptor-pinned root/parent/fence boundary and relative `openat`/`renameat` operations;
        it never reopens the configured root path after construction and preserves ambiguous
        temporary evidence. Native regressions cover root-path replacement, symlinked parents and
        targets, group/world-writable roots and descendants, hard-linked targets, fence inode
        replacement, precondition changes, and write-fence contention. No broker connector is
        present in the closed production registry, so there is no broker capability claim in this
        cohort.
- [x] Persist complete decision/replay dependencies and keep evidence, invocation, observational,
      and live-comparison modes distinct. `DecisionCaptureBuilder` cross-binds the exact task,
      plan, manifest, bundle, materialization, invocation, policy/index/component fingerprints,
      observation tape, evidence, effects, and verification records before the durable archive
      publishes its content-derived decision root last. Exact lookup has no current-data fallback.
      Evidence and invocation reproduction have no call surface; observational replay can consume
      only the ordered `RecordedProviderTape`; and production non-live composition injects
      `RecordedOnlyReplayServices`, which constructs no network, model, tool, connector, or effect
      client. The 31-test macOS replay gate and strict all-feature Clippy pass without fuzz or soak.
- [x] Enable live comparison only through an explicit provider configuration, fresh authorization,
      new effect intents, and a separately reviewed security profile. Standalone `cigard` remains
      structurally recorded-only; a local macOS embedding must construct the complete
      `cigar.production-live-replay.tenant-bound.v1` profile from an explicit durable authorization
      repository and tenant-bound verifier/provider/effect-gate factory, then call
      `compose_production_server_with_live_replay`. The composer rejects shared/non-macOS use and
      inactive authority-document tenants. The engine consumes a current one-use authorization,
      rejects source-decision effect IDs, requires exact newly authorized effect IDs, reauthorizes
      them through the independent effect gate, and quarantines late provider output. All 31 replay
      crate tests, 28 replay-focused daemon tests, the explicit-profile scope regression, and strict
      all-target/all-feature daemon Clippy pass without fuzz or soak execution.
- [x] Integrate signed backup/create/verify/restore and GC plan/run with current trust policy,
      empty-target restore, retention, legal hold, complete roots, backup completeness, and stale
      plan/revision rejection.
      Evidence: production CLI backup now emits a signed format-two inventory containing the
      consistent SQLite database, encrypted blobs, and exact external monotonic effect checkpoint.
      Checkpoint capture runs inside the SQLite immediate writer exclusion and under its own
      cross-process lock; verification proves a complete one-to-one effect-record/checkpoint match.
      Restore rejects format one, newer/older/substituted current checkpoints, and nonempty targets,
      holds the checkpoint lock through verified atomic publication, and never rewrites external
      truth. GC uses owner-private no-clobber signed plans binding current trust, exact revision,
      ordered candidate set/root, selection bound, retention, legal hold, and backup completion;
      direct destructive legacy GC is unreachable. Before first deletion, an exact locked preview
      publishes a durable owner-private execution marker bound to the canonical database path identity
      and every plan field. Only that marker permits an interrupted run to resume with already-
      absent signed candidates; unplanned orphans never enter the exact deletion call. The strict
      JSON plan omits absent signature expiry instead of emitting forbidden `null`.

Required tests:

- [x] Publication conflicts, lease expiry/fencing, event resume/gap, recipient mismatch, replayed
      handoff, partial acceptance, ancestor revocation, and typed merge conflict cases.
      Evidence: `crates/cigar-space/tests/{space,handoff}.rs`,
      `durable_snapshot::tests::sqlite_restart_retains_scoped_event_resume_and_monotonic_lease_fences`,
      `space_handoff_adapters::tests::typed_event_resume_crosses_hidden_project_gap_without_disclosure`,
      the durable result/revocation restart assertions, and
      `capability_signature_attenuation_tamper_time_and_revocation_fail_closed` cover this exact
      set without relying on fuzz or soak execution.
- [x] Every effect transition plus process kill at all durable boundaries, at least 100,000
      possible-remote-commit operations, and proof of no duplicate logical effect.
      Evidence: `wp12_effects::protocol_transition_matrix_is_closed` covers the closed transition
      matrix; `wp12_faults::efx_c01_through_c24_use_real_process_kill_and_fresh_recovery` kills and
      freshly recovers a child at every stable boundary; and
      `one_hundred_thousand_possible_commit_campaign_has_no_duplicate_or_blind_retry` records exactly
      100,000 possible-remote-commit operations with zero duplicate logical effects and zero blind
      redispatches. `wp12_sqlite::remote_commit_before_sqlite_receipt_failure_recovers_without_duplicate`
      additionally proves real SQLite reopen, explicit `Unknown`, reconciliation, and one remote
      object. These deterministic macOS tests are neither fuzz nor soak execution.
- [x] Corrupt/missing replay dependency, unavailable exact component, live/non-live boundary, and
      completeness/diff fixtures. The public replay suite rejects archive/digest substitution,
      missing exact sources/components, gapped or extra observations, stale/reused live authority,
      old effect IDs, late cancelled provider output, and oversized observations; it separately
      qualifies every completeness category and all seven structured diff dimensions.
- [x] Wrong backup trust root/key, corruption, substitution, interrupted restore, RPO-0 journal
      recovery, stale GC plan, legal hold, and referenced-blob protection.
      Evidence: `backup::tests::{signed_backup_verifies_restores_empty_and_preserves_root,
      embedded_signer_trust_survives_rotation_and_rejects_revocation,
      format_two_backup_signs_exact_effect_checkpoint_member}` cover signature/checksum
      substitution, retained versus revoked keys, every backup/restore failpoint, empty-target
      publication, and the signed checkpoint member. `production_effect_authentication::tests::
      production_authenticator_backup_is_complete_and_rejects_checkpoint_rollback` persists a real
      SQLite version-zero effect, restarts, verifies its format-two backup, advances monotonic truth,
      restarts again, and rejects rollback. All eight `store_owned_gc` tests cover signed restart,
      stale revision, same-revision candidate addition and missing-candidate substitution before
      execution, durable partial-delete restart/resumption, retention of a newly visible unplanned
      orphan, dry-run non-mutation, corrupt execution-marker rejection, convergent rerun, trust/key
      rejection, semantic tamper, legal hold, backup/retention denial, legacy bypass denial, writer
      exclusion, and live referenced blob preservation. The full CLI workflow also exercises key
      rotation/revocation and strict signed plan serialization.

Exit gate:

- [x] No dispatch occurs before durable intent and current authorization; no unsafe retry occurs;
      every ambiguous result remains `UNKNOWN` until reconciliation.
      Evidence: the kernel and daemon adapter suites cover stale/revoked authority, approval and
      attempt deadlines, competing claims and permit reuse, unreceipted ownership, connector panic
      and error, descriptor drift, same-key collision, non-idempotent retry, lost receipt, restart,
      inconclusive reconciliation, and ambiguous compensation. All deny connector entry, remain
      explicit `Unknown`, or advance through a separately journaled reconciliation as required.
- [x] Non-live replay proves OS-enforced and structural zero egress. The engine's non-live entry
      point rejects live mode and owns no live fallback path; the production factory is deny-only,
      recorded tapes report zero live calls, and the native macOS `wp13_no_egress` subprocess
      regression passes under the operating-system network-denial sandbox.
- [x] Backup, restore, and GC exercises preserve canonical semantic roots.
      Evidence: `signed_backup_verifies_restores_empty_and_preserves_root` reconstructs and compares
      the authoritative root, while
      `tests::production_backup_restore_and_store_owned_gc_use_signed_durable_state` compares the
      live and restored SQLite semantic roots and proves deletion of an unreferenced encrypted blob
      leaves that root unchanged. Current macOS gates pass 85/85 store targets, 168/168 daemon
      targets, and 64/64 CLI targets plus strict Clippy for all three crates; fuzz and soak were
      intentionally not executed.

## FULL-400 — Promote the complete local runtime and operator surface

Dependencies: FULL-300

Capabilities: `daemon`, `serving`, local `remote`, `extensions`, `otlp`, `diagnostics`, and
`completion-man`

Owned paths: `crates/cigar-api/`, `crates/cigar-daemon/`, `crates/cigar-cli/`,
`crates/cigar-extension-host/`, `crates/cigar-observe/`, local IPC, generated completions/man pages

- [x] Compose the embedded runtime and `cigard` only from production repositories, workers,
      policies, journals, indexes, connector registries, and key providers.
- [x] Qualify protected Unix-socket operation on the native macOS arm64 cohort, explicit loopback
      token fallback, HTTP/JSON, gRPC, and resumable SSE with identical operation semantics.
      Windows named-pipe execution/ACL qualification remains a separate deferred profile.
- [x] Implement and test every route in `crates/cigar-cli/assets/cigar-help.txt`: full catalog,
      context, project/focus, space, handoff, effect, replay, policy, backup, GC, diagnostics,
      doctor, serve, MCP, plugin, release verification, completion, and man pages.
- [x] Enforce strict target selection, configuration provenance, secret-file handling, dry-run and
      confirmation semantics, noninteractive behavior, cancellation, deadline, idempotency,
      expected revision, JSON/text output, and error/exit-code mapping.
- [x] Finish the signed extension boundary: manifest/ABI/signature validation, capability broker,
      no ambient authority, WASI/native subprocess isolation, remote bridge, opaque handles,
      fuel/memory/I/O/deadline limits, cancellation, and canonical output validation.
      Activation authenticates the signed manifest and its package, implementation, ABI, schema,
      authority, and resource bindings. The invocation-scoped broker now binds the exact request
      cancellation token and monotonic deadline, roots filesystem grants in open directory
      descriptors, opens every descendant without following symlinks, and bounds reads before
      allocation. WASI remains import-deny-by-default; the macOS arm64 native backend executes an
      immutable verified snapshot under the deny-default system sandbox with a CPU rlimit and
      sampled RSS enforcement; and the bounded remote bridge reauthenticates its peer bindings on
      every exchange. Linux native launch code remains development-only and is not qualified by
      this item.
- [x] Complete liveness/readiness, startup recovery, bounded workers/queues, backpressure, graceful
      shutdown, content-free diagnostics, metrics, and opt-in OTLP with bounded labels and explicit
      collector trust roots. The native macOS source cohort exposes one closed 43-family/137-series
      schema with exact OpenMetrics/dashboard/OTLP parity and production-owner values for process,
      admission, streams, queues, compiler/cache, index, handoff, effects, reconciliation, blob,
      lease, and shutdown state. Startup opens readiness only after ordered durable recovery;
      worker poison, invalid cursors, dependency failure, or shutdown close it before further
      dispatch. OTLP is opt-in, bounded, strips ambient metadata, and requires an explicit CA for
      HTTPS. The affected API/daemon/dashboard/observe run passes 278/278 tests, both live OTLP
      collectors, strict Clippy, and warning-denied rustdoc; focused independent lifecycle,
      production-runtime, readiness, and telemetry reruns pass 16/16. Fuzz, soak, installed-byte,
      PostgreSQL-pool, and non-macOS claims remain outside this item.

Required tests:

- [x] Differential behavior for all 45 operations across embedded, HTTP, gRPC, local IPC, and SDK
      adapters where each transport applies. The generated registry differential executes all 44
      unary operations through embedded, HTTP, and gRPC normalization and the sole stream through
      embedded, HTTP/SSE, and gRPC; the production differential binds all 45 contracts to concrete
      handlers and exercises a durable mutation/read pair over embedded plus live TCP HTTP and
      gRPC. A native macOS gate now sends every generated contract over the real owner-private Unix
      socket, including the SSE stream and direct OpenMetrics response. Rust, TypeScript, Python,
      and Go tests bind every generated method and payload mapping to the 45-operation capability
      authority and its exact declared transports. The focused gates, complete affected Rust and
      SDK suites, generator drift check, strict Clippy, warning-free Rustdoc, and compatibility
      matrix regressions pass. This is source-tree macOS qualification only: installed/published
      package execution and non-macOS transport qualification remain later work, and fuzz/soak were
      intentionally skipped for this run.
- [x] Authentication, authorization, cursor, idempotency, optimistic revision, compression/body
      bomb, stream backpressure, timeout, cancellation, restart, and SSE resume cases. The complete
      19-case `cigar-api` transport-conformance suite covers verified peer identity, strict JSON
      security fields, fully expanded gzip/deployment limits, gRPC compression rejection, bounded
      streaming queues, disconnect cancellation, unary/stream deadlines, incomplete bodies,
      optimistic revisions, and cursor-bound SSE resume. API unit gates add forged, expired, and
      cross-scope cursor rejection plus concurrent exactly-once idempotency. Production daemon
      regressions add pinned OIDC/local-token authentication attacks, default-deny and revoked
      authorization, durable idempotency replay/collision/pending recovery, real SQLite restart,
      scoped pagination/event resume, and effect/replay cancellation. The locked full
      `cigar-api` and `cigar-daemon` suites pass on the native macOS cohort; no fuzz, soak, or
      non-macOS qualification is represented by this item.
- [x] Unix mode/link/path-race tests on native macOS arm64. The native endpoint suite requires an
      owner-private `0600` socket in a non-group/world-writable owner runtime directory, refuses
      pre-existing regular files and dangling symlinks without unlinking them, and binds guard
      cleanup to the original device/inode so a same-path socket substitution survives shutdown.
      The live Unix listener test verifies HTTP multiplexing and exact cleanup; the seven process
      path tests reject symlinked ancestors, permission/link/owner violations, and final-file or
      ancestor replacement races. Windows ACL tests remain required for the later Windows profile
      and cannot inherit this macOS evidence.
- [x] Extension signature/ABI/schema substitution, forbidden filesystem/network/environment access,
      output flood, infinite loop, crash, cancellation, and resource exhaustion.
      The 34-test `cigar-extension-host` all-target/all-feature suite passes on native macOS arm64.
      It includes signed package/implementation/ABI/schema substitution, forged and cross-request
      handles, descriptor-root replacement, symlink/traversal/hard-link rejection, a bounded
      oversized-file read, exact in-flight cancellation/deadline propagation, canonical frame and
      output limits, WASI fuel/memory exhaustion, output flood, infinite loop, crash, remote peer
      reauthentication, immutable native snapshot restart, a real 96 MiB resident-memory probe
      against a signed 64 MiB limit, and the real hostile sandbox probe for filesystem, network,
      environment, and child-process denial. The exact locked package test, strict
      all-target/all-feature Clippy, and warning-free Rustdoc gates pass; fuzz and soak were
      intentionally not executed for this macOS-only run.
- [x] Telemetry canaries proving no source content, prompt, secret, path, user identity, effect
      argument, or high-cardinality attacker value enters output. `DaemonTelemetry` accepts only
      closed, value-free event methods; worker labels come from the nine-variant `WorkerKind` enum;
      and `telemetry_surfaces_drop_ambient_metadata_and_never_accept_content_canaries` exercises
      every OpenMetrics, JSON snapshot, and debug surface against all seven canary classes. The
      same regression injects canaries as tonic metadata and proves the mandatory OTLP interceptor
      clears them, closing the upstream exporter's ambient `OTEL_EXPORTER_*_HEADERS` path.
- [x] Generated CLI help, completions, man pages, API docs, and command registry remain identical in
      meaning. The macOS `generated_user_surfaces_have_exact_commands_options_and_value_domains`
      gate derives all 68 public command paths from the Rust registry and requires exact top-level
      and subcommand equality in help, the manual, Bash, Zsh, and Fish assets. It also derives all
      27 accepted long options from the closed parser, rejects missing or extra documented options,
      freezes completion value domains, and binds all 34 operation-backed commands to the generated
      API operation ID and read/mutation contract. The complete `cigar-cli` test suite, native
      Bash/Zsh/mandoc checks, `cargo xtask generate --check`, and strict package Clippy pass.

Exit gate:

- [x] All 45 operations have identical governed behavior across every currently claimed
      source-local macOS interface. The exhaustive registry/transport/SDK authority gates above
      prove operation identity, payload mapping, stream shape, and dispatch binding without
      claiming installed artifacts; installed SDK/package qualification remains in FULL-600 and
      FULL-900.
- [x] No unauthenticated listener, ambient credential, extension authority escalation, or
      content-bearing diagnostic/metric path exists in the claimed source-local macOS profile.
      Local IPC is owner-private; loopback TCP requires an explicit token; remote listeners require
      configured channel/authentication authority; OTLP rejects ambient credentials and metadata;
      extension capabilities remain invocation-scoped; telemetry accepts only closed enums and
      numeric values. Existing listener/auth/extension suites plus the complete seven-canary
      telemetry regression pass.
- [x] Readiness closes on integrity, policy, journal, migration, or required-index failure. Every
      mandatory probe must appear exactly once and be healthy, production readiness derives from
      both gate and durable dependencies, startup failure never opens it, and worker poison or
      invalid durable index state closes dispatch and every queue. The complete affected suite and
      focused `readiness`, `lifecycle`, and `production_runtime` regressions pass on native macOS.

## FULL-500 — Promote remote and shared-service operation

Dependencies: FULL-400; storage work may start after FULL-100 behind a disabled profile

Capabilities: shared portions of `remote`, `serving`, `shared`, and `vector`

Owned paths: PostgreSQL/object implementations, `migrations/postgres/`, shared workers,
`deploy/compose/`, `deploy/kubernetes/shared/`, shared runbooks and observability

- [ ] Complete PostgreSQL metadata, tenant row-level defense, encrypted S3-compatible object CAS,
      outbox/invalidation workers, cache/index generations, shared event wakeups, pooling, timeout,
      failover, backup/restore, and rolling-compatible migrations.
- [ ] Require HTTPS/gRPC channel identity, OIDC issuer/audience/algorithm pinning, bounded JWKS
      refresh, tenant claim validation, optional mTLS, and separate runtime/migrator/backup/GC
      principals. The channel/OIDC/mTLS implementation and focused native macOS suites are green:
      nine authentication tests cover pinned EdDSA, issuer/audience/tenant binding, hostile claims,
      expiry, bounded refresh, cooldown, and concurrent refresh; two discovery tests cover exact
      same-origin redirect/proxy-free JWKS policy; and both optional and required-mTLS shared
      listener tests pass. Four disjoint PostgreSQL principals are now implemented and compile-
      checked; the checkbox remains open until the live shared-profile rerun proves the new
      backup/GC capability split against PostgreSQL.
- [ ] Qualify Compose and Kubernetes profiles against managed or production-shaped PostgreSQL,
      object storage, private CA, OIDC, secret mounts, and actual CSI/RWX/POSIX semantics.
- [x] Make vector, extensions, live connectors, live replay, and OTLP independently disableable and
      fail closed when required configuration or identity is absent. Native macOS focused tests
      prove an absent vector profile is disabled and shared vector use is rejected; the production
      capability response exposes no extension host; an empty source registry disables ingestion;
      disabled effects construct no connector transport while shared live HTTP is rejected; live
      replay requires the explicit complete tenant-bound profile; and absent OTLP constructs no
      exporter while HTTPS OTLP requires an explicit matching CA. Each affected path passed strict
      compilation through the daemon/store/CLI gates.
- [x] Enforce authenticated HTTPS for remote CLI/SDK. Reject URL credentials, redirects, ambient
      proxies, insecure remote HTTP, untrusted roots, and credential inheritance from project
      configuration. The CLI now requires an explicit owner-safe authorization file for every
      remote target and keeps project configuration from supplying it. Rust, TypeScript, Python,
      Go HTTP, and Go high-level gRPC require an explicit bounded bearer source before remote use;
      dynamic empty credentials fail before transmission. Default transports reject URL authority,
      non-loopback HTTP, redirects, and ambient proxies where the platform exposes them; custom
      transports require explicit caller trust. Strict Clippy, 11 CLI configuration tests, seven
      Rust remote tests, 23 TypeScript tests/build, Ruff/mypy plus 21 Python tests, and Go test/vet
      all pass on native macOS.

Exit gate:

- [ ] Tenant isolation and denied existence hold under concurrency, lag, stale indexes, failover,
      and authorization changes.
- [ ] Failover loses no committed journal entry and duplicates no logical effect. The last
      `cigar.wp18-failover-qualification.v1` receipt passed all three production-store phases over
      private-CA TLS with physical replication, synchronous `remote_apply`, explicit promotion,
      `pg_rewind` rejoin, zero acknowledged-write loss, zero duplicate revisions/effects/claims,
      and a verified physical restore semantic-root match. The subsequent final principal-
      escalation hardening intentionally invalidated that source-bound receipt; rerun the same
      qualification against the stable source before checking this gate.
- [ ] Adjacent versions roll without incompatible writes; backup/restore retains semantic roots.
- [ ] Shared scale reaches the PRD target and a 24-hour installed-service soak shows no memory,
      descriptor, task, queue, lease, or digest trend outside defined stabilization.

## FULL-600 — Promote SDKs, MCP, and the Claude Code adapter

Dependencies: FULL-400; shared-mode cases also depend on FULL-500

Capabilities: `sdk`, `mcp`, `plugin`

Owned paths: `sdk/rust/`, `sdk/typescript/`, `sdk/python/`, `sdk/go/`, `crates/cigar-mcp/`,
`crates/cigar-claude-hook/`, `adapters/claude-code/`, plugin packaging

- [x] Generate and package all 45 operations and 70 nominal types from the frozen catalogs for
      Rust, TypeScript, Python, and Go. Preserve Context ABI, version, method, type, fixture, and
      retry-class parity. The generator drift gate is clean and every language binds its generated
      methods, payload registry, error/retry catalog, package-local semantic fixture, Context ABI,
      and `1.0.0-dev.1` identity to the same authorities. Deterministic macOS-arm64 development
      producers emit the 19-file Rust SDK crate through a complete 20-crate offline publication
      chain, the 70-file npm package, 36-file Python sdist plus 32-file wheel, and 36-file Go module
      ZIP. Two real Rust producer runs were byte-identical; the TypeScript, Python, and Go artifact
      digests also remain byte-identical across repeat builds. This is development packaging only:
      no registry publication, signature, support, or release claim is implied.
- [x] Qualify Rust embedded and HTTP/SSE, TypeScript HTTP/SSE, Python async/sync HTTP/SSE, and Go
      HTTP/SSE plus high-level gRPC. Enforce deadlines, cancellation, pagination, stream resume,
      typed errors, version negotiation, digest/delta verification, and caller idempotency. The
      complete native macOS cohort passes 32 Rust no-default-feature tests and 33 all-feature tests,
      including the embedded daemon, plus strict all-target Clippy and warning-denied rustdoc;
      TypeScript passes typecheck, 23/23 transport tests, and its package-install suite; Python
      passes strict mypy, Ruff, and 21/21 sync/async tests; and Go 1.26.5 passes the complete HTTP,
      SSE, and high-level gRPC module suite. Go's module graph uses `x/net` 0.56.0, and both the SDK
      and recorded demo return no findings from govulncheck 1.6.0 and Trivy 0.69.2's current DB.
      Non-macOS qualification and fuzz/soak remain explicitly outside this run.
- [x] Prove no SDK automatically retries `dispatchEffect` or any operation whose outcome can be
      ambiguous. Safe-read retry must preserve request identity and deadline. The frozen v1
      operation catalog has one connector-dispatch boundary whose external outcome can become
      ambiguous, `dispatchEffect`; Rust, TypeScript, Python, Go HTTP, and Go high-level gRPC all
      force that operation to one attempt even when a larger retry policy is configured. New
      safe-read retry tests bind every retry to the same normalized envelope, method, URL,
      operation ID, body, and caller identity while proving that the original absolute deadline
      is retained rather than reset. Rust records exact envelope equality and one monotonic
      `Instant`; the HTTP SDKs observe decreasing remaining timeout under a stable request; the Go
      gRPC server validates both attempts and a decreasing remaining deadline. The Rust focused
      contract suite passes 6/6 without default features, the TypeScript suite passes 23/23, the
      Python suite passes 21/21, and the complete Go HTTP/gRPC suite passes. The Rust all-feature
      rerun also passes as part of the completed aggregate SDK gate above.
- [x] Qualify MCP 2025-06-18 framing, ten tools, eight `cigar://` resource families, duplicate-key
      rejection, safe integer/request IDs, silent notifications, cancellation, output budgets,
      opaque expiring handles, no synthetic degraded data, and no authority amplification.
      The packaged macOS stdio path now uses a bounded reader queue so valid cancellation
      notifications can interrupt an in-flight CLI child while remaining silent; mutating
      cancellation reports an ambiguous outcome and preserves idempotency requirements. OS-random
      128-bit handles, lazy five-minute expiry, exact serialized-envelope accounting, closed
      generated tool/CLI/HTTP routes, mutually exclusive request forms, bounded safe IDs, and
      content-free resource failures are covered by deterministic unit and installed-binary tests.
      The locked `macos-qualification` run passes all 38 MCP tests, generator drift is clean, and
      strict all-target Clippy plus warning-denied Rustdoc pass.
- [ ] Build the Claude plugin only from installed signed CIGAR executables. Qualify documented
      hooks, bounded injection, duplicate suppression, `/cigar:why`, token accounting, compaction
      checkpoints, recipient-specific one-use read-only subagent handoffs, and plugin
      install/doctor/uninstall.
- [x] Keep context lookup degradation visible and fail open only for context availability. Keep
      recognized mediated-effect authorization fail closed. Never read provider transcripts or
      undocumented provider state. The 13-test hook suite proves bounded visible degradation when
      context is unavailable, exact duplicate and repeated-materialization suppression, compaction
      reset/recompile, recipient-bound subagent handoffs, and denial of recognized mediated effects
      whenever current authority cannot be verified. Static source/package scans reject private
      provider-path access primitives, every documented public event has a strict fixture, and
      malformed, duplicate-key, deeply nested, oversized, and backend-output inputs fail within
      their closed limits. The five-process plugin lifecycle suite additionally proves package and
      hook/MCP command substitution fail closed, installation consumes the authenticated staged
      bytes even if the source changes, unsupported host versions mutate nothing, and uninstall
      preserves unrelated host and CIGAR bytes. Locked native macOS tests, strict hook Clippy, the
      package validator, private-path scan, and recorded public-surface smoke pass; the separate
      installed-signed-plugin requirement remains open above.
- [ ] Publish a compatibility record for every claimed Claude Code version/platform combination;
      do not generalize the current Apple-silicon single-version observation.

Exit gate:

- [x] Four SDK workflows produce the same semantic bundle identity from clean installed packages
      on every claimed runtime/platform. The only claimed cohort is native Apple-silicon macOS:
      Rust runs the canonical crate quickstart and a default-feature consumer through a fresh
      20-crate offline registry; TypeScript installs its npm archive plus a locally packaged exact
      protobuf dependency with scripts and network disabled; Python installs both the exact sdist
      and wheel with `protobuf==6.33.5` into separate clean offline CPython 3.14 environments and
      imports the 45-operation/70-type public SDK; and Go downloads the exact module ZIP through a
      fresh file proxy/module cache before running its packaged workflow. All five distributed
      files produce
      `1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84`.
- [ ] MCP and Claude integration tests run from packaged binaries/plugin rather than workspace
      paths, and clean uninstall preserves unrelated host files byte-for-byte.
- [ ] Adapter failure cannot corrupt host or CIGAR state, leak provider data, or authorize effects.

## FULL-650 — Finish the optional dashboard and soak control plane

Dependencies: FULL-400 and frozen Rust SDK/API contract; optional shared views depend on FULL-500

This packet is a separate artifact/profile and is not a core v1 blocker unless the release owner
explicitly adds it to `packaging/artifact-matrix.v1.json`.

- [ ] Execute the remaining ordered work in `docs/dashboard/post-main-integration-todo.md`; do not
      duplicate its INT identifiers here.
- [ ] Finish sidecar configuration/path hardening, active-process recovery, transactional byte
      ledgers, schema-validated receipt ingestion, and independent signature/source/artifact
      verification.
      Active-process fail-closed reconciliation, transactional aggregate output/evidence ledgers,
      strict schema/path receipt ingestion, and a fail-closed local installed-artifact byte binder
      are implemented in SQLite v4/Rust. The binder is partial-only and rejects source drift,
      mutation, links, and non-arm64 binaries. Automatic adoption, an actual installed artifact,
      authenticated signature/notarization/provenance, and candidate binding keep this aggregate
      requirement unchecked.
- [ ] Implement one allowlisted child-process supervisor using fixed executable identities and argv
      arrays, isolated state/evidence roots, OS resource limits, no shell, bounded output, process
      group/job-object termination, cancellation settlement, and restart recovery.
      Fixed executable/argv, no-shell cleared execution, separated roots, bounded output,
      macOS process-group termination, cancellation settlement, child-only core/CPU/file/FD limits,
      100 ms RSS/process-group polling, fail-closed restart reconciliation, and receipt-before-pass
      are complete for three non-soak profiles. A real supervisor-process crash test and actual CPU,
      file-size, open-file, aggregate RSS, and aggregate process-count enforcement tests pass.
      Kernel-hard memory/job-process limits, exhaustive escaped-child handling, and non-macOS support
      keep this aggregate requirement unchecked.
- [ ] Implement the real `cigar-soak` installed-binary driver with deterministic workload/fault
      plans, 1–64 sessions, mixed ingest/compile/delta/space/handoff/effect/replay/backup/GC work,
      reference-model comparison, invariant monitoring, and canonical signed result.
- [x] Keep generic dashboard mutation dry-run-only; effect dispatch, compensation, restore, and GC
      execution remain unavailable unless separate narrowly scoped reviewed controls are added.
- [ ] Complete browser E2E, accessibility, keyboard, reduced-motion, forced-colors, zoom, narrow
      viewport, CSP, auth/CSRF, session, safe-event, pagination, retention, resource, and crash tests.
  - [x] Run the current observer/auth/control-disabled slice through real Chromium, Firefox, and
        WebKit on native Apple-silicon macOS. Playwright 1.61.1 passes 27/27 for bootstrap/session
        confinement, unauthenticated rejection, same-origin and CSP boundaries, generated protocol
        rendering/search, axe WCAG A/AA, keyboard skip navigation and display-menu focus, reduced
        motion/theme, forced colors, 200% zoom, narrow no-overflow layouts, explicit transient-
        failure recovery, and bounded manual-refresh coalescing. Native Rust tests now cover live
        supervisor receipt lifecycle, a real supervisor-process crash, resource enforcement, and
        durable retention/pagination, but those flows are not yet driven through the browser. The
        aggregate browser box therefore remains unchecked.
- [ ] Package the dashboard and optional Compose/Kubernetes overlays without changing default Cargo
      members, ordinary daemon/CLI builds, beta artifacts, base deployments, or daemon behavior.
  - [x] Define a separate development-source macOS dashboard archive ID and exact package contract,
        and prove by source invariant that Cargo defaults, the ordinary macOS runtime archive,
        daemon Dockerfile, base Compose, and shared Kubernetes YAML remain dashboard-free. No
        producer, image/overlay, installed qualification, or artifact-matrix selection is claimed.
        Evidence: `docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.

Exit gate:

- [ ] Dashboard absence, disablement, crash, or upgrade cannot change CIGAR protocol behavior.
  - [x] Prove the source-level absence slice for default Cargo members, the ordinary macOS runtime
        archive, daemon Dockerfile, base Compose, and shared Kubernetes YAML. Live daemon behavior,
        disablement, crash isolation, install, and upgrade comparisons remain open. Evidence:
        `docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.
- [x] Browser assets never receive the daemon credential or arbitrary executable/argv/path input.
      The deterministic production-bundle gate rejects external/inline/dynamic active content,
      direct transports outside the closed same-origin wrapper, Node/runtime APIs, command/argv/
      executable/environment/raw-target/authorization fields, missing module dependencies, and
      wrapper weakening. Thirty-one browser unit/model cases plus 23 hostile-verifier cases pass on
      native Apple-silicon macOS.
- [ ] Soak completion is based on independently verified evidence, not child exit status.

## FULL-700 — Complete WP19 quality and security qualification

Dependencies: all product-code packets selected for the release

Execute `todo-launch.md` LAUNCH-100 through LAUNCH-108 against one exact clean candidate.

- [ ] Run security, compatibility, chaos, migration, and installation matrices on every applicable
      native platform with no missing environment or retry-only pass.
  - [x] Complete the bounded source-tree `local` profile on native Apple-silicon macOS for all nine
        currently applicable matrix suites. The terminal result is 58 passing cases, one
        clean-committed source-snapshot blocker, and zero remaining assertion failures: chaos 6/6,
        compatibility 8/9, end-to-end 3/3, installation 6/6, integration 7/7, migration 12/12,
        models 1/1, offline 4/4, and security 11/11. `COMPAT-VECTORS-001` cannot issue its
        source-bound command receipt from the concurrently modified checkout, although all four
        underlying SDK/runtime vector verifiers pass 363 canonical vectors and 100,000
        differential records independently. This is not clean-candidate, installed-byte, or
        cross-platform evidence. Fuzz, soak, shared-only, and release-only cases were not run.
- [ ] Map every normative PRD requirement and critical invariant to active positive, negative,
      property/model, process/fault, cross-runtime, and installed-byte evidence.
- [ ] Reach at least 80% line and 70% branch coverage across every shipped package, feature,
      binary, generated adapter, connector, and target.
- [ ] Run all 14 fuzz targets for at least 604,800 clean CPU-seconds each; restart an affected
      target after fixing any defect. Deferred for this run without changing the threshold.
      The release policy now requires all 14 named target metrics, exact aggregate reconciliation
      at 8,467,200 seconds, and zero unresolved defects. The signed, hash-chained cumulative ledger
      and its adversarial verifier are implemented, but no fuzz execution occurred in this cohort.
- [ ] Complete sanitizer, Miri/UB-equivalent, semantic property, concurrency-model, no-egress,
      crash, migration, and adversarial campaigns.
      The bounded native Apple-silicon diagnostic passes all seven 512-case semantic property
      families plus seven production-linked Loom models and three model-governance tests (18/18
      workspace tests). The machine manifest records 132 exact schedules, 14 required branches,
      source/symbol bindings, full bounds/configuration, and seven rejected divergence mutants;
      direct Send/Sync production races are additionally barrier-exercised without model-side
      serialization. Native strict Miri also passes its focused canonical/identity model 1/1 after
      pinning the upstream AArch64/Miri fix in `zmij` 1.0.23. A prior v1 diagnostic reported six
      TSan production-path cases and four ASan integration cases with matched LLVM 22.1.8
      Rust/C instrumentation, and the reviewed UB-equivalent finds no first-party macOS unsafe/FFI
      source while binding the native dependency inventory and Windows-only exclusion. Rust UBSan
      is unsupported on this target and was not run or claimed. Independent audit invalidated the
      v1 receipt because it did not prove an exact selector executed a test; a hardened v2 rerun is
      pending and none of those ten sanitizer cases currently qualifies. The 14-target fuzz campaign,
      no-egress, migration, adversarial, and clean-candidate campaigns remain open, so the aggregate
      item is not complete.
- [ ] Run at least four hours of release-candidate mutation analysis with zero viable survivor or
      timeout on a critical invariant.
      Release verification now enforces a 90% score floor, >= 14,400 seconds, full production
      package coverage, zero timeouts, and zero critical viable survivors. The native macOS-arm64
      mutation-only xtask route now independently recomputes those claims from cargo-mutants 27.1.0
      source lists and raw outcomes under locked/offline no-network execution. No campaign was run
      in this bounded pass, so this item remains open.
- [ ] Run the complete effect fault campaign, shared failover/scale campaign, and 24-hour mixed
      installed-service soak. Long soak execution is deferred for this run without a waiver.
      The six-case local macOS chaos profile passes as diagnostic evidence; shared failover/scale,
      the full effect RC campaign, and soak remain open.
- [ ] Run pinned source/dependency/secret scanners and a deep security review with no reachable
      critical/high finding and no deferred claimed surface.

Exit gate:

- [ ] WP19 is complete with no skipped, waived, flaky, quarantined, unknown, stale, synthetic, or
      unbound result.

## FULL-800 — Complete WP20 efficacy, performance, demos, and SDK workflows

Dependencies: FULL-700 plus preliminary exact installed artifacts

Execute `todo-launch.md` LAUNCH-200 through LAUNCH-202.

- [ ] Build at least 270 independently adjudicated task identities across the nine required strata,
      with hidden evaluator inputs and conflict-of-interest separation.
- [ ] Run seven real baselines and five ablations using paired/randomized execution and at least
      10,000 clustered bootstrap resamples.
- [ ] Meet the machine thresholds in `packaging/release-requirements.v1.json`, including critical
      recall, precision, unauthorized-context, physical reduction, and task-success requirements.
- [ ] Run installed daemon performance and scale on pinned native hosts with raw samples, resource
      curves, saturation behavior, and regression comparison.
      The normalized v4 local catalog and explicit macOS-arm64 `large_local` profile are now
      implemented. The preflight source-binds its 64 GiB database cap, 300 GiB activation
      requirement, 16 GiB reserve, hard atom/edge/blob quotas, and a 4.668 GB normalized-record
      payload lower bound. This does not replace installed-artifact evidence: the physical
      1M-atom/10M-edge/100-GiB run, integrity pass, and verified backup/restore remain pending on a
      dedicated qualifying host.
- [ ] Run all seven demos and four SDK workflows twice from distribution artifacts under enforced
      no-egress where applicable, including negative and recovery paths.

Exit gate:

- [ ] WP20 is complete and every claim is reproducible from raw candidate-bound evidence.

## FULL-900 — Complete WP21 packaging, platforms, operations, and supply chain

Dependencies: FULL-700 and FULL-800

Capabilities: `installers`, `macos`, Apple-silicon `arm`, plus packaging for every other selected
macOS cohort capability. `windows`, Linux artifacts, Intel macOS, and `oci` remain inventoried but
deferred to separate profiles.

Execute `todo-launch.md` LAUNCH-300 through LAUNCH-309.

- [x] Implement development-only build tooling for the unsigned, unnotarized, unqualified
      `cli-daemon-macos-aarch64` archive. This advances implemented-source/build-tooling only; it
      does not mark the native artifact built in a candidate profile or claim qualification,
      publication, support, signing, notarization, or release readiness.
- [x] Close the selected macOS runtime package over the checked-in production executables:
      `cigar`, `cigard`, `cigar-mcp`, and `cigar-claude-hook`. The dedicated archive contract,
      Homebrew bottle contract, producers, content-free probes, and receipts bind all four; the
      optional dashboard and internal conformance/benchmark/soak binaries remain excluded. All
      candidate, signing, notarization, installed qualification, publication, and support claims
      remain false or unevidenced.
- [x] Implement the bounded development-only Apple-silicon Homebrew producer and exact tap/bottle
      contracts. Its bottle uses the real Cellar payload layout, deterministic Homebrew 6-compatible
      receipt metadata, an embedded formula and source-bound SPDX; its tap formula binds the exact
      bottle and native-archive digests. This advances producer/contract source only: signing,
      notarization, clean install, upgrade, uninstall, publication, support, and candidate build
      state remain false or not evidenced.
  - [x] Bind construction to the exact Apple-silicon macOS 15.6 identity represented by the
        `arm64_sequoia` bytes, and add a read-only verifier that reconstructs the pair from its
        native input before accepting the canonical unqualified build receipt. The focused suite
        passes 8/8; this adds no installed-byte, signing, notarization, publication, or support
        claim.
- [x] Implement the development-only Claude Code plugin producer. It compiles a thin native arm64
      hook, validates and freezes the public plugin payload, verifies the closed plugin contract,
      publishes only through the protected external workspace, and emits a `built-unqualified`
      receipt. The packaged documentation now describes Claude Code `2.1.207` on Apple-silicon
      macOS only as a future qualification target; installed signed CIGAR/MCP/hook bytes, lifecycle
      qualification, publication, support, and release claims remain false.
- [x] Implement deterministic development producers and closed package contracts for every row
      selected by the macOS arm64 profile projection in
      `packaging/artifact-matrix.v1.json`. The combined focused producer suite passes 70/70 tests;
      the profile still records every artifact as planned with `built=false` and `qualified=false`,
      so this check advances source tooling only and is not candidate packaging evidence.
  - [x] Add the development-only complete-artifact assembler and independent verifier for the 17
        selected rows. Ten exact external producer workspaces are receipt-, authority-, source-,
        version-, ABI-, target-, host-, contract-, and mutation-validated before owner-only bytes,
        `release-build.json`, and `SHA256SUMS` are created. The manifest remains explicitly
        `cigar.local-archive-build.v1`; clean-candidate production, signing, notarization, installed
        qualification, publication, and support remain open.
- [ ] Build and qualify the native full-product archive for `aarch64-apple-darwin`. Do not infer
      Intel macOS/Rosetta, Linux, Windows, or OCI qualification from that archive.
  - [x] Make the native producer select the explicit `full` feature profile; make narrow-beta or
        ambiguous runtime receipts fail closed; and implement exact full-help, executable-digest,
        semantic-identity, workflow-binding, no-egress, permission-denial, backup/restore, and
        retained-upgrade verification. A locally staged release-byte diagnostic passed all 23
        checks under Seatbelt. Clean non-admin archive/Homebrew qualification, signing, and
        notarization remain open, so the parent task remains unchecked.
- [ ] Build and qualify npm, Rust crate chain, Python wheel/sdist, Go module, Claude plugin, and a
      macOS arm64 native distribution containing every required sidecar. The Linux amd64/arm64
      non-root OCI index is deferred to a separate profile.
- [ ] Freeze the initial installer scope to an Apple-silicon Homebrew formula/bottle plus the
      signed/notarized macOS arm64 archive. Intel bottles, WinGet, deb/rpm/MSI, and Linux package
      managers require later profile-specific producers and qualification.
- [ ] Install, upgrade, use offline, and uninstall every artifact in a clean non-admin,
      no-compiler, empty-cache environment. Preserve unrelated user/host configuration.
- [ ] Execute every documentation command and live operational exercise against exact installed
      bytes.
- [ ] Resolve all distributed license-review items; generate artifact-level SPDX and CycloneDX
      SBOMs and reconcile them with packed/unpacked/image inventories.
- [ ] Scan every archive, package, installer, binary, root filesystem, image layer, and plugin for
      vulnerabilities, secrets, malware/miner indicators, endpoints, developer paths, unexpected
      executables, and license issues.
- [ ] Prove two-builder reproducibility or the approved closed normalization comparison; apply
      macOS signing/notarization, ecosystem-package signatures, provenance, and isolated production
      signatures only after qualification. Windows and OCI signing remain deferred with those
      profiles.

Required live operational exercises:

- [ ] Key creation/custody and rotation with retired-key verification and current revocation.
- [ ] Local storage corruption/authentication recovery and exact semantic-root comparison.
- [ ] Index rebuild under read traffic with generation/watermark validation.
- [ ] Degraded compiler/vector/extension operation without authorization weakening.
- [ ] Unknown-effect recovery, journal quarantine, and connector/adapter disable.
- [ ] Transport identity, OIDC/JWKS/mTLS rotation, and credential expiry.
- [ ] Capacity/queue-age response, graceful drain, restart, and rollback.
- [ ] Shared backup/restore and rolling migration on production-shaped external services.

Exit gate:

- [ ] WP21 is complete; every claimed platform/profile has installed-byte evidence, every artifact
      is reproducible and fully bound to SBOM/license/scan/provenance/signature records, and no
      final-byte critical/high finding remains.

## FULL-1000 — Complete WP22, publish exact bytes, and transition documentation

Dependencies: FULL-900

Execute `todo-launch.md` LAUNCH-400 through LAUNCH-404.

- [ ] Close `packaging/qualification-gaps.v1.json` only from independently read machine evidence.
- [ ] Assemble every required category in canonical `release-evidence.json`; reject missing,
      failed, skipped, waived, stale, synthetic, dirty, mutable, or incorrectly bound inputs.
- [ ] Perform independent offline verification plus artifact/signature/SBOM/provenance/source/policy
      substitution, omission, duplication, rollback, and tampering tests.
- [ ] Obtain required human security, legal, platform, operations, compatibility, and release
      approvals against the exact candidate and artifacts.
- [ ] Publish already-qualified immutable bytes without rebuilding or mutating metadata. Read every
      registry object, package, image, installer, archive, signature, SBOM, provenance, and evidence
      object back by digest before signing the final tag.
- [ ] Preserve the initial beta artifacts and documentation as a separate immutable lane.
- [ ] Sync the exact released source commit into `cigar-website` through its reviewed importer;
      never copy a dirty sibling worktree.
- [ ] Create a versioned full-product documentation lane. Do not relabel `/docs/dev/` in place.
- [ ] Derive capabilities, compatibility, downloads, and support state from signed publication and
      public readback records. Change `development` to `supported` only for the exact
      artifact/platform/profile combinations with evidence.
- [ ] Run website content, browser, accessibility, CSP, output-boundary, reproducibility, container,
      staging, and public readback gates before promotion.

Exit gate:

- [ ] WP22 and `cargo xtask release verify dist/` pass without waiver or skipped condition.
- [ ] Public bytes match the final release evidence exactly.
- [ ] The website cannot expose a download or support claim without authenticated publication
      state, and unsupported optional profiles remain visibly excluded.

## Rollout cohorts

Use internal cohorts to reduce blast radius. A cohort is not a public support claim until it has its
own exact artifacts and evidence.

1. **Local read-only context:** discovery, ingest, catalog query, policy, retrieval,
   plan/compile/explain/materialize, and non-vector fallback.
2. **Local durable coordination:** spaces, checkpoints, handoffs, recorded replay, backup, and GC;
   effects remain prepare-only.
3. **Connector canary:** enable one reviewed effect connector at a time with explicit approval,
   reconciliation, compensation, disable switch, and fault evidence.
4. **Local interfaces:** full CLI, daemon/local IPC, Rust SDK, other SDKs, MCP, and Claude plugin.
5. **Shared synthetic staging:** PostgreSQL/object storage, tenant isolation, OIDC/mTLS, failover,
   rolling migrations, optional vector backend, and operational exercises.
6. **Multi-platform release candidate:** exact installed artifacts and long campaigns; no source
   changes after qualification begins.
7. **Full release:** independent offline verification, approvals, signatures, exact-byte public
   promotion, and digest readback.
8. **Post-release:** content-safe monitoring, dependency/scanner refresh, rollback, connector
   disable, key rotation, and recovery exercises.

## Completion contract for every checkbox

Before marking any implementation checkbox complete:

- the behavior and security boundary exist in production code rather than a fixture-only adapter;
- no `TODO`, placeholder success, unsupported alias, silent fallback, or ignored flag is reachable;
- limits, cancellation, deadlines, idempotency, revisions, redaction, and content-safe errors are
  explicit;
- unit, property, integration, conformance, fault, compatibility, and documentation tests required
  by the surface pass;
- generated schemas, API references, fixtures, SDKs, CLI/MCP tables, and website source inputs have
  no drift;
- evidence is canonical, immutable, complete, source/artifact-bound, outside the candidate, and
  independently read;
- any migration, effect, key, backup, shared-store, or authorization change includes recovery and
  negative tests; and
- the task's exit gate passes from installed artifacts on every claimed platform/profile.

Any source, schema, vector, lockfile, generator, toolchain, build script, gate policy, or artifact
content change creates a new candidate and invalidates affected and downstream evidence according
to `todo-launch.md`.

## Explicit non-scope

Do not add an agent planner, workflow scheduler, model gateway, vector-database product,
graph-database product, hosted billing system, agent studio, prompt marketplace, visual workflow
editor, private provider-file parser, universal exactly-once claim, or deterministic-model-output
claim. Do not add provider adapters beyond the checked-in Claude Code adapter without a separately
approved product/security plan. These are PRD non-goals or future possibilities, not unfinished
features hidden by the initial beta boundary.
