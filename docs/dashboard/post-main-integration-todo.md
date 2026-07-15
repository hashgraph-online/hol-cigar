# Dashboard post-main-codebase integration queue

Status: **optional observer plus three macOS non-soak controls integrated; soak and full qualification remain gated**
Maintainer: dashboard integration owner
Integration baseline: 2026-07-13 at
`56a5a1346bdfd362f67c279f4f8cd5d4ba7c46b2`; exact baseline and results are under
`docs/dashboard/integration-evidence/`. A post-baseline unrelated `README_BETA.md` is preserved
unmodified and excluded from dashboard evidence.
Purpose: the ordered, implementation-ready queue for connecting the optional dashboard to the
final protocol tree without overwriting concurrent work

This is the canonical handoff checklist. Keep incomplete work unchecked and record an evidence
path beside every completed item. Do not infer completion from a successful process exit alone.

## Immutable integration rules

- The dashboard remains an optional sidecar. Do not add it to Cargo `default-members`, start it
  from `cigard`, add a dashboard listener to the daemon, or put dashboard services in base
  deployment manifests.
- Use the public `cigar-sdk` for daemon HTTP/SSE calls. Do not add direct database access, an ad-hoc
  daemon HTTP client, or browser access to the daemon bearer token.
- Preserve the final main-agent tree. Never resolve overlap with reset, checkout, clean, bulk
  formatting, generated-file replacement, or lockfile regeneration before inspecting its diff.
- Protocol operations and browser models are generated from frozen catalogs/schemas. Never ship a
  handwritten second list of the 45 operations.
- Test commands remain disabled until a reviewed supervisor and receipt producer prove their exact
  security/evidence contract. Three non-soak macOS profiles now meet that narrower gate; soak stays
  disabled until an isolated driver exists. A healthy daemon is not release evidence.

## Completion gate — establish exclusive shared-file ownership

- [x] Obtain confirmation that the main-codebase job is complete and no agent/process still owns
  root manifests, locks, generated API surfaces, `sdk/`, `crates/cigar-daemon/`, `xtask`, quality
  tooling, deployment bases, or release evidence.
- [x] Capture `git rev-parse HEAD`, `git status --short`, `git diff --stat`, and the staged diff in
  `docs/dashboard/integration-evidence/baseline.txt`. Record every pre-existing modification and
  untracked path; do not stage or edit unrelated entries.
- [ ] Verify `.git/index.lock` is absent and no package manager, generator, formatter, or Cargo
  lock writer is active. If any shared file changes during the audit, stop and restart this gate.
  `.git/index.lock` was absent; managed macOS sandbox denied both `ps` and `pgrep`, so the process
  half is intentionally not attested. User ownership handoff plus a clean status established scope.
- [x] Re-read `AGENTS.md`, final architecture/PRD decisions, root manifests, generator entrypoints,
  API compatibility tests, and deployment/release scripts from the final HEAD. Reconcile this list
  with final names before editing.
- [ ] Create a dedicated dashboard integration branch or worktree from the released HEAD. Bring
  dashboard-owned paths across without copying stale shared files.
  Not performed: the dashboard paths had already landed in commit `56a5a134`; changes remain
  unstaged in the existing user worktree rather than mutating Git branch/worktree state.

Exit gate: the baseline evidence names the exact commit and dirty entries, ownership is exclusive,
and a reviewer can distinguish pre-existing work from dashboard integration.

## INT-001 — preserve typed unhealthy readiness in `cigar-sdk`

Files to inspect: daemon `/readyz` handler, Rust SDK remote decoder and transport tests, generated
health response types, compatibility fixtures.

- [x] Add an SDK transport fixture where `/readyz` returns HTTP 503 with the valid negotiated media
  type and a strict typed `ReadinessResponse { ready: false, ... }`.
- [x] Change the shared SDK response policy narrowly so this endpoint returns the typed unhealthy
  value. Continue rejecting malformed bodies, wrong media types, redirects, oversized bodies,
  invalid versions, and non-success statuses for endpoints that do not define a typed status body.
- [x] Preserve typed CIGAR problems and retry classification. Do not convert arbitrary 503 JSON into
  success and do not add a dashboard-only response decoder.
- [ ] Test ready 200, unhealthy 503, malformed 503, problem 503, redirect, timeout, cancellation,
  token rotation, and compatibility mismatch.
  The new exact cases plus existing negotiation/credential suites pass; redirect, timeout, and
  cancellation are not yet assembled into one readiness-specific matrix.
- [ ] Run the SDK/daemon transport suites and store their machine-readable receipts.

Exit gate: the dashboard can distinguish `unhealthy` from `unreachable` exclusively through the
SDK, and the old success/error paths remain covered.

## INT-002 — integrate the Rust workspace once

Files: root `Cargo.toml`, `Cargo.lock`, dashboard/soak manifests.

- [x] Add `crates/cigar-dashboard` and `crates/cigar-soak` to workspace `members`; leave
  `default-members` byte-for-byte unchanged.
- [x] Prefer one reviewed root workspace dependency for `cigar-sdk` with `default-features = false`
  and switch the dashboard manifest to inherit it. Add no daemon/store implementation dependency.
- [x] Reconcile only dependencies actually used by the completed crates. Pin according to the
  repository policy; do not opportunistically upgrade unrelated packages.
- [x] Update `Cargo.lock` once, then inspect its diff for unrelated version churn, duplicate major
  lines, default feature activation, native/TLS additions, and unexpected build scripts.
- [x] Prove `cargo build` default outputs and existing CLI/daemon help/listeners/config behavior are
  unchanged. Separately build/test both new packages with all targets.
- [ ] Run format, strict Clippy, dependency/license/advisory checks, and the existing workspace
  tests. Archive exact commands, commit, toolchain, and receipts.
  Dashboard/soak format, tests, and strict Clippy pass; beta profile/tests/Clippy pass. Root
  `cargo xtask lint` stops on pre-existing vendored TODO/secret-marker findings, so the complete
  workspace lint/advisory gate remains open rather than being suppressed.

Exit gate: default builds do not include/start the dashboard, and explicit package builds are clean.

## INT-003 — generate browser and dispatcher contracts

Files: final API/schema generator, frozen operation/payload/error catalogs, generated Rust/TypeScript
outputs, drift checks.

- [ ] Extend the authoritative generator to emit dashboard operation metadata and a typed Rust
  dispatch table from the frozen catalogs. Include service, operation ID, method/path, auth class,
  mutation class, streaming, dry-run/revision/idempotency requirements, media types, and limits.
  Observer v1 serializes `cigar_api::generated::OPERATIONS` directly and accounts for all 45 IDs;
  the generic typed mutation dispatcher, payload schemas/media/limit metadata, and call policy stay
  open. Do not replace the generated-registry projection with a copied browser list.
- [ ] Generate browser-safe TypeScript models and validators from dashboard JSON Schemas. Do not
  import Node transports or secrets into the browser bundle.
- [ ] Make generation deterministic: stable ordering, normalized newlines, generator/source digest,
  checked-in outputs where repository policy requires them, and a zero-diff regeneration test.
- [ ] Reject missing/duplicate operation IDs, unsupported schemas, unknown mutation classes, unsafe
  generic operations, and catalog/schema disagreement at generation time.
- [ ] Add the 11+ dashboard schemas and their local references to final schema/docs manifests and
  strict validation/drift jobs.

Exit gate: one generated source of truth accounts for all 45 frozen operations and regeneration is
byte-stable.

## INT-004 — integrate the private frontend workspace

Files: `pnpm-workspace.yaml`, root/package lock, `apps/dashboard/package.json`, build configuration,
generated API models, static asset manifest generator.

- [x] Add only `apps/dashboard` to the pnpm workspace. Keep root install/build behavior optional and
  do not make daemon/core release jobs depend on Node.
- [x] Review the frontend dependency decision. Observer v1 intentionally retains native browser
  APIs and CSS with zero third-party dependencies; `pnpm-lock.yaml` gained only the empty private
  importer. React/Vite/chart packages are unnecessary for the delivered bounded surface.
- [x] Land the dependency-free display-preference foundation: closed System/Light/Dark,
  Comfortable/Compact, and System/Standard/Reduced cycling; semantic text/icon labeling;
  malformed-value, cross-tab, and storage-denied fallbacks; an Escape-closeable native menu; and
  unit tests. It persists only three versioned display keys, never protocol/session/live-update data.
- [x] Land bounded live-update controls in the prototype: pause closes EventSource and suppresses
  automatic polling without clearing the last classification; one manual refresh remains available;
  resume and foreground visibility request one immediate refresh. The queue coalesces concurrent
  manual refresh requests to one. Pure policy tests fail closed for unknown state.
- [x] Migrate the dependency-free prototype without regressing CSP, keyboard behavior, reduced
  motion overrides, density/theme/live-update controls, 320 px layout, 200% zoom, semantic text/icon
  states, or the always-visible status rail.
- [x] Generate a deterministic exact-byte static asset manifest as part of the explicit dashboard
  build. Reject undeclared files, traversal, symlinks, MIME disagreement, and stale digests.
  `pnpm --filter @cigar/dashboard build` now regenerates the sorted canonical manifest; the
  independent verifier enforces all listed properties. Content-hash filenames are not required by
  this exact-byte manifest contract.
- [ ] Add unit/component/accessibility/browser tests for all aggregate states, stale/unreachable
  transitions, disabled controls, long bounded values, hostile text, light/dark themes, and no-JS
  bootstrap failure.
- [x] Prove the production bundle contains no daemon credential, raw target URL credential,
  arbitrary command surface, Node transport, eval/dynamic code execution, or external asset fetch.
  The exact-byte build now runs `verify-browser-security.mjs` over every production HTML, CSS, and
  JavaScript asset. All network calls cross one closed same-origin route wrapper with redirect,
  credential, and referrer confinement. Thirty-one browser unit/model cases plus 23 independent
  verifier/hostile-fixture cases pass on native Apple-silicon macOS; the hostile fixtures cover
  external and inline content, direct transports, Node APIs, dynamic code/DOM sinks, privileged
  fields, missing module dependencies, and wrapper weakening.

Exit gate: a clean checkout can explicitly build deterministic verified assets, while core builds
remain Node-independent.

## INT-005 — complete typed status, diagnostics, and safe streaming

Files: dashboard gateway/status/metrics/event modules, SDK fixtures, sidecar schemas, frontend status
views.

- [x] Poll typed version/capabilities/configuration/diagnostics/readiness/liveness and parse only the
  closed bounded OpenMetrics families. Validate unique components/workers, finite values, queue
  depth <= capacity, monotonic counters, and exact freshness semantics.
- [ ] Add the complete fixture matrix: healthy, degraded, unhealthy 503, startup, graceful shutdown,
  timeout, disconnect, reconnect, stale, incompatible, token rotation, malformed/oversized metrics,
  counter reset, duplicate series, and clock anomalies.
- [x] Land the conflict-free browser status foundation: the persistent rail consumes only the
  sanitized aggregate status plus SSE invalidations; a native health disclosure shows exact
  aggregate/configuration/diagnostics times, freshness, failures, redacted alias, closed
  configuration facts, stale sources, component reason codes/latencies, and reconnect. Its pure
  model tests cover exact 10/30-second boundaries, malformed ages, closed states/transports, and
  bounded byte formatting. Typed upstream problem codes/runbook links and browser fixtures remain.
- [x] Implement bounded in-memory history and resumable sidecar SSE with monotonic IDs, per-client
  buffers, lag/truncation signals, cancellation, reconnect behavior, and no protected content.
  Landed before shared integration in `events.rs`, `history.rs`, and the authenticated server route;
  evidence: 50-test isolated dashboard suite plus strict Clippy on 2026-07-13.
- [ ] Proxy protocol events through the SDK only after event schemas/redaction rules are complete.
  Do not persist source text, prompts, raw effect arguments, credentials, or arbitrary upstream
  errors.
- [x] Keep operational, latest-verification, and candidate-bound release states independent in APIs
  and every browser route.

Exit gate: status classification is deterministic under the full fixture matrix and all buffers,
polls, values, labels, bodies, and reconnect attempts are bounded.

## INT-006 — implement the allowlisted job supervisor

Files: reviewed run registry, dashboard job/run-store modules, run/event schemas, test fixtures.

- [x] Resolve only immutable reviewed profile IDs to closed executable identities and fixed argv.
  Never accept command text, paths, flags, environment keys, working directories, or shell fragments
  from HTTP. Evidence: macOS supervisor integration and negative browser control tests in the
  86-test Rust/31-test browser-model suites on 2026-07-14; exact non-soak results are in
  `docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.
- [ ] Require control enablement, authenticated session, CSRF, availability probe, concurrency
  permit, isolated absolute roots, confirmation metadata, and a persisted queued record before spawn.
- [ ] Implement process-group/job-object ownership, bounded environment, no inherited daemon token,
  stdout/stderr byte caps, structured safe progress, timeout, TERM/grace/KILL cancellation, shutdown
  cleanup, orphan reconciliation, and crash-safe terminal transitions.
  Native macOS now has a dedicated process group, cleared allowlist environment, content-opaque
  output caps, timeout/cancel/shutdown TERM-grace-KILL-reap, bounded descendant/output settlement,
  and independent terminal states. SQLite v4 atomically binds `running` to PID/PGID plus a macOS
  creation-identity digest and an inherited liveness lock; restart marks only a proven-empty group
  `lost`, while live/legacy/preparing/ambiguous rows fail closed without signalling a recovered PID.
  Child-only CPU/core/file/FD rlimits, polled aggregate RSS/process ceilings, tool-version and
  monotonic timing, and disk-full classification are implemented. A real supervisor test process
  exits without destructors while its child remains alive; restart refuses the live identity and
  reconciles only after the exact child identity is absent. Actual CPU-time termination, file-size
  truncation, open-file exhaustion, aggregate RSS, and aggregate process-count tests pass.
  Structured progress, exhaustive child-escape handling, and non-macOS support remain open and keep
  this aggregate box unchecked.
- [x] Complete dashboard-only SQLite metadata with transactional byte retention, evidence-root
  confinement, disk-full policy, and active-process restart recovery. Never read daemon storage.
  Schema v4 reserves aggregate output/evidence ceilings at queue time and atomically settles exact
  observed usage with lifecycle, process identity, and both sanitized descriptors. Unsafe or
  over-limit trees cannot pass; `SQLITE_FULL`/receipt `ENOSPC` fail closed without partial terminal
  state. Destructive full-volume qualification remains an external exit-gate test.
- [x] Land the conflict-free persistence foundation: append-only schema v4, runs/transitions/safe-
  events/evidence-descriptor/preferences tables, private WAL/FULL-sync single writer, strict
  monotonic run records, terminal age/count pruning, restart reload, and authenticated bounded run
  plus sanitized evidence list/detail reads with short-lived collection-bound HMAC cursors. Startup
  quick-check/foreign-key validation and retention regressions fail closed. The same single writer
  now produces create-new owner-only online SQLite snapshots, validates/syncs each snapshot, refuses
  overwrite/link/permissive-parent paths, and passes independent reopen/readback tests. This is not a
  restore API and does not authorize process launch or filesystem receipt ingestion.
  Schema v4 additionally records supervisor generation and private process identity, migrates v2
  rows as explicit legacy generation 0, adds an empty resource ledger when migrating v3 without
  inventing historical usage, closes identity rows at terminal settlement, and rejects malformed or
  lifecycle-inconsistent active identities.
- [ ] Verify receipts independently: schema, source revision, binary/artifact digest, profile digest,
  timestamps, status, completeness, and candidate binding. Process exit zero alone never passes.
  The three enabled development profiles now require canonical confined receipts bound to source,
  profile/matrix, macOS/arm64, counts/status/canary, and process outcome, plus a separate executable/
  argv/registry/environment/output supervisor receipt that explicitly binds the dashboard and
  profile SHA-256 values. A fail-closed local verifier now binds an arm64 dashboard executable,
  archive, asset manifest, package contract, and source identity but can emit only a partial
  `installed-unqualified` descriptor. No real installed artifact, authenticated signature,
  notarization, provenance, or candidate binding was qualified, so this aggregate box remains open.
- [ ] Enable a profile in the API/UI only after its executable contract and positive/negative tests
  pass. Keep unavailable profiles visible with a stable reason.
  `dashboard-contracts` has a real positive supervisor integration. Compatibility/security matrix
  producers share the reviewed matrix receipt verifier, but only a profile whose complete executable
  ancestry passes the immutable-tool checks is exposed as available; this host intentionally reports
  the mutable Homebrew-backed compatibility toolchain as `tool_missing`. Those matrix profiles have
  not been run end-to-end through the UI in this pass. Every soak/exit-only command remains unavailable.

Exit gate: focused injection, traversal, symlink/hard-link, TOCTOU, cancellation, restart,
disk-full-error classification, output flood, forged receipt, resource-launcher, and concurrent-
start tests pass. Evidence:
`docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`. Destructive volume
exhaustion and exhaustive escaped-descendant tests remain open.

## INT-007 — connect the isolated soak driver

Files: `cigar-soak`, testkit/sim extensions, daemon installed-binary launcher, soak schemas and
profiles.

- [ ] Implement a driver trait and a production installed-binary driver that creates private temp
  state/runtime/project/evidence roots and launches its own daemon. It must never target the status
  daemon or user data.
- [ ] Bind plan/result to seed, source revision, exact binary digests, config digest, profile digest,
  platform, start/end times, and deterministic fault schedule.
- [ ] Implement mixed workloads, session bands, reference comparisons, invariant sampling,
  throughput/error/latency/resource series, queue saturation, cancellation, cleanup, and explicit
  partial/failed outcomes.
- [ ] Use deterministic fault controls supplied by testkit/sim; never use shell commands, global
  network mutation, host clock changes, or unbounded resource exhaustion.
- [ ] Prove the verifier rejects stale, duplicated, truncated, synthetic, under-duration,
  insufficient-sample, invariant-violating, wrong-binary, and wrong-source results.
- [ ] Run accelerated deterministic qualification before enabling 5m/30m/2h/24h profiles. Long-run
  buttons remain disabled until shorter stages, leak trends, cancellation, and cleanup pass.

Exit gate: the supervisor launches an isolated soak, streams only safe progress, verifies the result,
and leaves user state and the observed daemon untouched.

## INT-008 — optional command, deployment, and packaging surfaces

- [ ] Add `cargo xtask dashboard build|test|check` only after final xtask semantics are stable. Every
  subcommand must execute real work and validate receipts; no alias/placeholders may report green.
- [ ] Add an explicit Compose profile/override and separate Kustomize overlay. Base Compose/K8s
  outputs must have no dashboard image, port, service, ingress, secret, volume, or policy.
- [ ] Default to numeric loopback. Remote/multi-user/production ingress is out of v1 scope. Ensure
  browser sessions, Host/Origin/CSRF, credential mounts, read-only filesystem, capabilities,
  resources, shutdown, and network policy match the threat model.
- [ ] Define a separately selected dashboard package/artifact with SBOM, licenses, provenance,
  static asset manifest, reproducibility record, and uninstall/upgrade behavior. Core artifacts
  remain dashboard-free.
  - [x] Define the development-source `cigar-dashboard-macos-aarch64` artifact identity and separate
    `macos-dashboard-archive-v1` exact package contract. The contract excludes `cigar-soak`, source
    maps, credentials, state, runtime, evidence, sandbox, and build-tree content. It is deliberately
    absent from the artifact matrix until a producer and installed qualification exist. Evidence:
    `packaging/development/contracts/macos-dashboard-archive.v1.json` and
    `docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.
- [x] Prove by source invariant that Cargo default members, the ordinary macOS runtime archive,
  daemon Dockerfile, base Compose YAML, and shared Kubernetes YAML contain no dashboard or soak
  inclusion. This is an omission-source test, not a live install/deployment comparison. Evidence:
  `architecture_tests::dashboard_is_absent_from_default_build_core_archive_and_base_deployments` in
  `docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.
- [x] Add operator/security/troubleshooting/runbook docs, including credential rotation, stale
  status, incompatible target, disabled controls, run cancellation/recovery, retention, and complete
  removal. Evidence: `docs/dashboard/{index,operator-guide,security,testing,troubleshooting,development}.md`.

Exit gate: omission tests prove every core install/deployment/release path is unchanged unless the
dashboard is explicitly selected.

## INT-009 — qualification and release evidence

- [ ] Run sidecar security cases: session fixation/replay/expiry/capacity, bootstrap replay, CSRF,
  Host/Origin, redirect/proxy bypass, request/body/header limits, cache/CSP/security headers,
  credential leakage, path confinement, parser fuzzing, and child-process abuse.
- [ ] Run browser accessibility, responsive, reduced-motion, keyboard, stale-state, reconnect, and
  performance tests with table/text equivalents for charts.
- [ ] Run supported-platform install/start/upgrade/uninstall tests separately from CIGAR core claims.
- [ ] Run deterministic accelerated soaks, then 5m, 30m, 2h, and finally 24h. Bind every accepted
  result to the release candidate and archive the verifier output. A rerun invalidates superseded
  candidate evidence explicitly.
- [ ] Re-run optionality comparison: default dependency graph, artifacts, help, listeners,
  environment reads, accepted daemon config, deployment renders, SBOM, install footprint, and core
  test matrix before/after integration.
  - [x] Complete the source-level default-member, runtime-contract, Dockerfile, base-Compose, and
    shared-Kubernetes omission slice. Dynamic listeners/config/environment/SBOM/install-footprint
    comparisons remain open. Evidence:
    `docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.
- [ ] Review all remaining boxes in `todo-dashboard.md`; mark complete only with a named evidence
  path and commit. Document accepted deferrals as v2 scope rather than silently lowering v1 gates.

Final exit gate: the optional dashboard can be built, run, tested, soaked, packaged, and removed
without changing CIGAR protocol semantics or default behavior, and every claim has candidate-bound
machine-verifiable evidence.
