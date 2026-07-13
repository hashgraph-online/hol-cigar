# Dashboard post-main-codebase integration queue

Status: **deferred until the main-codebase agent has completed and released ownership of shared
files**  
Maintainer: dashboard integration owner  
Last dashboard-only audit: 2026-07-13 at
`9ee6b09cf73397eb1b02da9991e3dbcf12c7b301`; tracked/shared files were clean and only the
dashboard-owned new paths were untracked. This is not an ownership handoff: integration remains
blocked until the main-codebase agent explicitly reports completion  
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
- Test and soak commands remain disabled until a reviewed supervisor and isolated driver prove
  their security and evidence contracts. A healthy daemon is not release evidence.

## Completion gate — establish exclusive shared-file ownership

- [ ] Obtain confirmation that the main-codebase job is complete and no agent/process still owns
  root manifests, locks, generated API surfaces, `sdk/`, `crates/cigar-daemon/`, `xtask`, quality
  tooling, deployment bases, or release evidence.
- [ ] Capture `git rev-parse HEAD`, `git status --short`, `git diff --stat`, and the staged diff in
  `docs/dashboard/integration-evidence/baseline.txt`. Record every pre-existing modification and
  untracked path; do not stage or edit unrelated entries.
- [ ] Verify `.git/index.lock` is absent and no package manager, generator, formatter, or Cargo
  lock writer is active. If any shared file changes during the audit, stop and restart this gate.
- [ ] Re-read `AGENTS.md`, final architecture/PRD decisions, root manifests, generator entrypoints,
  API compatibility tests, and deployment/release scripts from the final HEAD. Reconcile this list
  with final names before editing.
- [ ] Create a dedicated dashboard integration branch or worktree from the released HEAD. Bring
  dashboard-owned paths across without copying stale shared files.

Exit gate: the baseline evidence names the exact commit and dirty entries, ownership is exclusive,
and a reviewer can distinguish pre-existing work from dashboard integration.

## INT-001 — preserve typed unhealthy readiness in `cigar-sdk`

Files to inspect: daemon `/readyz` handler, Rust SDK remote decoder and transport tests, generated
health response types, compatibility fixtures.

- [ ] Add an SDK transport fixture where `/readyz` returns HTTP 503 with the valid negotiated media
  type and a strict typed `ReadinessResponse { ready: false, ... }`.
- [ ] Change the shared SDK response policy narrowly so this endpoint returns the typed unhealthy
  value. Continue rejecting malformed bodies, wrong media types, redirects, oversized bodies,
  invalid versions, and non-success statuses for endpoints that do not define a typed status body.
- [ ] Preserve typed CIGAR problems and retry classification. Do not convert arbitrary 503 JSON into
  success and do not add a dashboard-only response decoder.
- [ ] Test ready 200, unhealthy 503, malformed 503, problem 503, redirect, timeout, cancellation,
  token rotation, and compatibility mismatch.
- [ ] Run the SDK/daemon transport suites and store their machine-readable receipts.

Exit gate: the dashboard can distinguish `unhealthy` from `unreachable` exclusively through the
SDK, and the old success/error paths remain covered.

## INT-002 — integrate the Rust workspace once

Files: root `Cargo.toml`, `Cargo.lock`, dashboard/soak manifests.

- [ ] Add `crates/cigar-dashboard` and `crates/cigar-soak` to workspace `members`; leave
  `default-members` byte-for-byte unchanged.
- [ ] Prefer one reviewed root workspace dependency for `cigar-sdk` with `default-features = false`
  and switch the dashboard manifest to inherit it. Add no daemon/store implementation dependency.
- [ ] Reconcile only dependencies actually used by the completed crates. Pin according to the
  repository policy; do not opportunistically upgrade unrelated packages.
- [ ] Update `Cargo.lock` once, then inspect its diff for unrelated version churn, duplicate major
  lines, default feature activation, native/TLS additions, and unexpected build scripts.
- [ ] Prove `cargo build` default outputs and existing CLI/daemon help/listeners/config behavior are
  unchanged. Separately build/test both new packages with all targets.
- [ ] Run format, strict Clippy, dependency/license/advisory checks, and the existing workspace
  tests. Archive exact commands, commit, toolchain, and receipts.

Exit gate: default builds do not include/start the dashboard, and explicit package builds are clean.

## INT-003 — generate browser and dispatcher contracts

Files: final API/schema generator, frozen operation/payload/error catalogs, generated Rust/TypeScript
outputs, drift checks.

- [ ] Extend the authoritative generator to emit dashboard operation metadata and a typed Rust
  dispatch table from the frozen catalogs. Include service, operation ID, method/path, auth class,
  mutation class, streaming, dry-run/revision/idempotency requirements, media types, and limits.
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

- [ ] Add only `apps/dashboard` to the pnpm workspace. Keep root install/build behavior optional and
  do not make daemon/core release jobs depend on Node.
- [ ] Select exact reviewed React, Vite, test, accessibility, and chart dependencies; prefer native
  browser APIs and CSS over packages. Update `pnpm-lock.yaml` once and inspect all transitive changes.
- [x] Land the dependency-free display-preference foundation: closed System/Light/Dark,
  Comfortable/Compact, and System/Standard/Reduced cycling; semantic text/icon labeling;
  malformed-value, cross-tab, and storage-denied fallbacks; an Escape-closeable native menu; and
  unit tests. It persists only three versioned display keys, never protocol/session/live-update data.
- [x] Land bounded live-update controls in the prototype: pause closes EventSource and suppresses
  automatic polling without clearing the last classification; one manual refresh remains available;
  resume and foreground visibility request one immediate refresh. The queue coalesces concurrent
  manual refresh requests to one. Pure policy tests fail closed for unknown state.
- [ ] Migrate the dependency-free prototype without regressing CSP, keyboard behavior, reduced
  motion overrides, density/theme/live-update controls, 320 px layout, 200% zoom, semantic text/icon
  states, or the always-visible status rail.
- [ ] Generate a deterministic exact-byte static asset manifest as part of the explicit dashboard
  build. Reject undeclared files, traversal, symlinks, MIME disagreement, and stale digests.
- [ ] Add unit/component/accessibility/browser tests for all aggregate states, stale/unreachable
  transitions, disabled controls, long bounded values, hostile text, light/dark themes, and no-JS
  bootstrap failure.
- [ ] Prove the production bundle contains no daemon credential, raw target URL credential,
  arbitrary command surface, Node transport, eval/dynamic code execution, or external asset fetch.

Exit gate: a clean checkout can explicitly build deterministic verified assets, while core builds
remain Node-independent.

## INT-005 — complete typed status, diagnostics, and safe streaming

Files: dashboard gateway/status/metrics/event modules, SDK fixtures, sidecar schemas, frontend status
views.

- [ ] Poll typed version/capabilities/configuration/diagnostics/readiness/liveness and parse only the
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
- [ ] Keep operational, latest-verification, and candidate-bound release states independent in APIs
  and every browser route.

Exit gate: status classification is deterministic under the full fixture matrix and all buffers,
polls, values, labels, bodies, and reconnect attempts are bounded.

## INT-006 — implement the allowlisted job supervisor

Files: reviewed run registry, dashboard job/run-store modules, run/event schemas, test fixtures.

- [ ] Resolve only immutable reviewed profile IDs to closed executable identities and fixed argv.
  Never accept command text, paths, flags, environment keys, working directories, or shell fragments
  from HTTP.
- [ ] Require control enablement, authenticated session, CSRF, availability probe, concurrency
  permit, isolated absolute roots, confirmation metadata, and a persisted queued record before spawn.
- [ ] Implement process-group/job-object ownership, bounded environment, no inherited daemon token,
  stdout/stderr byte caps, structured safe progress, timeout, TERM/grace/KILL cancellation, shutdown
  cleanup, orphan reconciliation, and crash-safe terminal transitions.
- [ ] Complete dashboard-only SQLite metadata with transactional byte retention, evidence-root
  confinement, disk-full policy, and active-process restart recovery. Never read daemon storage.
- [x] Land the conflict-free persistence foundation: append-only schema v2, runs/transitions/safe-
  events/evidence-descriptor/preferences tables, private WAL/FULL-sync single writer, strict
  monotonic run records, terminal age/count pruning, restart reload, and authenticated bounded run
  plus sanitized evidence list/detail reads with short-lived collection-bound HMAC cursors. Startup
  quick-check/foreign-key validation and retention regressions fail closed. The same single writer
  now produces create-new owner-only online SQLite snapshots, validates/syncs each snapshot, refuses
  overwrite/link/permissive-parent paths, and passes independent reopen/readback tests. This is not a
  restore API and does not authorize process launch or filesystem receipt ingestion.
- [ ] Verify receipts independently: schema, source revision, binary/artifact digest, profile digest,
  timestamps, status, completeness, and candidate binding. Process exit zero alone never passes.
- [ ] Enable a profile in the API/UI only after its executable contract and positive/negative tests
  pass. Keep unavailable profiles visible with a stable reason.

Exit gate: injection, traversal, symlink/hard-link, TOCTOU, cancellation, restart, disk-full, output
flood, forged receipt, and concurrent-start tests pass.

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
- [ ] Add operator/security/troubleshooting/runbook docs, including credential rotation, stale
  status, incompatible target, disabled controls, run cancellation/recovery, retention, and complete
  removal.

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
- [ ] Review all remaining boxes in `todo-dashboard.md`; mark complete only with a named evidence
  path and commit. Document accepted deferrals as v2 scope rather than silently lowering v1 gates.

Final exit gate: the optional dashboard can be built, run, tested, soaked, packaged, and removed
without changing CIGAR protocol semantics or default behavior, and every claim has candidate-bound
machine-verifiable evidence.
