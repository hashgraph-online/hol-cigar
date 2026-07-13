# CIGAR protocol dashboard v1 execution backlog

Audience: GPT-5.6 SOL implementation agents, CIGAR maintainers, and test operators
Repository review date: 2026-07-13
Observed baseline: `0d8a8115b4fa1bedec534eeca497a157836ed6da` (`Initial Commit`) plus an intentionally dirty WP19-WP21 worktree
Target: an optional, local-first sidecar for observing, exercising, and soak-testing CIGAR without changing protocol semantics or weakening its security boundaries

## Implementation checkpoint — 2026-07-13

This backlog is partially implemented in dashboard-owned new paths. Shared integration remains
deferred while the main-codebase agent owns root manifests, locks, generated surfaces, and quality
tooling. The implementation checkpoint observed `HEAD` at
`9ee6b09cf73397eb1b02da9991e3dbcf12c7b301`; the tracked/shared worktree was clean and only
dashboard-owned new paths remained untracked at the audit. Shared integration still stays deferred
until the main-codebase agent is explicitly complete and releases ownership; a clean snapshot alone
is not treated as authorization to edit root manifests, locks, SDK, generated, release, or
deployment files.

Completed slices (do not redo them):

- strict dashboard configuration, numeric-loopback/path separation, verified static-asset manifest,
  one-time bootstrap secret, bounded HMAC session/CSRF store, owner-only bootstrap file, Host/Origin
  rejection, security headers, request limits, and Axum static shell routing;
- responsive dependency-free browser shell with persistent operational/verification/release status
  separation, protocol-flow overview, reviewed test cards, disabled soak controls, light/dark tokens,
  keyboard focus, reduced motion, a tested System/Light/Dark local-only theme preference, bounded
  pause/resume plus background-tab live-update suspension, an accessible display menu with tested
  comfortable/compact density and System/Standard/Reduced motion policies, and 320 px layout;
- a read-only health-details disclosure sourced exclusively from the single sanitized aggregate
  status response, with exact observation times, freshness, failures, redacted target alias,
  deployment/transports/limits, diagnostics staleness, component reason codes, and reconnect;
- strict dashboard JSON schemas and local-reference validator;
- exact-byte-digest-bound reviewed run-profile registry with nine sorted profiles, closed executables,
  fixed argv, availability probes, platform/resource/duration bounds, and every command honestly
  `command_not_implemented` until the process supervisor exists;
- authenticated run-profile and aggregate-status APIs; explicit registry startup validation; typed
  `cigar-sdk` compatibility negotiation and liveness/readiness polling; rotating owner-only token
  file validation; bounded reconnect/freshness/failure classification; and dynamic browser status
  and profile rendering without exposing the daemon credential;
- typed redacted configuration polling plus parallel diagnostics/OpenMetrics polling; a bounded
  closed-family parser; cross-source queue/counter validation; stable diagnostic degradation; and a
  responsive queue-utilization view with a text equivalent;
- a bounded authenticated safe-event plane with monotonic IDs, exact replay, Last-Event-ID resume,
  explicit retention-gap/lag resync, hard subscriber limits, browser EventSource refresh, and a
  dashboard-only owner-protected SQLite journal that commits through one writer before publication;
- append-only dashboard SQLite schema v2 with strict runs, run-transition, safe-event, evidence-
  descriptor, and closed-preference tables; a validated monotonic run state machine; terminal-only
  oldest-first count/age pruning; restart reload; authenticated bounded run and sanitized evidence
  list/detail APIs with strict collection-bound HMAC cursor pagination; startup quick-check/foreign-
  key validation; serialized create-new owner-only online backup snapshots with integrity/readback
  tests; and browser verification/release cards sourced from independent histories while launch and
  filesystem ingestion remain disabled;
- `cigar-soak` deterministic plan generation for all four required durations plus offline result
  verification covering duplicate keys, plan/source/binary bindings, phases, session bands, scheduled
  faults, sample sufficiency, timestamps, invariant/status consistency, and passing duration;
- dashboard developer/testing/architecture/ADR documentation and an explicit shared-integration
  handoff.

Verified independently outside the shared Cargo workspace: 50 `cigar-dashboard` tests and 4
`cigar-soak` tests pass offline; both crates pass strict Clippy with warnings, unwrap/expect/panic,
TODO/unimplemented, and indexing denied. The dependency-free browser models have 20 passing Node tests;
14 dashboard schemas and 53 local references validate.

Still intentionally blocked or incomplete:

- root Cargo/pnpm membership and lockfile updates. The canonical ordered post-main-agent handoff is
  `docs/dashboard/post-main-integration-todo.md`; the deferral rationale remains in
  `docs/dashboard/integration-deferred.md`;
- active-process recovery, filesystem receipt ingestion and independent verification, transactional
  byte ledgers, generated 45-operation dispatcher, and React/generated-model integration;
- the current `cigar-sdk` remote decoder rejects a valid typed readiness body carried with HTTP 503;
  the shared SDK must preserve that typed unhealthy observation before DASH-011 can claim its full
  readiness fixture matrix. The dashboard does not bypass the SDK to work around it;
- job supervisor and real isolated soak workload driver. `cigar-soak run` fails closed with
  `DriverUnavailable`, and every browser launch button remains disabled;
- long soaks, packaging, optional deployment overlays, and any release/qualification claim.

## Outcome

Build a polished dashboard that makes CIGAR understandable while it is running. The dashboard must show protocol health on every screen, visualize the major record and state-machine flows, safely exercise the frozen v1 operation surface, launch only reviewed test/soak profiles, and preserve machine-readable run evidence.

The dashboard is **100% optional**:

- `cigard`, `cigar`, MCP, SDKs, embedded mode, and every existing API continue to build and run when no dashboard package is installed or process is started.
- The dashboard is a separate `cigar-dashboard` process. Do not add it as a runtime dependency of `cigar-daemon`, do not start it implicitly, and do not add a default listener to `cigard`.
- Existing workspace `default-members` stay unchanged. An ordinary `cargo build` continues to build only the existing CLI/daemon/MCP defaults.
- Compose and Kubernetes assets enable it only through an explicit profile/overlay. Base deployments contain no dashboard container, port, service, ingress, credential, or network rule.
- The daemon remains the authority for protocol behavior. The dashboard never reads or writes daemon SQLite/PostgreSQL/blob state directly.

## Repository findings that constrain the design

| Existing surface | Observed implementation | Dashboard implication |
|---|---|---|
| Frozen API | `spec/api/operations-v1.json` declares 45 HTTP/gRPC operations; generated Rust/TypeScript contracts already exist | Generate the explorer and sidecar dispatch table from the frozen catalogs; never maintain a handwritten second operation list |
| Status | `/livez`, `/readyz`, `/v1/version`, `/v1/capabilities`, `/v1/configuration`, `/v1/diagnostics`, and `/metrics` already exist | Aggregate these through the sidecar; do not add a redundant dashboard status endpoint to `cigard` |
| Streaming | `subscribeSpaceEvents` already uses bounded resumable SSE | Proxy verified events through the sidecar and preserve resume IDs; do not invent WebSocket-only semantics |
| Client | `cigar-sdk` supports typed remote calls, compatibility negotiation, retry rules, and SSE | The Rust sidecar must use `cigar-sdk` with `default-features = false`; it must not reimplement daemon transport behavior |
| Telemetry | `crates/cigar-daemon/src/telemetry.rs` exposes four process counters and bounded queue metrics; OTLP exists | V1 can provide a useful status view, but required PRD metrics are incomplete and need an explicit instrumentation packet |
| Observability crate | `crates/cigar-observe` is currently only a placeholder module | Put reusable content-safe metric/event types here when they are shared; do not move dashboard HTTP/UI code into it |
| Test support | `crates/cigar-testkit` and `crates/cigar-sim` are skeletal | Extend them with deterministic workload/fault controls before claiming a meaningful soak harness |
| Test matrices | Security, compatibility, chaos, migration, and installation matrices plus `tools/quality/run_matrix.py` exist | Test Center launches allowlisted matrix profiles and consumes their receipts; it never constructs arbitrary shell commands |
| Soak requirement | `prd.md` requires a 24-hour mixed workload and `soak-result.v1.json`, but no first-class soak harness/result schema exists | Implement a real isolated soak driver and evidence schema before enabling the 24-hour button |
| Command plane | Several `cargo xtask` suites are aliases/placeholders and `bench`, `package`, and release verification deliberately fail | Surface unavailable profiles as unavailable with a reason. Never display a green result for a placeholder or alias |
| Release state | WP19-WP21 are in progress and release evidence is not bound to a clean candidate | Keep operational health, test health, and release readiness visually separate; the dashboard must not imply that a healthy daemon is release-ready |
| Frontend | No web application or component system exists; pnpm workspace currently contains the TypeScript SDK and Claude adapter | Add a new private frontend package with exact locked dependencies and repository-native design tokens |

## Fixed v1 architecture

```text
Browser on loopback
  |  HttpOnly session + CSRF; daemon credential never enters browser
  v
cigar-dashboard (new Rust/Axum sidecar)
  |-- verified static UI assets
  |-- status aggregator and bounded event broker
  |-- generated typed operation dispatcher
  |-- allowlisted job supervisor
  |-- dashboard-only SQLite run metadata
  |
  | typed HTTP/SSE through cigar-sdk
  +-------------------------------> existing cigard API
  |
  | argv arrays; no shell; isolated state/evidence roots
  +-------------------------------> cigar-soak / cargo xtask / matrix runners
                                      |
                                      +--> external CIGAR_EVIDENCE_DIR
```

Create these ownership boundaries:

```text
apps/dashboard/                     React/TypeScript SPA source and UI tests
crates/cigar-dashboard/             Optional Axum BFF, auth, gateway, jobs, run store
crates/cigar-soak/                  Internal deterministic installed-binary soak driver
crates/cigar-observe/               Shared content-safe observations/metric definitions only
crates/cigar-sim/                   Deterministic external services, clocks, and fault schedules
crates/cigar-testkit/               Fixtures, seeded IDs, workload builders, receipt assertions
schemas/dashboard/                  Sidecar config/API/run JSON Schemas
tests/dashboard/                    E2E fixtures, reviewed run-profile registry, security cases
deploy/compose/dashboard.yaml       Explicit optional Compose profile/override
deploy/kubernetes/dashboard/        Explicit optional Kustomize overlay; no base inclusion
docs/dashboard/                     Operator, security, testing, and troubleshooting docs
```

`cigar-dashboard` connects only to an explicitly configured CIGAR HTTP endpoint in v1. Local mode requires a loopback target and the daemon's owner-protected bearer-token file. Supporting the existing local Unix socket or Windows named pipe requires adding a reviewed transport to `cigar-sdk`; do not bypass SDK verification with an ad hoc socket client. A remote multi-user dashboard and internet-facing ingress are v2 concerns.

## Non-negotiable product and security rules

- [ ] **RULE-001 — One source of protocol truth.** Generate operation groups, methods, paths, request/response/event schemas, auth class, mutation class, revision/idempotency rules, and size limits from `spec/api/operations-v1.json`, `spec/api/operation-payloads-v1.json`, `schemas/json/api-payload-types-v1.schema.json`, `spec/errors/catalog.yaml`, and the generated Rust types. `apps/dashboard` may not contain a manually copied 45-operation registry.
- [ ] **RULE-002 — Credentials stay server-side.** Read the daemon bearer token from an absolute owner-only file into zeroized process memory. Never return it to the browser, persist it in dashboard state, render it into HTML, put it in a URL, log it, or pass it to a child test process.
- [ ] **RULE-003 — Loopback is not authentication.** Require a random one-time dashboard bootstrap secret, exchange it for an `HttpOnly; Secure` when TLS is used; otherwise loopback-only `HttpOnly; SameSite=Strict` session cookie, rotate it on restart, enforce Origin/Host checks, and require a per-session CSRF header for every non-GET sidecar request.
- [ ] **RULE-004 — Read-only by default.** Protocol mutation controls and test execution are independently disabled unless `[control] enabled = true`. Even with control enabled, protocol mutations default to daemon-native `dry_run=true`. Effect dispatch, compensation, destructive administration, backup restore, and GC execution are out of scope for the v1 generic explorer.
- [ ] **RULE-005 — No shell surface.** Test and soak runs resolve an immutable profile ID to a reviewed executable plus fixed argv vector. Do not accept executable paths, working directories, flags, environment names, command text, or shell fragments from the browser. Use `std::process::Command`/`tokio::process::Command` without `sh -c`, `bash -c`, `cmd /C`, PowerShell, or interpolation.
- [ ] **RULE-006 — Never test user data by default.** Soaks create a private temporary CIGAR state/runtime/project/evidence root and spawn an isolated daemon. Attaching a destructive or sustained workload to the status target is forbidden in v1.
- [ ] **RULE-007 — Content-safe by construction.** Default UI events and persisted run metadata contain stable codes, counts, bounded durations, digests, and opaque IDs—not source content, prompts, secrets, credentials, raw effect arguments, raw paths, or raw test output. Private diagnostic logs are an explicit local opt-in, mode `0600`, excluded from export and release evidence.
- [ ] **RULE-008 — Separate meanings of green.** Display three independent states: `Operational` (live daemon), `Verification` (latest test/soak run), and `Release evidence` (candidate-bound qualifying receipts). Never infer one from another.
- [ ] **RULE-009 — No direct persistence coupling.** Dashboard history lives in its own SQLite file. The only daemon access is through public SDK/API contracts. Do not link to `cigar-store` for reading production tables.
- [ ] **RULE-010 — Bounded everything.** Bound request bodies, decoded JSON nodes/depth, event sizes, event buffers, history rows, metrics series, graph nodes/edges, concurrent jobs, output bytes, child duration, retained artifacts, polling concurrency, and reconnect attempts. Reject overflow with a stable sidecar problem response.
- [ ] **RULE-011 — Fail closed on incompatibility.** If version/capability negotiation fails, keep static protocol documentation available but disable live calls and control actions. Show the exact public compatibility reason without exposing credentials or protected data.
- [ ] **RULE-012 — Evidence before completion.** A task box is complete only after its tests and named artifacts are read and verified. A process exit code is not sufficient when a receipt is absent, stale, partial, skipped, synthetic, or bound to another source/binary.
- [ ] **RULE-013 — Preserve the current dirty worktree.** Existing changes listed by `git status --short` belong to other active work. Add dashboard files narrowly; never clean, reset, overwrite, or reformat unrelated WP19-WP21 files.

## V1 information architecture and required UX

The persistent application shell must contain a compact top status rail visible on every route. It shows daemon state, data freshness, version/protocol, current target alias, active run, and a clear `CONTROL ENABLED` warning when applicable. Clicking it opens the full health drawer.

| Route | Required v1 content |
|---|---|
| `/` Overview | Operational/verification/release cards; eight readiness components; queue saturation; request counters; version and capabilities; active run; recent safe events; quick links |
| `/protocol` Protocol map | Generated seven-service/45-operation topology; auth/mutation/stream badges; record-flow overview; search and keyboard navigation |
| `/protocol/operations/:id` Operation explorer | Generated request form/schema, limits, examples, dry-run execution where allowed, response/problem inspector, latency, semantic ETag/cursor, copy-safe redacted export |
| `/context` Context lab | Plan -> candidates -> lanes -> manifest -> bundle -> delta visualization; token/lane bars; omission/disposition table; digest/reference links; direct-ID lookup |
| `/spaces` Spaces and handoffs | Commit/event timeline, resumable live SSE, fork/publish/checkpoint/conflict/handoff relationship graph, stale/disconnected stream state |
| `/effects` Effects and replay | Intent/authorization/attempt/receipt state machine, UNKNOWN emphasis, reconciliation/compensation links, replay completeness and diff views; read-only by default |
| `/tests` Test Center | Reviewed profiles, prerequisites/availability, expected duration and scope, launch confirmation, one active control run, cancellation, content-safe progress |
| `/tests/runs/:id` Run detail | State timeline, current phase, safe metrics, process lifecycle, evidence bindings, failure classification, artifact links constrained to the evidence root |
| `/soak` Soak monitor | Workload mix, sessions, fault schedule, throughput/error/latency/resource trends, invariants, reference-digest comparisons, ETA, cancellation semantics |
| `/evidence` Evidence browser | Read-only schema-validated receipts; source/artifact binding; status filters; explicit development-vs-release labels; sanitized export |
| `/settings` Settings/About | Effective redacted sidecar config and source, target reachability, UI preferences, retention, versions/licenses, control/security warnings |

V1 UX acceptance targets:

- [ ] Initial static shell renders within 1 second on the reference developer machine; first status classification within 2 seconds when the daemon is reachable.
- [x] Freshness is explicit: the browser labels `fresh` below 10 seconds, `stale` from 10 through 30
  seconds, and `expired observation` above 30 seconds without inventing aggregate health. The
  backend remains authoritative for `unreachable` after its bounded probe/freshness policy.
- [x] Pausing live updates freezes rendered status without dropping its classification; it closes
  the browser EventSource, suppresses automatic polling, keeps one bounded manual refresh available,
  and immediately resynchronizes on resume. Hidden tabs suspend the EventSource/polling and perform
  one bounded refresh when visible again. Browser lifecycle/E2E verification remains in DASH-040.
- [ ] Every chart has a table/text equivalent, every status uses icon/text as well as color, and no essential workflow requires pointer hover.
- [ ] Full keyboard operation, visible focus, reduced-motion support, 200% zoom, 320 px responsive layout, and WCAG 2.2 AA contrast are release gates.
- [ ] Use a calm dark/light system theme, dense but readable cards, a monospace data face, restrained semantic color, and no decorative animation that competes with status or test progress.
- [ ] Large JSON/CBOR, graph, event, and metrics views virtualize or paginate. Default caps: 1,000 rows, 500 graph nodes, 1,000 edges, 10,000 retained safe events per run; make truncation visible.

## Execution order

Execute packets in numeric order. A packet may begin only when its dependencies and exit gate pass.

1. DASH-000 through DASH-003: freeze contracts and scaffold without changing daemon behavior.
2. DASH-010 through DASH-014: secure sidecar foundation, status gateway, persistence, and event model.
3. DASH-020 through DASH-025: application shell, overview, protocol explorer, and visualizers.
4. DASH-030 through DASH-035: allowlisted test execution and deterministic soak harness.
5. DASH-040 through DASH-045: evidence, packaging, deployment, docs, and full qualification.

Do not begin long-duration soak qualification until the isolated driver, accelerated fault tests, leak trend analysis, cancellation, and receipt verifier all pass.

---

## Phase 0 — Freeze the dashboard contract

### DASH-000 — Record the implementation baseline and ADR

Dependencies: none
Owner: architecture
Output: `docs/dashboard/architecture.md`, `docs/dashboard/adr/0001-local-sidecar.md`

- [ ] Re-run `git status --short`, record the exact baseline commit/tree and existing unrelated changes in the ADR, and state that this packet does not qualify or modify WP19-WP22 evidence.
- [ ] Document the process/data-flow diagram above, trust boundaries, local-only v1 scope, sidecar/daemon/test-runner identities, storage roots, credential flow, and shutdown ordering.
- [ ] Write an explicit decision matrix rejecting: assets hosted by `cigard`, direct browser-to-daemon calls, direct daemon DB reads, Electron/native webviews, arbitrary terminal execution, production ingress, and dashboard-specific protocol semantics.
- [ ] Define support targets to match the eventual CIGAR binary matrix where possible, but label dashboard platform claims separately until native UI/E2E receipts exist.
- [ ] Define user personas: local developer (read/control), test operator (control), and observer (read-only). Multi-user RBAC is a v2 non-goal.

Done when maintainers can determine which process owns every request, credential, state file, event, and child process without reading implementation code.

### DASH-001 — Specify sidecar configuration and optionality

Dependencies: DASH-000
Owner: sidecar
Output: `schemas/dashboard/dashboard-config-v1.schema.json`, `deploy/dashboard/cigar-dashboard.example.toml`

- [ ] Define strict TOML `DashboardConfigV1` with `deny_unknown_fields` and these sections:
  - `server`: loopback `listen`, absolute `runtime_directory`, absolute verified UI asset root, request/body/event bounds, shutdown deadline;
  - `target`: explicit loopback HTTP base URL, absolute daemon token file, connect/request deadlines, polling intervals;
  - `control`: `enabled=false`, workspace root, reviewed profile registry, absolute evidence/state/sandbox roots, concurrency/retention bounds;
  - `history`: separate SQLite path, max runs/events/age/bytes;
  - `display`: target alias only—no secrets or raw endpoint credentials.
- [ ] Reject non-loopback binds/targets, URL userinfo/query/fragment, symlinks, relative paths, overlapping daemon/dashboard state, world/group-writable secret/state roots, zero/excessive limits, duplicate directories after canonicalization, and evidence roots inside a release candidate in control mode.
- [ ] Add `--config /absolute/path/dashboard.toml`, `--check-config`, and `--print-effective-config`; the latter redacts credentials and emits value source metadata.
- [ ] Optionality proof: compare `cigard --help`, `cigar --help`, listeners, environment reads, config acceptance, dependency graph, and default build outputs before/after the dashboard addition.
- [ ] Keep `cigar-dashboard` outside Cargo `default-members`; add `apps/dashboard` to pnpm workspace without making root install/build scripts run it implicitly.

Negative tests must cover non-loopback `0.0.0.0`, DNS names resolving to loopback, IPv4-mapped IPv6, token/state hard links, symlink swaps, path traversal, asset/state overlap, duplicate TOML keys, unknown fields, and integer overflow.

### DASH-002 — Define sidecar API and machine schemas

Dependencies: DASH-001
Owner: protocol/UI boundary
Output: `schemas/dashboard/*.schema.json`, `crates/cigar-dashboard/src/model.rs`

- [ ] Define closed versioned records:
  - `cigar.dashboard-bootstrap.v1`;
  - `cigar.dashboard-status.v1`;
  - `cigar.dashboard-safe-event.v1`;
  - `cigar.dashboard-run-profile.v1`;
  - `cigar.dashboard-run.v1`;
  - `cigar.dashboard-run-event.v1`;
  - `cigar.dashboard-protocol-call.v1`;
  - `cigar.soak-plan.v1` and `cigar.soak-result.v1`.
- [ ] Use RFC 7807 `application/problem+json` for sidecar failures with a dashboard-specific closed code catalog. Keep CIGAR problems nested as typed upstream outcomes rather than rewriting their codes.
- [ ] Freeze initial BFF routes:

  | Method/path | Semantics |
  |---|---|
  | `POST /api/v1/session:exchange` | One-time bootstrap-secret exchange; sets session and returns CSRF token |
  | `POST /api/v1/session:logout` | Revokes current session |
  | `GET /api/v1/bootstrap` | Redacted effective capabilities, feature gates, versions, limits |
  | `GET /api/v1/status` | Latest aggregate status plus freshness and upstream latency |
  | `GET /api/v1/events` | Resumable sidecar SSE for status/run/safe protocol events |
  | `GET /api/v1/protocol` | Generated services/operations/errors/visual metadata |
  | `POST /api/v1/protocol/calls` | Generated allowlisted typed operation dispatch |
  | `GET /api/v1/run-profiles` | Reviewed profiles and availability reasons |
  | `GET /api/v1/runs` | Bounded cursor-paginated run history |
  | `POST /api/v1/runs` | Start one reviewed profile by ID |
  | `GET /api/v1/runs/{run_id}` | One bounded run and evidence summary |
  | `POST /api/v1/runs/{run_id}:cancel` | Idempotent bounded cancellation |
  | `GET /api/v1/evidence` | Bounded schema-validated evidence index |
  | `GET /api/v1/evidence/{evidence_id}` | Sanitized receipt only; never arbitrary file serving |

- [ ] Require strict JSON, unique keys, exact media types, maximum depth/node/string/item sizes, canonical run IDs, cursor MACs, and no unknown fields.
- [ ] Generate TypeScript API models from the schemas. Prohibit handwritten frontend copies and prohibit importing Node-only `@cigar/sdk` transport code into the browser bundle.
- [ ] Add schema fixtures for minimal, maximal, unknown-field, duplicate-key, boundary, overflow, and hostile Unicode cases.

### DASH-003 — Scaffold the optional packages and build graph

Dependencies: DASH-001, DASH-002
Owner: build
Output: `crates/cigar-dashboard`, `crates/cigar-soak`, `apps/dashboard`

- [ ] Add `cigar-dashboard` and `cigar-soak` workspace members with `publish = false`, workspace lints, `unsafe_code = "forbid"`, and no default-member change.
- [ ] Make `cigar-dashboard` depend on `cigar-sdk` with `default-features = false`, Axum, Tokio, Serde, Rusqlite, Rustls, SHA-256, zeroize, and only narrowly required middleware.
- [ ] Create private `@cigar/dashboard` with TypeScript strict mode, React, Vite, router/query primitives, accessible test tools, and no runtime dependency on the Node-only SDK transport. Pin exact versions in `pnpm-lock.yaml`; retain workspace age/trust policy.
- [ ] Make frontend builds deterministic: fixed locale/timezone, content-hashed JS/CSS names, no build timestamp/random ID/absolute path, normalized source maps, and a canonical `asset-manifest.v1.json` with SHA-256 and byte size for every served file.
- [ ] Do not make Cargo invoke pnpm or the network. Development and packaging commands build the web application explicitly, then point the sidecar/package at the resulting verified asset directory.
- [ ] Add `cargo xtask dashboard build|test|check` only after the root command parser supports strict subcommand/flag rejection. Until then use documented explicit Cargo/pnpm commands without returning placeholder success.
- [ ] Add architecture checks preventing dependencies from `cigar-protocol`, semantic crates, or `cigar-daemon` to either dashboard package.

Exit gate:

```sh
cargo check --locked -p cigar-dashboard -p cigar-soak
pnpm --filter @cigar/dashboard typecheck
pnpm --filter @cigar/dashboard build
cargo xtask architecture-check
```

---

## Phase 1 — Build the secure sidecar and live status plane

### DASH-010 — Implement local session security and static serving

Dependencies: DASH-003
Owner: sidecar/security

- [ ] On first start create a 256-bit bootstrap secret from the OS CSPRNG, write it to a create-new owner-only file in `runtime_directory`, and print a one-time URL whose secret is in the fragment, never the query. The SPA exchanges it once, then clears browser history and memory.
- [ ] Store only a keyed digest of bootstrap/session secrets; use constant-time verification, short exchange TTL, idle/absolute session TTLs, rotation on restart, bounded session count, and zeroization.
- [ ] Bind only the configured numeric loopback address. Reject unapproved `Host`, `Origin`, `Forwarded`, and `X-Forwarded-*` values; do not trust proxies in v1.
- [ ] Set CSP with `default-src 'self'`, no inline script/style/eval, `connect-src 'self'`, `img-src 'self' data:`, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`; also set `nosniff`, strict referrer policy, permissions policy, COOP, and CORP.
- [ ] Verify the asset manifest and every file digest before accepting traffic. Serve only manifest entries using fixed content types; no directory listing, dotfiles, source maps in production mode, path decoding ambiguity, range amplification, or fallback for `/api/*`.
- [ ] SPA fallback returns only verified `index.html` for non-API GET/HEAD routes with HTML accept headers. Immutable hashed assets receive long caching; HTML/manifest/API responses receive `no-store`.
- [ ] Implement per-route body limits, concurrency limits, timeouts, structured content-safe access events, and graceful shutdown that first closes new sessions/actions, then SSE, jobs, store, and telemetry.

Security tests: DNS rebinding Host, CSRF form/fetch, malicious Origin/null Origin, cookie fixation/replay, bootstrap reuse, timing-safe bad secrets, encoded traversal, MIME confusion, HTML fallback over API, cache poisoning, compression bomb, slow body, SSE exhaustion, and secret-canary scan of all responses/logs/history.

### DASH-011 — Implement the verified daemon gateway

Dependencies: DASH-010
Owner: sidecar/gateway

- [ ] Build one `RemoteClientBuilder` from `cigar-sdk`; explicitly allow only configured cleartext loopback, disable proxies/redirects through the SDK, load the daemon token from the protected file, and negotiate compatibility before declaring connected.
- [ ] Re-open/re-read a rotated token only through a bounded watcher that revalidates owner, type, link count, size, and permissions. Preserve the last connection as unauthenticated until a new compatibility check passes.
- [ ] Implement status probes with independent deadlines and bounded jitter:
  - liveness/readiness every 2 seconds while visible/active;
  - diagnostics and metrics every 5 seconds;
  - version/capabilities/configuration on connect and every 60 seconds;
  - immediate refresh after reconnect or completed test run.
- [ ] Derive one closed aggregate state with this precedence: `incompatible` > `unreachable` > `unhealthy` > `degraded` > `starting` > `healthy`. Include per-source observation time, duration, consecutive failure count, and stale flag.
- [ ] Treat readiness HTTP 503 with a valid typed response as a successful unhealthy observation, not a transport outage. Never replace the last valid report with malformed/newer input.
- [ ] Enforce single-flight probes, a global upstream concurrency bound, exponential reconnect capped at 30 seconds, and cancellation when no dashboard sessions remain if background monitoring is disabled.
- [ ] Parse OpenMetrics using a bounded parser. Allow only `cigar_*` families and closed label sets; reject duplicate samples, non-finite values, invalid escaping, excessive series, or high-cardinality labels.
- [ ] Add a compatibility fixture matrix for reachable/healthy, gate closed, one degraded/unhealthy component, bad token, malformed response, version mismatch, response timeout, daemon restart, token rotation, and stale status.

### DASH-012 — Expand content-safe instrumentation needed by v1 views

Dependencies: DASH-011
Owner: observability
Output: additions in `crates/cigar-observe` and daemon telemetry; no dashboard-only daemon semantics

- [ ] Move reusable observation names/label enums into `cigar-observe`; keep storage-free and content-safe.
- [ ] Add the minimum bounded metrics required for useful v1 testing: API count/duration/error by closed operation/result, active requests/streams and backpressure, process uptime/RSS/CPU/open-FD-or-handle/task count, worker queue depth/capacity/age/rejections/heartbeat, compile count/duration/candidates/selected/lane tokens, index lag, cache hit/miss, effect states/UNKNOWN age/reconciliation, replay completeness, and ingest atoms/bytes/failures.
- [ ] Follow PRD §23: high-cardinality IDs belong only in traces, never metric labels. Prohibit tenant, user, source, path, prompt, record ID, digest, URL, effect argument, or arbitrary error text as labels.
- [ ] Add HELP/TYPE/UNIT lines, stable units, monotonic counters, deterministic output ordering, and `# EOF` to OpenMetrics.
- [ ] Add process probes per supported OS behind narrow safe abstractions. Missing platform capability produces an explicit unsupported observation rather than a zero value.
- [ ] Extend diagnostics only when a value cannot be represented safely in OpenMetrics and is needed for an operator decision. Keep response ordering and schema generation deterministic.
- [ ] Extend Prometheus rules for request errors, stream backpressure, UNKNOWN age, worker loss, memory/FD trend, and index lag using the new exact names.

Done when dashboard charts need no scraping of logs or private storage and telemetry tests prove bounded label cardinality plus canary absence.

### DASH-013 — Add dashboard persistence and safe event brokerage

Dependencies: DASH-010, DASH-011
Owner: sidecar/storage

- [x] Create a dashboard-only SQLite database with append-only migrations and tables for runs, run state transitions, safe events, evidence descriptors, and preferences. Never store daemon credentials or raw protocol payloads by default.
- [x] Open with WAL, foreign keys, busy timeout, bounded cache, `synchronous=FULL` for run transitions, owner-only file/parent permissions, no symlinks/hard links, and a single writer task.
- [ ] Make run state transitions closed and monotonic: `queued -> preparing -> running -> cancelling -> {cancelled|passed|failed|timed_out|lost}`; allow `preparing|running|cancelling -> lost` only after process recovery proves no live child.
- [ ] Generate stable UUIDv7 run/event IDs; order by committed sequence, not wall-clock alone. Persist state before publishing its SSE event.
- [x] Implement bounded resume-aware sidecar SSE. Per-subscriber overflow closes that subscriber with a typed resync event; it never blocks status or job writers.
- [ ] On restart reconcile persisted active runs against PID plus start-time/process identity. Never signal a reused PID. Mark unprovable outcomes `lost`, preserve evidence, and require a new run.
- [ ] Apply retention only to terminal runs, oldest first, with transactionally updated byte/count ledgers. Evidence files are not deleted unless they are inside the configured dashboard-owned evidence root and unreferenced.
- [ ] Add backup/corruption/startup recovery tests and prove the dashboard cannot damage or lock daemon state.

Implemented foundation: schema v1-to-v2 migration, strict run decoding, queued/preparing/running/
terminal transition tests, restart reload with run-scoped safe events, authenticated bounded
`GET /api/v1/runs`, `GET /api/v1/runs/{run_id}`, `GET /api/v1/evidence`, and
`GET /api/v1/evidence/{evidence_id}`, plus independent UI verification/release projections. Keep the
remaining boxes open until PID/start-time recovery, transition-to-SSE coordination, filesystem
receipt ingestion/verification, byte ledgers, backup failure cleanup, and disk-full behavior are
proven.
Startup now also rejects failed SQLite quick-checks and foreign-key damage; retention tests prove
active runs are never evicted and evidence-referenced terminal runs remain protected. The internal
backup path is serialized through the single writer, refuses relative/existing/symlink destinations
and permissive parents, emits a standalone `0600` snapshot, verifies schema/integrity, syncs it, and
passes reopen/readback tests. Restore remains intentionally outside the generic explorer; keep this
box open for active-process recovery, transactional byte ledgers, disk-full behavior, and the final
no-daemon-storage/locking integration proof.

### DASH-014 — Generate a typed dynamic operation dispatcher

Dependencies: DASH-002, DASH-011
Owner: generator/gateway

- [ ] Extend the existing API generator to emit a dashboard Rust dispatch match and frontend operation metadata from the same 45-operation catalogs.
- [ ] For each operation, deserialize strict JSON into its generated request type, validate the typed payload, reconcile path fields, apply SDK `CallOptions`, call the typed SDK method, and serialize a bounded typed response. Do not forward arbitrary upstream paths.
- [ ] Generate policy metadata: `read`, `safe_mutation`, `dangerous_mutation`, `stream`; v1 explorer permits all reads and explicitly reviewed dry-run-safe mutations. Dangerous mutations remain documentation-only.
- [ ] Enforce daemon-native idempotency and expected-revision types. Generate idempotency keys server-side when requested; display the opaque key only in the current response so a test operator can intentionally reuse it.
- [ ] Require a two-step confirmation token bound to session, operation ID, canonical request digest, dry-run flag, and a 60-second expiry before any live mutation.
- [ ] Return both decoded typed JSON and content-safe envelope metadata: operation ID, duration, response byte count, ETag, cursor presence, trace/correlation ID, and response digest. Raw CBOR download is opt-in and memory-only.
- [ ] Special-case `subscribeSpaceEvents` as a bounded verified SSE proxy preserving upstream event IDs and cancellation; never convert cursor and event IDs.
- [ ] Generator drift checks must fail if any operation/schema/auth/mutation/stream rule changes without updated generated files and fixtures.

Exit gate: all 45 operations have exactly one generated dispatcher classification; every generated request/response fixture round-trips; deliberately mismatched path/payload IDs, missing idempotency/revision, dangerous operation, malformed CBOR, and oversized event fail closed.

---

## Phase 2 — Build the dashboard experience

### DASH-020 — Implement the design system and application shell

Dependencies: DASH-003, DASH-010, DASH-013
Owner: frontend

- [ ] Define semantic CSS variables for canvas/surface/text/border/focus and healthy/degraded/unhealthy/info/control states in light/dark modes. Never encode meaning with a raw palette token.
- [ ] Build accessible primitives: app shell, status rail, side navigation, command/search palette, card, disclosure, data table, tabs, timeline, badge, toast/live region, dialog, confirm panel, skeleton, empty/error/stale states, JSON tree, code block, sparkline, and graph canvas.
- [ ] Use native SVG/Canvas for protocol graphs with a text/table fallback. Do not add a heavyweight diagram editor in v1.
- [ ] Establish typography, 4/8 px spacing rhythm, density modes, responsive breakpoints, reduced motion, focus ring, z-index layers, and deterministic chart colors.
- [ ] Add route-level error boundaries and distinguish unauthenticated, disconnected, incompatible, stale, permission-disabled, empty, loading, and internal-failure states.
- [x] Persist only non-sensitive display preferences in local storage. The prototype stores only
  closed theme, density, and motion values under versioned keys; unknown values fall back to
  `system`, `comfortable`, and `system`. It does not persist protocol requests/responses, IDs,
  endpoints, CSRF values, run input, or live-update state.
- [ ] Add component stories/fixtures or an equivalent isolated visual harness for every semantic state and viewport.

Implemented prototype foundation: semantic light/dark tokens, explicit System/Light/Dark override,
comfortable/compact density, System/Standard/Reduced motion with OS-media-query fallback, visible
focus, reduced-motion enforcement, responsive breakpoints, and an Escape-closeable native display
menu. Keep the broader boxes open until the complete primitive set, deterministic chart palette,
route error boundaries, visual fixtures, and browser accessibility/zoom/viewport gates exist.

### DASH-021 — Build persistent status and Overview

Dependencies: DASH-012, DASH-020
Owner: frontend/status

- [x] Render the persistent status rail from one aggregate status query plus sidecar SSE
  invalidations; freshness presentation is separate and no component invents daemon health.
- [ ] Overview cards:
  - operational state/freshness/latency;
  - daemon version, source revision, protocol range, API line, mode, and enabled profiles;
  - all eight readiness components with public reason code/remediation link;
  - nine worker queues with depth/capacity/oldest age/rejections/heartbeat;
  - request/stream rate, error rate, latency, memory/FD/tasks, index lag, UNKNOWN effect age;
  - latest verification run and release-evidence state as separate cards.
- [ ] Keep a bounded client-side rolling window for charts; use monotonic-counter deltas, detect counter reset on daemon restart, and never join points across source revision/process identity changes.
- [ ] Add a health drawer with exact observation times, stale sources, upstream problem code, reconnect action, redacted effective target, and links to relevant runbooks under `docs/operations`/`docs/troubleshooting`.
- [ ] Make warning thresholds derive from reviewed configuration/Prometheus rule constants rather than UI-only magic numbers.
- [ ] Test healthy, degraded, unhealthy, starting, stale, unreachable, incompatible, control-enabled, counter reset, queue saturation, and partial-metric states visually and semantically.

Implemented prototype foundation: the health disclosure shows exact aggregate/configuration/
diagnostics timestamps, freshness, consecutive failures, the redacted alias, deployment mode,
enabled public transports, reviewed request/timeout limits, stale sources, component states/reason
codes/latencies, and a bounded reconnect action. Keep the drawer box open until typed upstream
problem codes and reviewed runbook links exist; keep the visual-state box open until browser fixture
and accessibility coverage proves the complete matrix.

### DASH-022 — Build the generated Protocol Map and operation explorer

Dependencies: DASH-014, DASH-020
Owner: frontend/protocol

- [ ] Render the seven service groups and all 45 operations from generated metadata with full-text search, filters for auth/mutation/stream, request/response/event type links, limits, error mappings, and curl-free SDK/CLI examples that never include credentials.
- [ ] Render JSON-Schema-driven request forms with enum/select, integer bounds, arrays, discriminated unions, record IDs/digests, timestamps, and raw JSON expert mode. Form and raw modes share the same validator and preserve no secrets after navigation.
- [ ] Display dry-run/live state unmistakably. Live safe mutation requires the generated confirmation handshake; dangerous mutations show why they are unavailable.
- [ ] Response inspector tabs: typed tree, envelope, references, validation, and raw CBOR metadata. Link recognized opaque IDs/digests without treating arbitrary strings as resources.
- [ ] Problem inspector shows stable CIGAR code, retry class, remediation, correlation ID, HTTP status, and operation phase. Do not render upstream arbitrary HTML/Markdown.
- [ ] Add an in-memory recent-call list capped at 50 and cleared on logout/reload. A sanitized export contains schemas, operation IDs, timing, codes, and digests only.
- [ ] Add deterministic examples from existing conformance/demo fixtures; label examples as fixtures, never as current daemon state.

### DASH-023 — Build context/compiler visualizations

Dependencies: DASH-022
Owner: frontend/context

- [ ] Provide a guided lab for discover -> ingest -> plan -> compile -> explain -> materialize -> delta -> revalidate, using only generated allowed operations.
- [ ] Visualize `ContextPlan`, `SelectionManifest`, `ContextBundle`, and `ContextDelta` as linked immutable records with digest verification state.
- [ ] Show the five standard lanes (`rules`, `task`, `evidence`, `history`, `tools`), selected block count/tokens, physical/cache token comparison, budget utilization, conflicts/staleness, provenance count, transform/representation, and omission/disposition reasons.
- [ ] Show bundle-to-bundle delta additions/removals/resulting tokens and verify the target using existing SDK verification results; never compute a competing semantic digest in JavaScript.
- [ ] Support direct ID/digest lookup because the v1 API does not expose global list operations. Recent resources are session-local results, not a database inventory.
- [ ] Redact block content by default. Explicit content reveal is local-control only, time-limited, excluded for protected classifications, never persisted, and cleared on blur/navigation/logout.
- [ ] Bound all graphs/tables and provide a deterministic collapsed summary for over-limit objects.

### DASH-024 — Build spaces, handoffs, effects, and replay views

Dependencies: DASH-022
Owner: frontend/protocol flows

- [ ] Spaces: render commit parents, ordered coordination events, overlay/focus branch, checkpoint, conflict, invalidation, and publish relationships. Subscribe using verified SSE and expose connected/reconnecting/stale/resumed state.
- [ ] Handoffs: render capsule -> preview -> acceptance -> result delta -> merge plus issuer/recipient scope and revocation state using opaque identifiers and public metadata only.
- [ ] Effects: render durable intent -> authorization -> attempt -> receipt/journal states with legal transitions from protocol types. Make `UNKNOWN` visually dominant and show safe inspect/reconcile guidance; never offer automatic dispatch retries.
- [ ] Replay: render request, completeness dependencies, observational execution, and live comparison diff. Distinguish observation from live side effects and require the existing live-authorization contract.
- [ ] Generate state-machine visualization metadata from Rust enums/transition validators or a checked manifest. Do not hand-copy legal transitions into frontend source.
- [ ] Link related records only when an explicit typed field proves the relationship. Do not infer from display text, timestamps, or prefix similarity.
- [ ] Add empty/direct-ID entry states and explain that the frozen API has no global list endpoint instead of querying storage behind the API.

### DASH-025 — Add global usability features

Dependencies: DASH-021 through DASH-024
Owner: frontend

- [ ] Command palette searches routes, operations, run profiles, public error codes, and loaded opaque IDs; actions respect read/control gates.
- [ ] Deep links encode only route and opaque resource ID. Never encode request bodies, credentials, CSRF, source paths, or protected content.
- [ ] Add consistent `Copy ID`, `Copy digest`, `Open related`, `View schema`, `View runbook`, and `Export sanitized` actions with explicit success/error feedback.
- [ ] Add in-product glossary for atom, contract, plan, lane, manifest, bundle, delta, space, handoff, effect, UNKNOWN, replay, and evidence binding.
- [ ] Add time range, auto-refresh, pause, and timezone controls; preserve exact UTC timestamps in detail views.
- [ ] Add a first-run tour that uses fixture data and never makes a live mutation.

---

## Phase 3 — Add reviewed test execution and soak testing

### DASH-030 — Define the reviewed run-profile registry

Dependencies: DASH-002, DASH-013
Owner: quality/security
Output: `tests/dashboard/run-profiles-v1.json` and schema

- [ ] Each profile contains: stable ID/title/description, kind, exact executable selector, fixed argv, working-directory class, availability probes, platform set, control requirement, expected/max duration, resource ceilings, network mode, concurrency group, cancellation grace, receipt schema/category, and documentation link.
- [ ] Initial profile groups:
  - fast: format/generation, unit, vectors, conformance smoke;
  - matrices: compatibility, security, chaos, migration, installation where locally applicable;
  - demos/benchmarks: only commands that currently produce honest receipts;
  - soak: 2-minute smoke, 15-minute developer, 1-hour extended, 24-hour release candidate.
- [ ] Profile registry commands must reflect real implemented commands. Mark `bench`, `package`, release verification, or aliased xtask suites unavailable until their command-plane owners are complete.
- [ ] Bind the registry to a SHA-256 digest and source revision. Sidecar startup rejects duplicate IDs, unknown fields, unbounded duration/resources, path escape, shell programs, environment passthrough, writable source checkout for release profiles, missing receipt schema, and incompatible concurrency groups.
- [ ] Availability is a structured reason such as `available`, `control_disabled`, `source_checkout_required`, `tool_missing`, `platform_unsupported`, `dependency_cache_missing`, `credential_missing`, or `command_not_implemented`.
- [ ] The browser can choose only profile ID and an enumerated safe duration/workload preset already present in the signed registry. It cannot override argv or environment.

### DASH-031 — Implement the cross-platform job supervisor

Dependencies: DASH-030
Owner: sidecar/process

- [ ] Resolve tools from configured absolute paths or a startup-captured allowlisted toolchain manifest; do not use a browser-provided path or mutable PATH lookup after startup.
- [ ] Spawn with fixed argv, sanitized environment allowlist, explicit private working/sandbox/evidence directories, null stdin, bounded stdout/stderr collectors, and `kill_on_drop`.
- [ ] Never pass the daemon token. Generate a distinct least-privilege credential only for an isolated soak daemon when required.
- [ ] Unix: create a dedicated process group/session, send TERM to the group, wait bounded grace, then KILL, and reap every child. Windows: use a Job Object with kill-on-close and verify PID creation time before control.
- [ ] Persist `preparing` before filesystem/process work and `running` with PID/process identity before publishing. Capture executable SHA-256, argv digest, registry digest, source descriptor, tool versions, start/end monotonic and UTC times, and sanitized environment digest.
- [ ] Stream only structured safe progress records from a dedicated framed FD/file. Hash/count ordinary stdout/stderr; do not show them in the browser. Cap private debug logs and require explicit CLI-side opt-in.
- [ ] Implement concurrency groups: at most one source-mutating/cache-heavy run, one soak, and a small bounded number of read-only checks. Queue order is FIFO with cancellation.
- [ ] Implement timeout, user cancellation, sidecar shutdown, crash recovery, child escape, disk-full, output flood, malformed progress, receipt missing, and receipt mismatch as distinct terminal classifications.
- [ ] A zero exit with absent/invalid/stale receipt is `failed`, not `passed`. A nonzero exit with a valid failed receipt remains `failed` with receipt details.

Process security tests must attempt shell metacharacters, executable substitution, PATH swap, symlink race, environment injection (`RUSTC_WRAPPER`, loaders, proxies, credentials), forked child escape, PID reuse, output flood, progress-frame bomb, cancel race, disk exhaustion, and sidecar kill/restart.

### DASH-032 — Build deterministic simulation and workload primitives

Dependencies: DASH-030
Owner: testkit/sim

- [ ] Extend `cigar-testkit` with fixed clock, UUIDv7/nonce/random seeds, synthetic tenant/project/task builders, deterministic content generator, canonical workload plan, secret canaries, reference roots, and receipt assertions.
- [ ] Extend `cigar-sim` with deterministic filesystem/Git sources, fake external effect service, object/key/index fault adapters, latency/error schedule, connection drop/restart controls, and a reference event/effect model.
- [ ] Every fault is named, seeded, scheduled by logical operation count or monotonic offset, and recorded in the plan/result. No unrecorded randomness or wall-clock dependence.
- [ ] Synthetic content covers overlapping symbols, Unicode/confusables, injection text, secrets, invalidations, stale/corrected records, handoff conflicts, idempotent/non-idempotent effects, and replay dependencies without containing real repository/user data.
- [ ] Add accelerated virtual-time tests for every workload stage and fault. Process-kill/storage durability cases remain real-process tests and cannot be replaced by virtual time.
- [ ] Prove canaries never appear in safe events, metrics, dashboard APIs, run DB, or exported evidence.

### DASH-033 — Implement `cigar-soak`

Dependencies: DASH-031, DASH-032
Owner: soak/quality

- [ ] Implement strict commands:

  ```text
  cigar-soak plan --profile <reviewed-id> --out <plan.json>
  cigar-soak run --plan <plan.json> --evidence-dir <absolute-dir>
  cigar-soak verify --plan <plan.json> --result <soak-result.v1.json>
  ```

- [ ] `run` creates an isolated sandbox, writes strict daemon policy/authority/source/effect registries and owner-only credentials, starts the exact configured `cigard` binary on ephemeral loopback ports, performs compatibility/readiness checks, drives it through `cigar-sdk`, then performs ordered shutdown and post-run verification.
- [ ] Implement the PRD mixed workload: discovery/ingestion, compile, delta, context switching, spaces/checkpoints/events, handoff preview/accept/result/merge/revoke, effect prepare/authorize/dispatch/reconcile/compensation, observational replay, backup verification, and GC planning/execution in the isolated state.
- [ ] Session schedule covers 1, 2, 4, 8, 16, 32, and 64 concurrent sessions according to profile duration; workload weights and seeds are recorded.
- [ ] Inject bounded dependency latency/unavailability, stream disconnect/resume, daemon graceful restart, selected process kill/recovery, index lag, object/key failure, and effect ambiguous outcome according to the plan. Never inject an unmodeled destructive host fault.
- [ ] Sample at bounded intervals: completed/failed operations by class, latency histogram, RSS/CPU/FD-or-handle/tasks, queues, locks, WAL/database/blob sizes, index lag, active streams, UNKNOWN effects/age, leases, reference root/digest, and canary count.
- [ ] Evaluate pass criteria from PRD §28.3: no memory/descriptor/task trend after stabilization, deadlock, lost commit, stuck lease, unbounded queue, unexplained UNKNOWN, unauthorized output/canary, or reference digest drift.
- [ ] Use a reviewed trend method: exclude warm-up, require minimum samples, calculate robust slope plus confidence bound, compare absolute and percentage ceilings, and record raw bounded samples. Do not call two endpoints a trend.
- [ ] On cancellation, stop issuing new work, classify in-flight effects conservatively, reconcile, flush receipt, terminate isolated daemon in order, and emit `cancelled`; cancellation is never a passing result.
- [ ] `verify` recomputes digests and thresholds offline, validates source/binary/plan/profile binding, rejects missing phases/sessions/faults/samples, overlapping time, clock reversal, non-finite values, synthetic metrics, skipped checks, and status inconsistent with failures.

Required profile minimums:

| Profile | Duration | Purpose | Qualification claim |
|---|---:|---|---|
| `soak-smoke` | 120 s | Harness/receipt/E2E smoke | None |
| `soak-developer` | 900 s | UI and common mixed-flow feedback | None |
| `soak-extended` | 3,600 s | Leak/fault signal before nightly | Development only |
| `soak-rc-24h` | 86,400 s | Exact installed candidate gate | Release only when all source/artifact/platform bindings pass |

### DASH-034 — Build Test Center and Soak Monitor

Dependencies: DASH-031, DASH-033, DASH-020
Owner: frontend/quality

- [ ] Test Center cards show profile availability, exact scope, expected/max duration, network/service prerequisites, resource impact, evidence category, last result, and why a profile is disabled.
- [ ] Launch confirmation shows target isolation, source/binary revision, evidence directory, profile/registry digest, duration, faults, and cancellation behavior. Require the user to type the profile ID for the 24-hour run.
- [ ] Active run view consumes safe run SSE, survives reload/resume, and shows stage timeline, elapsed/remaining, current session band, operation counts/rates, failures, resource charts, queue/UNKNOWN state, fault annotations, and invariant table.
- [ ] Cancellation is idempotent and clearly states `cancelling` until the process group and isolated daemon are reaped and a final receipt exists.
- [ ] Results distinguish harness failure, product invariant failure, threshold failure, infrastructure failure, timeout, cancellation, lost supervisor state, and invalid evidence.
- [ ] Never offer `retry` for effect dispatch or a failed release soak as if it continued accumulated duration. A new run gets a new plan/run ID.
- [ ] Provide sanitized receipt download only after server-side schema verification and root confinement.

### DASH-035 — Add evidence ingestion and release-readiness separation

Dependencies: DASH-013, DASH-031, DASH-033
Owner: evidence

- [ ] Index only configured allowlisted receipt schemas under the external evidence root; use descriptor-relative traversal where supported, reject symlinks/hard links/path escape/case collisions, and cap files/count/total bytes.
- [ ] Validate schema, canonical JSON, attachment digest/size, source commit/tree/clean flag, source archive, artifact ID/SHA, tool/policy/profile digest, platform, duration, network mode, and status before display.
- [ ] Classify each receipt `sample`, `development`, `candidate-bound`, `installed-artifact`, or `release-qualifying`; classification is derived from evidence, never chosen in UI.
- [ ] Read `docs/execution/work-packets.yaml`, `packaging/qualification-gaps.v1.json`, and `packaging/release-requirements.v1.json` only when an explicit workspace evidence source is configured. Treat them as read-only and show their observed revision/freshness.
- [ ] Release readiness remains `not qualified` while the current dirty/unbound WP19-WP21 blockers exist, regardless of daemon/test health.
- [ ] Sanitized export includes receipt metadata and digests only. Never bundle raw logs, test sandboxes, source content, token files, daemon state, or private evidence by directory recursion.

---

## Phase 4 — Integrate, package, and qualify

### DASH-040 — Add backend, frontend, and contract test suites

Dependencies: DASH-020 through DASH-025 and DASH-030 through DASH-035
Owner: quality

- [ ] Rust unit/property tests: config, sessions/CSRF, static assets, strict JSON, status precedence/freshness, metric parser, generated dispatcher, run state machine, cursor MACs, retention, evidence confinement, and process supervision.
- [ ] Frontend unit/component tests: query state, formatters, schema forms, status rail, charts/tables, graph caps, confirmation, run timeline, error states, keyboard behavior, and redaction.
- [ ] Contract differential: every dashboard schema fixture decodes equivalently in Rust and TypeScript; generated protocol metadata matches all 45 operations exactly.
- [ ] Integration tests use a deterministic fake upstream for all status/auth/malformed/timeout/restart cases and an actual local `cigard` for typed compatibility, status, safe calls, and resumable SSE.
- [ ] E2E tests use Playwright on Chromium, Firefox, and WebKit for bootstrap/login/logout, reconnect, overview, explorer read/dry-run, live event resume, launch/cancel run, reload active run, receipt view, and control-disabled states.
- [ ] Accessibility tests combine automated axe scans with keyboard-only scripted flows, focus-order assertions, live-region checks, reduced motion, forced colors, zoom, and chart table alternatives.
- [ ] Visual regression covers light/dark, 320/768/1440 widths, healthy/degraded/unhealthy/stale/incompatible, empty/loading/error, active soak, failed run, and dense capped data.
- [ ] Security suite includes all negative cases from DASH-010/DASH-031 plus dependency audit, secret scan of built assets, CSP verification, and source-map/package-content inspection.

### DASH-041 — Prove optionality, performance, and resource bounds

Dependencies: DASH-040
Owner: performance/quality

- [ ] Start `cigard` without dashboard installed/configured and prove identical listeners, routes, environment/config reads, steady-state memory within noise, and no dashboard files/processes.
- [ ] Start/stop/crash the dashboard and prove daemon requests, workers, readiness, shutdown, storage roots, and effect truth continue independently.
- [ ] Dashboard idle targets on the reference machine: <= 1% CPU average, <= 150 MiB RSS sidecar, <= 150 MiB browser tab, <= one status upstream request in flight, no unbounded handle/task growth over 1 hour.
- [ ] UI targets: <= 250 KiB compressed initial JS unless reviewed, <= 2 seconds interactive cold local load, <= 100 ms p95 interaction for ordinary tables, <= 16 ms animation frame budget where motion is enabled.
- [ ] Load-test 10 browser sessions, 10,000 safe events, 1,000 run rows, maximum accepted metrics series, and capped protocol graphs. Verify backpressure/resync rather than memory growth.
- [ ] Run the 1-hour extended soak while the dashboard observes it and compare resource/invariant results with a headless run. Observation must not change canonical protocol digests or cause material throughput regression.

### DASH-042 — Add explicit developer deployment enablement

Dependencies: DASH-040, DASH-041
Owner: deployment

- [ ] Add `deploy/compose/dashboard.yaml` as an explicit profile/override with separate daemon and dashboard containers, loopback/host-only published UI port, read-only root filesystem, non-root UID, dropped capabilities, bounded tmpfs/state/evidence volumes, and no Docker socket.
- [ ] The dashboard container receives a read-only daemon token file and UI assets, its own writable runtime/history/evidence roots, and no daemon database/blob/keystore/policy/effect credentials.
- [ ] Add a Kubernetes dashboard overlay only for port-forwarded/operator development. Use a distinct service account, no automounted token, NetworkPolicy permitting only dashboard->cigard and required DNS if any, no public Ingress, read-only filesystem, seccomp, resource bounds, and separate secrets.
- [ ] Add startup/readiness/liveness probes for the sidecar itself. Sidecar readiness requires verified assets/session machinery/store but may remain ready with upstream state `unreachable` so the UI can explain the outage.
- [ ] Base `deploy/compose/*.yaml` and `deploy/kubernetes/shared/kustomization.yaml` must remain dashboard-free; add tests asserting this.
- [ ] Provide a one-command documented local flow that starts the already-configured daemon plus optional dashboard without embedding development credentials in tracked files.

### DASH-043 — Package the sidecar without changing core artifacts

Dependencies: DASH-003, DASH-040, DASH-042
Owner: packaging

- [ ] Define a separate optional dashboard archive/image artifact ID and package contract. Do not silently insert dashboard bytes into existing `cigar`, `cigard`, SDK, plugin, or daemon image artifacts.
- [ ] Package `cigar-dashboard`, exact hashed UI assets/manifest, example config, license/NOTICE/third-party inventory, and docs. Package `cigar-soak` only in test/qualification tooling, not the ordinary observer artifact unless explicitly claimed.
- [ ] Verify packed/unpacked file allowlists, modes, ownership expectations, asset digests, no source maps/private logs/tokens/state, no install scripts, and no unexpected network endpoints.
- [ ] Add dashboard dependencies/assets to SBOM, vulnerability/license/secret scanning, provenance, reproducibility, signing, and artifact matrix only after the producers and installed tests exist.
- [ ] Installed smoke runs from an empty directory, connects to an installed local daemon, displays status, performs a read-only operation, starts/cancels soak-smoke using installed qualification tools, verifies evidence, and uninstalls without touching daemon/user state.

### DASH-044 — Write operator and contributor documentation

Dependencies: DASH-042, DASH-043
Owner: docs

- [ ] `docs/dashboard/index.md`: value, scope, screenshots/diagrams, enable/disable, status meanings, routes.
- [ ] `docs/dashboard/security.md`: trust model, credentials, bootstrap/session/CSRF, loopback restrictions, control mode, child isolation, content safety, evidence and threat model.
- [ ] `docs/dashboard/testing.md`: profile registry, unavailable commands, run states, soak profiles, cancellation, receipt interpretation, development vs release qualification.
- [ ] `docs/dashboard/troubleshooting.md`: daemon unreachable/incompatible, token permissions/rotation, stale metrics, SSE resume, stuck/lost run, disk/retention, asset mismatch, browser/CSP issues.
- [ ] `docs/dashboard/development.md`: deterministic frontend build, schema/generator workflow, component conventions, tests, visual/a11y checks, adding a reviewed run profile.
- [ ] Update README/deploy/docs site manifests and command inventories only with generated/checkable links. Do not describe the dashboard as production internet-facing or a release verifier.

### DASH-045 — Final v1 qualification and handoff

Dependencies: DASH-040 through DASH-044
Owner: release/quality

- [ ] Run format, generation, lint, unit, contract, integration, E2E, accessibility, visual, security, dependency, packaging, install/uninstall, optionality, performance, and 1-hour observation gates on the exact candidate.
- [ ] Run native sidecar/install smoke on every claimed OS/architecture. Remove unsupported platform claims rather than recording a skip.
- [ ] Run `soak-rc-24h` only against exact installed daemon/soak binaries after source and artifacts are frozen. Bind result to source commit/tree/archive, daemon and soak binary SHA-256, dashboard observer SHA-256, profile/plan/registry digests, platform, and evidence schema.
- [ ] Verify dashboard connected and disconnected modes, control disabled/enabled, daemon restart, sidecar restart, browser reload, token rotation, cancellation, and full evidence readback.
- [ ] Perform a focused security review of session/auth, proxy/SSRF, static serving, dynamic dispatch, child process control, filesystem/evidence traversal, HTML rendering, dependency assets, and secret handling; zero critical/high findings.
- [ ] Re-run secret canaries over browser responses, built assets, sidecar logs, run DB, metrics, sanitized exports, packages, and evidence.
- [ ] Update the observed status in `IMPLEMENTATION_STATUS.md` and work-packet/evidence manifests only with exact machine receipts. Do not mark WP19-WP22 complete merely because the dashboard itself passed.

Final done conditions:

- [ ] A new user can explicitly enable the sidecar, authenticate locally, and see current CIGAR health within 2 seconds.
- [ ] The top status rail remains present and correct on every route, including stale/unreachable/incompatible states.
- [ ] All 45 frozen operations are discoverable; every permitted live/dry-run call is typed and policy-classified from generated metadata.
- [ ] Context, space/handoff, effect, replay, and test/soak flows have bounded accessible visual and tabular representations.
- [ ] A user can launch, monitor, cancel, resume viewing, and verify allowlisted tests/soaks without any arbitrary-command or credential path.
- [ ] The 2-minute and 15-minute soaks pass hermetically; the 1-hour and 24-hour results are labeled solely according to their actual evidence bindings.
- [ ] With the dashboard absent, disabled, stopped, or crashed, CIGAR behavior and its default deployment surface are unchanged.
- [ ] No daemon credential, protected content, secret canary, raw private log, or unrestricted filesystem path reaches browser storage, dashboard history, safe events, packages, or sanitized evidence.
- [ ] Documentation explains both the product value and the hard security/qualification limits without implying production readiness.

## Deferred beyond v1

Do not pull these into v1 unless the scope is explicitly amended and threat-modeled:

- Internet-facing/shared multi-user dashboard, OIDC login, RBAC, ingress, or hosted SaaS.
- Direct local Unix-socket/Windows-pipe transport unless implemented once in `cigar-sdk` and fully qualified.
- Arbitrary SQL, filesystem browser, daemon database viewer, raw terminal, custom command editor, or uploaded executable/test plugin.
- Editing trusted policy/authority/source/effect registries from the browser.
- Automatic effect dispatch/retry, backup restore, destructive GC, migration, release signing/publishing, or secret/key management.
- Collaborative annotations, saved protocol payloads, cloud evidence upload, alert acknowledgement, mobile native app, or general-purpose dashboard plugins.
- Claiming Grafana/APM replacement; the sidecar is a protocol testing/visualization surface and should link to external observability for fleet-scale analysis.
