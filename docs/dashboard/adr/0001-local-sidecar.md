# ADR 0001: local sidecar dashboard

Status: accepted; observer integrated 2026-07-13; bounded macOS non-soak controls added 2026-07-14

Integration baseline: commit `56a5a1346bdfd362f67c279f4f8cd5d4ba7c46b2`, tree
`d06cf0075faf21ffa7d6c55d0da3229f4cebc4b1`, clean worktree. Exact capture is in
`docs/dashboard/integration-evidence/baseline.txt`. This ADR and observer integration do not modify,
replace, or qualify WP19-WP22 or secure-beta release evidence. A later unrelated untracked
`README_BETA.md` is outside dashboard ownership and remains untouched.

## Context

CIGAR already exposes a frozen 45-operation API, bounded SSE, readiness, diagnostics, metrics, and
typed SDK clients. It does not contain a browser application. Adding browser assets or dashboard
routes to `cigard` would expand the daemon's unauthenticated/static-serving surface and make the UI
part of every deployment even when unused.

## Decision

Implement a separate `cigar-dashboard` Rust process with a browser application served on loopback.
The sidecar uses `cigar-sdk` with embedded-daemon features disabled. Observer v1 owns browser
authentication, status aggregation, a read-only projection of the generated operation registry,
reviewed profile metadata, and dashboard-only run history. Three independently receipt-producing
non-soak profiles may be supervised when control is explicitly enabled on native Apple-silicon
macOS. Typed mutation dispatch, soak execution, and release qualification remain gated follow-up
work.

V1 is local-first. Both the dashboard listener and daemon HTTP target are numeric loopback
addresses. Remote multi-user access, OIDC login, RBAC, public ingress, and hosted operation are
deferred.

## Rejected alternatives

| Alternative | Reason rejected |
|---|---|
| Serve the SPA from `cigard` | Changes the daemon surface and violates runtime optionality |
| Browser calls `cigard` directly | Exposes daemon credentials and requires a browser CORS/auth model |
| Read daemon databases directly | Bypasses tenant/policy/API contracts and couples to persistence internals |
| Electron or a native webview | Adds a second runtime and packaging/security surface without a v1 need |
| Generic reverse proxy | Allows ungenerated paths and weakens typed operation controls |
| Browser terminal/custom commands | Creates an arbitrary local-code-execution surface |
| Dashboard-specific protocol records | Duplicates or changes frozen CIGAR semantics |

## Consequences

- CIGAR works unchanged when the dashboard is absent, stopped, or crashed.
- A local daemon must expose its authenticated loopback HTTP transport for the v1 dashboard.
- Static assets and the sidecar can be packaged independently from existing core artifacts.
- Shared or internet-facing deployment requires a later threat model and explicit architecture.
- The dashboard must distinguish operational health from verification and release evidence.

## Identities, roots, and shutdown

The browser identity is one restart-scoped local session derived from a one-time secret. The
sidecar process identity owns its runtime directory, verified assets, and separate history file. It
reads—but never returns—the daemon owner token and uses that credential only through the remote SDK.
The daemon remains the sole protocol/storage authority. The optional runner requires distinct
external owner-only sandbox/evidence roots and never receives the observed daemon token or user
state.

Graceful sidecar shutdown stops new HTTP work, closes the status monitor/SSE service, removes an
unused bootstrap file, flushes the single history writer, and then exits. Stopping or crashing the
sidecar does not signal, reconfigure, or stop `cigard`.

## Personas and support claims

- Observer: delivered; reads local status, generated protocol metadata, and sanitized history.
- Local developer/test operator: three non-soak development profiles can launch/cancel through the
  reviewed macOS supervisor; every soak/exit-only profile stays unavailable until its own receipt
  contract and the installed-binary driver exist.
- Multi-user administrator: explicitly out of scope; no RBAC/OIDC/ingress is provided.

Focused Rust/static/model qualification runs on the repository toolchain on native Apple-silicon
macOS. The observer/auth/control-disabled slice is exercised in real Chromium, Firefox, and WebKit;
live browser control/receipt flows and native packaging/install remain separate and unclaimed.
Linux, Windows, and non-Apple architectures are outside the initial control cohort.
