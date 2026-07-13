# ADR 0001: local sidecar dashboard

Status: accepted for v1 implementation

## Context

CIGAR already exposes a frozen 45-operation API, bounded SSE, readiness, diagnostics, metrics, and
typed SDK clients. It does not contain a browser application. Adding browser assets or dashboard
routes to `cigard` would expand the daemon's unauthenticated/static-serving surface and make the UI
part of every deployment even when unused.

## Decision

Implement a separate `cigar-dashboard` Rust process with a browser application served on loopback.
The sidecar uses `cigar-sdk` with embedded-daemon features disabled. It owns browser authentication,
status aggregation, generated operation dispatch, reviewed test supervision, and dashboard-only run
history.

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
