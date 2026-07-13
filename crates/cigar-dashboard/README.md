# cigar-dashboard

Stability: optional local sidecar, pre-v1.

`cigar-dashboard` is the local-only browser sidecar described in
`docs/dashboard/architecture.md`. It is intentionally not a dependency of `cigard` and is not a
default workspace member.

The current isolated implementation provides strict configuration, verified immutable assets,
one-time bootstrap/session/CSRF authentication, Host/Origin enforcement, a secured loopback Axum
listener, reviewed run-profile loading, and content-safe status monitoring through `cigar-sdk` with
default features disabled. Typed configuration, readiness, diagnostics, and metrics observations
are bounded and cross-validated before the browser receives closed queue/counter values. Browser
APIs require the dashboard session and never return the daemon credential.

Status transitions are committed to an owner-protected dashboard-only SQLite journal before they
enter the bounded resumable SSE broker. Schema v2 also stores strict dashboard run records and
append-only run transitions, plus closed evidence-descriptor and preference tables. Authenticated
bounded run and sanitized evidence list/detail reads drive independent verification/release cards;
their continuation cursors are short-lived, collection-bound, and HMAC-authenticated. There is no
HTTP run-creation, backup, restore, or receipt-ingestion surface. The internal history client can
emit a serialized create-new owner-only SQLite snapshot for operator tooling; it never overwrites a
path and validates schema, integrity, permissions, and readback. Replay is sequence-based, retention
gaps and subscriber lag produce an explicit resync event, and the journal never opens daemon
storage.

Protocol mutations and job launches remain unavailable. The profile endpoint is read-only and every
initial profile is explicitly `command_not_implemented` until the isolated supervisor exists.

Root workspace membership and lockfile integration are deferred while the main codebase
finalization pass is modifying shared files. The ordered handoff is maintained in
`docs/dashboard/post-main-integration-todo.md`.
