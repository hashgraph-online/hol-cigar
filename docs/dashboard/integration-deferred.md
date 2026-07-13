# Deferred shared-file integration

The canonical ordered handoff queue is
[`post-main-integration-todo.md`](./post-main-integration-todo.md). Keep that checklist current as
the final main tree is integrated; this page records only the reason shared edits remain deferred.

The dashboard implementation began while another agent was finalizing the main codebase. To avoid
conflicts, the initial slice changes only dashboard-owned new paths.

After the main pass completes, perform these shared-file edits in one reviewed integration change:

- Add `crates/cigar-dashboard` and `crates/cigar-soak` to root Cargo workspace members without
  changing `default-members`.
- Add only the exact shared dependencies required by the completed sidecar/soak implementations,
  then update `Cargo.lock` once.
- Add `apps/dashboard` to `pnpm-workspace.yaml`, select and pin the reviewed React/Vite/testing
  dependencies, and update `pnpm-lock.yaml` once.
- Extend the protocol/API generator to emit dashboard dispatch and browser contract models rather
  than manually copying operation metadata.
- Add dashboard schema files to the appropriate schema/docs manifests and drift checks.
- Reconcile `cigar-sdk` remote readiness decoding with the daemon's frozen transport: `/readyz`
  intentionally returns a valid typed `ReadinessResponse` with HTTP 503 when `ready=false`, while
  the current remote decoder rejects every non-success typed JSON response as a protocol error.
  Fix and qualify this in the shared SDK/API transport rather than adding a dashboard-only HTTP
  decoder.
- Add strict `cargo xtask dashboard build|test|check` dispatch only after the authoritative xtask
  command-plane work is stable.
- Add explicit optional Compose/Kustomize overlays and a separate optional package contract; keep
  all base deployments and core artifacts dashboard-free.

Before integration, complete the ownership and baseline gate in the canonical queue, re-run
`git status --short`, and inspect every overlapping root/lock/generated file. Never resolve overlap
by resetting or discarding the other agent's work.
