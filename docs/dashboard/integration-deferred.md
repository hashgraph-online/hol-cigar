# Dashboard shared integration record

The optional observer was integrated from baseline commit
`56a5a1346bdfd362f67c279f4f8cd5d4ba7c46b2`. Baseline evidence is under
`docs/dashboard/integration-evidence/`; remaining work is tracked in
`post-main-integration-todo.md` and `todo-dashboard.md`. Unrelated dirty-worktree files remain outside
dashboard evidence and must not be overwritten.

## Integrated

- `cigar-dashboard` and `cigar-soak` are explicit workspace members outside Cargo
  `default-members`; the sidecar has no daemon/store semantic dependency.
- `apps/dashboard` is an optional dependency-free pnpm workspace. Root install/build behavior and
  core artifacts remain unchanged.
- The authenticated protocol endpoint serves the generated seven-service/45-operation/34-error
  projection instead of a copied frontend registry.
- Eighteen dashboard schemas and 84 local references pass the strict offline scan. The exact asset
  inventory has a deterministic build and independent verifier.
- Typed observer status, closed metrics, safe SSE replay/resync, SQLite run/evidence persistence,
  cursor-bound pagination, and private online history backup are integrated.
- Native Apple-silicon macOS can initialize an optional allowlisted supervisor. Exactly three
  non-soak development profiles can become available. Fixed argv execution, cleared environment,
  captured tool identities and version digests, private roots, process-group cancellation, hard
  child CPU/core/file/FD ceilings, polled aggregate RSS/process ceilings, transactional output and
  evidence ledgers, bounded content-opaque output, independent canonical receipt verification, and
  sanitized supervisor/product descriptors are implemented.
- Focused dashboard evidence for this integration is 90/90 Rust tests, strict all-target/all-feature
  Clippy, warning-free rustdoc, 31/31 browser-model tests, 23/23 hostile browser-policy cases, ten
  verified assets, and 18/84 schema/reference checks. The current real-browser observer slice passes
  27/27 across Chromium, Firefox, and WebKit.

## Still deferred

- Automatic active-process adoption, interrupted-preparing/legacy repair, exhaustive child-escape
  recovery, structured progress framing, destructive full-volume recovery qualification, and
  kernel-hard memory/job-process ceilings. Native macOS generation-1 running rows have fail-closed
  PID/PGID/start-identity reconciliation and never signal a recovered PID; RSS and process count are
  polled every 100 ms and can transiently overshoot their profile ceiling.
- The installed-binary `cigar-soak` workload driver. Plan generation/offline verification exist, but
  all soak profiles remain `command_not_implemented` and no soak was run.
- Full protocol mutation explorer, effect/compensation/restore/GC execution, and release-evidence
  inference. Current runnable receipts are development-only.
- Live browser run/receipt E2E, the broader visual/status matrix, destructive/resource-performance
  qualification, container/native package production, install/upgrade/uninstall,
  SBOM/provenance/signing, and final independent security review. Native Rust now covers a real
  supervisor-process crash, resource ceilings, and durable retention, but this is not a browser or
  installed-candidate qualification.
- Native platforms other than Apple-silicon macOS. Platform skips must not be treated as support.

The incomplete gates above are explicit limitations. They do not weaken the observer boundary or
authorize a release-qualification claim.
