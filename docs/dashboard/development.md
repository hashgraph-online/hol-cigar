# Dashboard development

Dashboard work is split across independently testable, optional components:

- `crates/cigar-dashboard`: strict local configuration, verified assets, browser authentication,
  secure Axum shell, reviewed profile loading, typed SDK status monitoring, strict run persistence,
  safe event streaming, and authenticated status/profile/run APIs;
- `crates/cigar-soak`: deterministic plan generation and offline receipt verification;
- `apps/dashboard`: dependency-free status model and the future React application;
- `schemas/dashboard`: closed JSON contracts;
- `tests/dashboard`: configuration fixtures and the reviewed profile registry.

While the main repository finalization agent is active, these crates are deliberately not added to
the root workspace and no root lockfile is changed. See `integration-deferred.md` for the one-time
shared integration packet.

## Current local gates

Run the schema and dependency-free frontend checks directly:

```text
python3 tests/dashboard/validate_schemas.py
pnpm --dir apps/dashboard test:status
```

The frontend command currently runs 20 dependency-free unit tests covering the closed status model,
health-detail/freshness formatting, theme/density/motion preference policy, and fail-closed
automatic-refresh policy. Production asset digests are also enforced by the Rust asset-loader tests.

For Rust checks before shared integration, copy each crate to a private temporary standalone Cargo
package and use exact versions already present in the root lockfile. Keep build targets under the
temporary directory. After integration, the authoritative gates become:

```text
cargo test --locked --offline -p cigar-dashboard -p cigar-soak
cargo clippy --locked --offline -p cigar-dashboard -p cigar-soak --all-targets -- -D warnings
cargo fmt --all -- --check
```

The stricter local lint pass also denies `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, and
unchecked indexing.

## Adding a run profile

1. Add a schema-valid profile in ascending ID order.
2. Select only `cargo`, `python3`, or `cigar-soak`; provide fixed argv and no environment surface.
3. Bound duration, cancellation, memory, processes, ordinary output, and evidence.
4. Declare a fixed working-directory class, network mode, concurrency group, receipt schema, and
   honest evidence category.
5. Add only closed availability probes. Workspace paths must be normalized relative paths.
6. Keep the profile `command_not_implemented` until the exact supervisor dispatch and receipt
   verifier are tested. Never change availability merely to make a control appear enabled.
7. Re-run schema, Rust registry, security, and UI tests and review the new registry SHA-256.

Frontend code consumes generated or schema-derived types once shared integration is complete. Do
not hand-copy operation IDs or protocol payload fields into components. CSS uses the dashboard
tokens in `apps/dashboard/src/theme.css`; status rendering must preserve separate operational,
verification, and release-evidence states.
