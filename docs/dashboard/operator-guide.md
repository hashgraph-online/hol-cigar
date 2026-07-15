# Dashboard operator guide

The dashboard is an explicit local process. Core CIGAR builds, `cigard`, the CLI, MCP, SDKs, base
deployment manifests, and beta artifacts neither start nor require it. The initial claimed cohort is
native Apple-silicon macOS; control supports three non-soak development profiles only.

## Prerequisites

- A local `cigard` listening on numeric loopback HTTP with an absolute `local_token_file`.
- An ordinary, single-link daemon token file owned by the dashboard user and not writable by group
  or other users.
- The verified assets at `apps/dashboard/public` (or an exact packaged equivalent).
- An absolute dashboard TOML derived from `deploy/dashboard/cigar-dashboard.example.toml` and owned
  by the dashboard user. It must be a single-link regular file and not group/other writable.
- Separate owner-only runtime, history, and—when control is enabled—sandbox/evidence directories.

The daemon target must include its trailing slash, for example `http://127.0.0.1:7443/`. The
sidecar rejects hostnames, non-loopback targets, TLS/proxy forwarding, URL credentials/query/
fragment, and arbitrary upstream paths.

## Build and preflight

From the repository root:

```sh
pnpm --filter @cigar/dashboard build
pnpm --filter @cigar/dashboard test
cargo build --locked --offline -p cigar-dashboard
target/debug/cigar-dashboard --config /absolute/path/dashboard.toml --check-config
target/debug/cigar-dashboard --config /absolute/path/dashboard.toml --print-effective-config
```

The effective view redacts endpoints, credentials, and all local paths. Neither preflight mode binds
a listener or creates bootstrap/session state.

`--check-config` is also a read-only filesystem preflight. It rejects relative/non-normalized
paths, direct symlinks, multiple-link protected files, peer-writable or wrongly owned private state,
canonical directory aliases, dashboard state overlapping the daemon token, and control evidence or
sandbox roots nested in the source checkout (in either direction). The runtime and history parent
must already be owner-only `0700`; the bearer file must be owner-only and single-link. A configured
but not-yet-created evidence or sandbox leaf is accepted only below an existing owner-only `0700`
parent and is created `0700` by the control initializer.

Observer mode needs only:

```toml
[control]
enabled = false
max_concurrent_runs = 1
```

For the optional macOS control preview, create external directories first (`0700`) and add:

```toml
[control]
enabled = true
workspace_root = "/absolute/path/to/the/exact/cigar/source"
profile_registry = "/absolute/path/to/the/exact/cigar/source/tests/dashboard/run-profiles-v1.json"
evidence_directory = "/absolute/private/path/dashboard-evidence"
sandbox_directory = "/absolute/private/path/dashboard-sandboxes"
max_concurrent_runs = 1
```

The registry's `source_revision` must equal the workspace `HEAD`; the evidence/sandbox roots must be
outside the source checkout and canonically distinct from every other configured directory. Startup
also requires a
capturable fixed `git` and `python3` toolchain. This does not permit soak.

## Start and authenticate

```sh
target/debug/cigar-dashboard serve --config /absolute/path/dashboard.toml
```

The process writes a one-time loopback URL to stderr. Open it locally. The secret is in the URL
fragment, is exchanged once for an `HttpOnly; SameSite=Strict` session, and is removed from browser
history. A consumed/restarted link cannot be reused. On reload the authenticated browser rotates an
in-memory CSRF value; no CSRF or daemon token is stored in local storage.

`GET /healthz` is process liveness. The authenticated status view may remain available while the
daemon is unreachable so the UI can explain the outage. The persistent rail keeps separate:

- **Operational** — current typed daemon observation;
- **Verification** — latest independently verified reviewed run;
- **Release evidence** — current candidate/artifact qualification, if separately supplied.

Healthy operation never implies verification or release qualification.

## Running reviewed checks

With control enabled, Test Center shows the exact availability returned by the sidecar. Only
`dashboard-contracts`, `compatibility-matrix`, and `security-matrix` are eligible on this macOS
cohort, and each still requires a clean exact source checkout plus every required executable and
ancestor to pass identity/ownership/write-permission checks. On the current Homebrew layout,
`compatibility-matrix` is correctly `tool_missing`; do not weaken `/opt/homebrew` lineage checks to
enable it. Confirm the displayed fixed profile and start it; the browser cannot edit command
details.

Cancellation is idempotent at the UI and remains `cancelling` until the sidecar settles its process
group and persists a terminal state. A cancelled or timed-out run never passes. A zero exit without
the expected canonical product receipt also fails. Compatibility/security matrices can consume
substantial CPU/time; their evidence remains development-only.

Do not manually change soak/conformance/workspace profiles to available. The missing product receipt
or driver is a security boundary, not a UI toggle.

## Stop, rotate, back up, and remove

Ctrl-C initiates graceful shutdown. The sidecar cancels and settles currently owned children within
the configured deadline, stops monitoring, removes the bootstrap file, and closes dashboard history.
After an ungraceful stop, native macOS startup marks only a proven-empty persisted process group
`lost`. A live, legacy, preparing, reused, malformed, or otherwise ambiguous identity keeps control
disabled and is never signalled. Preserve history/evidence and leave control disabled when recovery
is required; automatic adoption is not supported.

To rotate the daemon token, atomically replace it with a new same-owner `0600`, single-link file.
The sidecar revalidates/reopens it on the next SDK request; no browser update is needed.

Dashboard SQLite online backup is an internal owner-only operation with no browser route. It creates
a new `0600` file below an owner-only destination and refuses overwrite/symlink/link targets.
Restore remains an offline operator procedure and is not implemented by the UI.

To remove the dashboard, stop only `cigar-dashboard`, confirm no dashboard-owned run remains, then
delete its config/runtime/history/sandbox/evidence/assets. Do not delete or modify the daemon token
or any CIGAR state. No daemon migration or configuration rollback is required.

## Failure interpretation

- **Starting** — first compatibility/typed observations have not completed.
- **Unhealthy** — daemon returned a valid typed readiness result with `ready=false`.
- **Unreachable** — bounded transport failures/freshness policy was exceeded.
- **Incompatible** — API/protocol negotiation failed; static protocol metadata remains available.
- **Control disabled** — `[control] enabled = false`; observer behavior is normal.
- **Platform/tool/source unavailable** — runtime cohort, captured tool, or exact source revision did
  not satisfy the registry.
- **Receipt missing/invalid/binding/outcome** — the child result was not independently trustworthy;
  it is intentionally failed even if the process exited zero.
- **Asset initialization failure** — run the asset verifier and rebuild; never bypass a stale
  manifest or undeclared file.

See [troubleshooting.md](troubleshooting.md) for bounded diagnosis. Never paste token bytes, raw
child output, source content, private receipts, or unrestricted local paths into a report.
