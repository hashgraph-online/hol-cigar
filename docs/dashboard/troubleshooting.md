# Dashboard troubleshooting

Diagnose the dashboard without weakening loopback, file, session, process, or receipt checks. Use
the redacted effective configuration and stable public problem codes; never copy daemon token bytes,
raw child output, source content, unrestricted paths, or private receipt contents into tickets.

## Configuration rejected before startup

Run:

```sh
target/debug/cigar-dashboard --config /absolute/path/dashboard.toml --check-config
target/debug/cigar-dashboard --config /absolute/path/dashboard.toml --print-effective-config
```

Confirm the config is an absolute, ordinary, single-link file owned by the current user and not
group/other writable. All configured paths must be absolute/normalized/distinct. Listener and target
must be numeric loopback; the target is HTTP with no username, password, query, fragment, or extra
path and includes a port/trailing slash. Do not use `localhost`, a LAN address, proxy, container
service name, or public ingress as a workaround.

Control mode additionally needs all workspace/registry/evidence/sandbox paths. Evidence and sandbox
must be owner-only directories outside the source checkout; registry source revision must equal
workspace `HEAD`; native host must be Apple-silicon macOS.

## Asset mismatch or blank shell

```sh
pnpm --filter @cigar/dashboard build
pnpm --filter @cigar/dashboard check:assets
```

The asset directory must contain exactly the manifest-listed ordinary files. Remove accidental
source maps, temporary files, symlinks, or unknown extensions, then rebuild the manifest. Do not edit
a digest/size/MIME entry to make tampered bytes pass. If browser devtools show CSP errors, confirm
there are no inline scripts/styles or third-party origins; broadening CSP is not supported.

## One-time URL or session fails

- Use the URL printed by the currently running process; a restart invalidates old material.
- The fragment can be exchanged once. A second tab/replay intentionally fails.
- Access the exact numeric-loopback host/port configured by the process; alternate hostnames fail
  Host/Origin validation.
- Clear only the `cigar_dashboard_session` cookie or use the UI logout, then restart for a fresh
  bootstrap. Do not copy the bootstrap fragment into logs.
- After reload, the UI calls `session:csrf` with the session cookie to rotate an in-memory value.
  Storage blockers should not require storing CSRF in local/session storage.

## Daemon unreachable or incompatible

Check that the daemon is running on the exact loopback HTTP endpoint and that its public `/livez`,
`/readyz`, `/v1/version`, and `/v1/capabilities` responses are reachable from the same user context.

- `unhealthy` means a valid typed `ready=false` response; fix the named daemon readiness component.
- `unreachable` means transport/freshness policy failed; inspect daemon process/listener and local
  firewall before restarting either process.
- `incompatible` means version/capability negotiation disagreed. Use matching source/artifacts; do
  not bypass negotiation or enable controls.
- stale diagnostics/metrics can coexist with a reachable daemon. The UI shows exact observation age
  and stale source; use one bounded reconnect rather than rapid manual polling.

The sidecar bearer file is reread safely. For rotation, atomically install a new same-owner `0600`,
single-link ordinary file at the configured path. Symlink, hard-link, permissive-mode, oversized,
invalid UTF-8, or changing files are rejected.

## SSE reconnect or missing events

Paused/hidden clients intentionally close EventSource and refresh once when resumed/visible. A
retained `Last-Event-ID` replays later events. An expired sequence or lagged subscriber receives
`stream.resync_required` and must reload bounded indexes; this is not evidence loss. Do not increase
buffers without reviewing count/byte/subscriber bounds.

## Profile disabled

Read the exact public reason:

- `control_disabled`: start with a valid explicit control configuration if reviewed execution is
  actually wanted;
- `platform_unsupported`: only native Apple-silicon macOS is currently claimed;
- `tool_missing`: the tool may be absent or rejected because its file/ancestor lineage is mutable;
  restart only after providing a protected reviewed installation. A Homebrew executable below a
  group-writable `/opt/homebrew` ancestor is intentionally omitted;
- `command_not_implemented`: there is no trustworthy command/receipt contract; it cannot be
  overridden in the UI.

Only three non-soak profiles are eligible, not guaranteed available. On the current host,
`compatibility-matrix` is `tool_missing` because required Homebrew tool lineages fail the closed
write-permission policy. Soak, conformance smoke, and workspace unit profiles are intentionally
closed.

## Run fails, times out, or will not cancel

Failure codes distinguish spawn/persistence, timeout, cancellation, output overflow, missing/unsafe/
invalid/wrongly bound receipt, and product outcome. Exit zero does not override receipt failure.

Cancellation signals the full macOS process group with TERM, waits the reviewed grace, then KILL and
reaps. The UI remains cancelling until a terminal record exists. After an ungraceful sidecar stop,
startup compares the private SQLite v4 process identity, inherited liveness lock, and bounded process-
group observations. A proven-empty group is recorded `lost`; a live or ambiguous identity keeps
control disabled without signalling it. Leave control disabled and preserve the database/evidence
when startup reports recovery required. Do not edit the history database or kill a PID based only on
stale dashboard history.

Raw stdout/stderr is intentionally unavailable. Use stable failure classification, supervisor
receipt digest, product receipt digest, and profile/source/registry bindings for diagnosis.

## Receipt rejected

The expected file must be created below the exact run evidence root at the profile-fixed relative
path, as canonical pretty JSON with one trailing newline. It must be a same-owner `0600` ordinary
single-link file and remain unchanged while opened. Source, macOS/arm64, profile/matrix/schema,
counts, canary, status, and process outcome must agree.

Do not move a receipt from another run, rewrite it by hand, follow a symlink, or classify it as
release evidence. Re-run the exact reviewed profile after correcting the producer.

## History, retention, or disk pressure

History parent directories must remain owner-only. Startup integrity/foreign-key/migration failures
close the sidecar instead of repairing unknown data. Preserve the failed database for offline
analysis; do not point the dashboard at daemon storage.

SQLite v4 reserves aggregate output/evidence limits at queue time and transactionally settles exact
observed bytes with terminal state and descriptors. Startup also requires enough reported free space
for the evidence ceiling plus headroom. That check cannot reserve capacity against another process:
if receipt persistence reports `ENOSPC` or SQLite reports `SQLITE_FULL`, the run fails closed and no
partial passing transition is committed. Restore space, preserve the active/indeterminate row and
evidence, then restart for reconciliation; do not edit SQLite by hand. The sidecar never recursively
deletes external evidence or sandboxes on the browser's request.

## Browser layout or accessibility

Use a current local browser at 100–200% zoom and honor system or explicit reduced motion. If controls
cannot be reached by keyboard, focus is not visible, status relies on color, or the 320 px layout
clips essential actions, treat it as a release-blocking UI defect. Real Chromium/Firefox/WebKit,
axe, forced-colors, zoom, and visual-regression receipts have not yet been produced; pure model tests
must not be cited as those gates.
