# Dashboard architecture

Status: initial implementation boundary

The CIGAR dashboard is an optional local sidecar. It is not part of `cigard`, is not started by
`cigard`, and is not required by the CLI, MCP server, SDKs, or embedded runtime.

## Runtime boundary

```text
loopback browser
    |
    | dashboard session + CSRF
    v
cigar-dashboard
    |-- verified UI assets
    |-- status aggregation
    |-- generated typed operation dispatch
    |-- reviewed test-run supervision
    |-- dashboard-owned run history
    |
    | cigar-sdk HTTP/SSE
    v
cigard public API
```

The browser never receives a CIGAR bearer token. `cigar-dashboard` reads that credential from an
absolute owner-protected file and uses the remote-only Rust SDK. Dashboard history is stored
separately and the sidecar never opens CIGAR's SQLite, PostgreSQL, blob, key, policy, authority, or
effect-registry files. Dashboard history snapshots are create-new, owner-only copies serialized by
the dashboard writer; they are not daemon backups and no generic browser restore surface exists.

## V1 trust boundaries

- The dashboard listener and configured CIGAR target must both be numeric loopback addresses.
- Loopback reachability is not authentication. A one-time bootstrap secret establishes an
  `HttpOnly; SameSite=Strict` dashboard session; state-changing sidecar requests also require a
  session-bound CSRF value and strict Origin/Host validation.
- Protocol calls use generated operation metadata and typed SDK methods. There is no arbitrary
  upstream URL/path proxy.
- Test controls resolve reviewed profile IDs to fixed executable and argv records. There is no
  terminal, custom command, browser-supplied path, or shell interpolation.
- Soak tests create isolated CIGAR state, runtime, project, and evidence roots. They do not drive
  sustained or destructive traffic against the status target.
- Default UI events contain stable codes, counts, durations, digests, and opaque IDs. They do not
  contain prompts, source content, credentials, raw effect arguments, or raw child output.

## Ownership

| Path | Owner |
|---|---|
| `apps/dashboard` | Browser application and frontend tests |
| `crates/cigar-dashboard` | Sidecar configuration, session, gateway, jobs, and run history |
| `crates/cigar-soak` | Isolated deterministic soak driver |
| `schemas/dashboard` | Dashboard configuration/API/run contracts |
| `tests/dashboard` | Contract fixtures, reviewed profiles, security and E2E tests |
| `docs/dashboard` | User, operator, security, and contributor documentation |

## Status model

The dashboard keeps three states separate:

1. Operational status derives from current daemon liveness, readiness, compatibility, diagnostics,
   and metrics.
2. Verification status derives from the latest schema-verified test or soak receipt.
3. Release-evidence status derives from candidate/artifact-bound qualification evidence.

A healthy daemon does not imply passing tests or release readiness. A stale observation never
replaces a newer valid observation, and a valid readiness response with HTTP 503 is an unhealthy
observation rather than a transport outage.

## Optionality invariant

Until the final integration packet, dashboard implementation work is confined to dashboard-owned
new paths. Root workspace manifests, lockfiles, generated protocol files, daemon code, and active
WP19-WP22 evidence are intentionally untouched while the main codebase finalization pass is active.
