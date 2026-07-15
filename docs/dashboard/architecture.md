# Dashboard architecture

Status: optional local observer with a bounded macOS control preview

`cigar-dashboard` is a separate, explicitly started process. It is not linked into or started by
`cigard`; the CLI, MCP server, SDKs, embedded runtime, default Cargo members, core packages, and
base deployments do not depend on it.

## Runtime boundaries

```text
local browser
    |  restart-scoped session + Origin/Host + CSRF
    v
cigar-dashboard
    |-- verified immutable UI assets
    |-- typed health/diagnostic aggregation through cigar-sdk
    |-- generated 45-operation documentation catalog
    |-- dashboard-only SQLite history and safe-event journal
    |-- optional reviewed-run supervisor (native Apple-silicon macOS only)
    |
    +---- bearer token used only here ----> loopback cigard public HTTP API
    |
    +---- exact profile ID ----> captured executable + fixed argv
                                |-- private sandbox
                                |-- external evidence root
                                `-- independently verified receipt
```

The browser never receives the daemon bearer token. The sidecar reopens that credential through an
owner-protected file boundary and uses typed SDK calls. It never opens the daemon SQLite/PostgreSQL,
blob, key, policy, authority, source, or effect-registry stores. Dashboard history is a different
SQLite database with its own migrations, integrity checks, writer, retention, and online backup.

## Observer plane

- Both the listener and daemon target are explicit numeric loopback HTTP endpoints. Proxy headers,
  arbitrary upstream URLs, browser-to-daemon calls, and internet ingress are rejected.
- A one-time fragment secret creates an `HttpOnly; SameSite=Strict` session. Mutating sidecar
  requests also need exact Host and Origin values plus a session-bound CSRF header.
- Static files are loaded into memory only after the manifest inventory, sizes, MIME types, and
  SHA-256 digests pass. The response CSP permits only same-origin external scripts and styles.
- Operational state comes from typed liveness, readiness, identity, configuration, diagnostics,
  and closed metrics observations. Transport failure, incompatible protocol, stale data, and a
  valid `ready=false` response are different states.
- The protocol view serializes the generated `cigar-api` projection. Browser code validates the
  seven services, 45 operations, payload bounds, and 34 public error records; it has no copied
  operation registry or general mutation proxy.

## Optional control plane

Control remains off unless all four isolated paths and `[control] enabled = true` are present.
Startup then requires native Apple-silicon macOS, the exact registry source revision at `HEAD`,
owner-only external evidence and sandbox roots, and a startup-captured toolchain.

Only these non-soak development profiles are eligible to become `available`:

- `dashboard-contracts`;
- `compatibility-matrix`;
- `security-matrix`.

Eligibility is not availability. Startup omits any executable whose file or ancestor lineage is
symlinked, replaced, peer-writable, or otherwise outside the protected owner/root boundary. The
system `/usr/bin/python3`, `/usr/bin/git`, and `/bin/ps` are preferred. On the current Homebrew
layout, `compatibility-matrix` is consequently `tool_missing` because its Node, Go, Corepack, and
uv paths traverse group-writable `/opt/homebrew` ancestors; this is intentional. `dashboard-contracts`
can remain available, and `security-matrix` can remain available when its Rust tools also pass the
same lineage checks. The API reports each profile's independently narrowed state.

The HTTP request contains only an exact profile ID. The sidecar resolves the captured executable,
fixed argv, workspace, duration, output/evidence caps, cancellation grace, concurrency group, and
receipt contract. It clears the environment, installs a private fixed PATH of captured executable
links, sets null stdin, hashes and counts bounded stdout/stderr without persisting their contents,
and owns a dedicated process group. Cancellation, timeout, and shutdown use TERM, a bounded grace,
KILL, and reap.

Before launch, the sidecar proves a clean exact `HEAD`, rejects unsafe Git checkout configuration,
securely reads the tracked tree through no-follow descriptors, validates the fixed Python import
closure, and builds a private detached snapshot. The child runs only from that snapshot. Source and
tool identities are rechecked before spawn and source snapshot bytes are rechecked after exit. The
supervisor receipt records the sorted exact execution-input manifest (path role, bytes, mode, owner,
and SHA-256), the clean-source assertion, and the source-tree digest.

The run is persisted as queued, preparing, and then atomically running with a private PID/process-
group creation identity before the corresponding safe events are published. An owner-only inherited
liveness lock and bounded macOS `ps` probes support restart reconciliation without adopting or
signalling a recovered process.
Exit zero is never enough: the expected canonical receipt must be an owner-only, single-link file
confined below the exact run evidence root, match source/profile/matrix/platform/outcome bindings,
and pass bounded strict-JSON validation. History receives only sanitized descriptors and digests;
raw receipt bytes, raw paths, stdout, and stderr stay out of browser/history surfaces. Every run also
gets a canonical supervisor receipt recording the exact execution binding and content-free output
metadata.

## Three independent meanings

1. **Operational** describes the current daemon observation.
2. **Verification** describes the latest independently verified dashboard-run receipt.
3. **Release evidence** requires candidate/artifact-bound qualification evidence.

The three values never imply one another. The currently runnable profiles are development evidence
only and therefore cannot set release readiness to qualified.

## Deliberate limits

- Soak launch is unavailable. `cigar-soak` plan/offline verification does not constitute a workload
  driver, and no soak profile is enabled in the dashboard.
- Generic protocol mutations, effect dispatch, compensation, restore, and GC execution remain
  unavailable.
- Generation-1 running/cancelling rows have native macOS restart reconciliation. A proven-empty
  process group becomes `lost`; an exact live identity, reused/ambiguous PID, legacy row, or
  interrupted `preparing` row blocks control startup and is never signalled. SQLite v4 adds an
  active/settled/indeterminate resource ledger: queuing reserves aggregate output/evidence bytes,
  and one transaction settles exact observed bytes with the terminal lifecycle, process identity,
  and both sanitized descriptors. A passing state is impossible when that transaction fails.
- The child-only launcher applies hard macOS core, CPU-time, per-file-size, and open-file limits
  before starting the captured executable. Aggregate process-group RSS and member count are sampled
  every 100 ms and fail closed on violation or an unreadable probe; they are not kernel-hard memory
  or job-scoped process limits and can transiently overshoot. Automatic adoption, exhaustive
  child-escape recovery, and structured progress framing are not implemented.
- Chromium/Firefox/WebKit E2E, accessibility automation, packaging/install receipts, performance
  qualification, and long-run observation are still external gates.
- The initial control claim is native Apple-silicon macOS only. Containers and non-macOS native
  control are not claimed by this implementation.

## Ownership and optionality

| Path | Responsibility |
|---|---|
| `apps/dashboard` | Browser application, deterministic assets, pure browser-policy tests |
| `crates/cigar-dashboard` | Sidecar auth, gateway, history, supervisor, receipt verification |
| `crates/cigar-soak` | Deterministic plan and offline soak-result verification; driver unavailable |
| `schemas/dashboard` | Strict dashboard configuration/API/run/receipt contracts |
| `tests/dashboard` | Fixtures, reviewed registry, schema and deployment checks |
| `docs/dashboard` | Operator, security, testing, and contributor documentation |

The dashboard crates are explicit workspace members but not `default-members`. Omitting or stopping
the sidecar requires no daemon configuration migration and changes no CIGAR protocol semantics.
