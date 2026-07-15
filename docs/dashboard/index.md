# CIGAR dashboard

The CIGAR dashboard is an optional local console for understanding a running CIGAR daemon without
giving the browser a daemon credential or direct persistence access. It combines typed health,
diagnostics, a generated protocol map, safe event/run history, and—when explicitly enabled on native
Apple-silicon macOS—three reviewed non-soak verification controls.

It is not an internet-facing admin service, a general command terminal, a soak driver, or a release
verifier. Omitting or stopping it changes no daemon route, worker, storage, artifact, or protocol
semantic.

## What it shows

- current liveness, readiness, compatibility, configuration, diagnostics, bounded metrics, and data
  freshness;
- a generated seven-service/45-operation protocol catalog with payload/event bounds and public error
  retry metadata;
- dashboard-owned content-safe events, runs, state transitions, and sanitized evidence descriptors;
- three intentionally separate signals: operational state, latest verification, and release
  evidence;
- reviewed profile availability and exact disabled reasons.

The initial UI is a single local application shell with anchored Overview, Protocol map, Test
center, Soak monitor, and Evidence sections. Static documentation remains useful when the daemon is
unreachable or incompatible. Soak and generic mutation controls are disabled.

## Data flow

```text
browser --dashboard session/CSRF--> cigar-dashboard --typed SDK + server-only token--> cigard
                                      |
                                      +--> separate dashboard SQLite
                                      |
                                      `--> optional fixed-profile child --> external verified receipt
```

The browser sees bounded public models only. It never sees the daemon token, raw child output,
source content, private logs, unrestricted paths, daemon storage, or receipt file bytes.

## Get started on macOS

1. Start an already configured local `cigard` on numeric loopback HTTP and locate its owner-only
   local-token file.
2. Build and verify the optional dashboard explicitly:

   ```sh
   pnpm --filter @cigar/dashboard build
   pnpm --filter @cigar/dashboard test
   cargo build --locked --offline -p cigar-dashboard
   ```

3. Copy `deploy/dashboard/cigar-dashboard.example.toml` to an absolute owner-only location, replace
   every example path, and keep `[control] enabled = false` for observer-only use.
4. Preflight, then start:

   ```sh
   target/debug/cigar-dashboard --config /absolute/path/dashboard.toml --check-config
   target/debug/cigar-dashboard serve --config /absolute/path/dashboard.toml
   ```

5. Open the one-time loopback URL printed by the process. The fragment is consumed once and replaced
   with a restart-scoped `HttpOnly` session.

For optional reviewed controls, follow [operator-guide.md](operator-guide.md) to configure separate
external evidence/sandbox roots. `dashboard-contracts`, `compatibility-matrix`, and
`security-matrix` are the only eligible non-soak profiles in the initial macOS cohort, but each is
independently narrowed by clean-source and protected-tool-lineage checks. The current Homebrew
layout leaves `compatibility-matrix` as `tool_missing`. All results are development evidence.

## Status meanings

| State | Meaning |
|---|---|
| Starting | compatibility or the first typed observation is incomplete |
| Healthy | fresh compatible liveness/readiness are valid and ready |
| Degraded | usable but a source is stale or a bounded component is degraded |
| Unhealthy | a valid readiness response says the daemon is not ready |
| Unreachable | transport/freshness failure exceeded the closed policy |
| Incompatible | version/capability negotiation failed; live/control actions are closed |

Verification and release evidence have separate values and never inherit `Healthy`.

## Sidecar routes

All routes are loopback-only. Except `/healthz` and initial session exchange, API routes require the
dashboard session; mutating routes also require exact Origin/Host and CSRF.

| Route | Purpose |
|---|---|
| `GET /healthz` | sidecar process liveness, independent of upstream readiness |
| `POST /api/v1/session:exchange` | one-time bootstrap exchange |
| `POST /api/v1/session:csrf` | authenticated in-memory CSRF rotation after reload |
| `POST /api/v1/session:logout` | current dashboard-session removal |
| `GET /api/v1/bootstrap` | bounded sidecar/session metadata |
| `GET /api/v1/status` | sanitized aggregate observation |
| `GET /api/v1/events` | bounded resumable safe-event SSE |
| `GET /api/v1/protocol` | generated frozen protocol projection |
| `GET /api/v1/run-profiles` | reviewed profiles and runtime availability |
| `GET/POST /api/v1/runs` | paginated history / exact-profile start |
| `GET /api/v1/runs/{id}` | one persisted run |
| `POST /api/v1/runs/{id}:cancel` | cancel one active canonical UUIDv7 run |
| `GET /api/v1/evidence` | paginated sanitized evidence descriptors |
| `GET /api/v1/evidence/{id}` | one sanitized descriptor |

## Documentation

- [Architecture](architecture.md)
- [Operator guide](operator-guide.md)
- [Security boundary](security.md)
- [Testing and evidence](testing.md)
- [Troubleshooting](troubleshooting.md)
- [Development](development.md)
- [Local-sidecar ADR](adr/0001-local-sidecar.md)
- [Remaining integration queue](post-main-integration-todo.md)

Known gaps are documented rather than hidden: no soak driver/run, no fuzzing in this pass, no
automatic adoption or exhaustive escaped-child recovery, no kernel-hard macOS RSS/job-process
ceiling (the supervisor uses fail-closed 100 ms group polling), no structured progress channel, no
live browser control/receipt qualification beyond the 27/27 observer/auth/control-disabled engine
slice, and no production package/install/release receipts yet.
