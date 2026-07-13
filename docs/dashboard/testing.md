# Dashboard test and soak model

The dashboard never accepts commands, executable paths, environment variables, working directories,
or arbitrary arguments from a browser. A control request selects only an exact ID from
`tests/dashboard/run-profiles-v1.json`. The sidecar validates that strict registry, retains its
exact-byte SHA-256 digest, and rejects duplicate or unsorted IDs, unknown fields, unsafe path
selectors, unbounded resources, and release profiles that target a source checkout.

## Availability

Registry availability is conservative. `command_not_implemented` is a static hard stop. Once the
job supervisor exists, an `available` profile must also pass its closed runtime probes. Runtime
availability is reported with one of these content-free reasons:

- `available`
- `control_disabled`
- `source_checkout_required`
- `tool_missing`
- `platform_unsupported`
- `dependency_cache_missing`
- `credential_missing`
- `command_not_implemented`

The initial registry intentionally marks every profile `command_not_implemented`; none may launch
until process-group isolation, environment sanitization, bounded output, cancellation, and strict
receipt checking land together.

## Soak profiles

| ID | Duration | Sessions | Meaning |
|---|---:|---|---|
| `soak-smoke` | 120 s | 1, 2 | Harness and receipt smoke; no qualification claim |
| `soak-developer` | 900 s | 1, 2, 4, 8 | Local mixed-flow feedback; no qualification claim |
| `soak-extended` | 3,600 s | 1 through 32 | Development-only leak and fault signal |
| `soak-rc-24h` | 86,400 s | 1 through 64 | Release evidence only with exact installed-candidate bindings |

`cigar-soak plan` generates a deterministic plan containing its seed, exact duration and session
schedule, workload weights totaling 10,000 basis points, logical-operation fault schedule, source
revision, daemon SHA-256, and profile-registry SHA-256. Existing plan paths are never replaced.

`cigar-soak verify` is offline. It binds a strict result to the exact plan bytes, source revision,
profile, and daemon digest; verifies monotonic RFC 3339 duration; requires every phase, session,
fault, sample class, and invariant; and rejects a passing status when duration, operations, or any
invariant is insufficient. Duplicate JSON object names and unknown fields fail closed.

The workload-running command currently exits with `DriverUnavailable`. This is intentional: plan
and receipt validation are useful independently, but an incomplete harness must never emit or
display a passing soak.

## Safe-event history and live status

The dashboard status stream is authenticated and same-origin at `GET /api/v1/events`. Events are
committed to the dashboard-owned SQLite journal before being retained or published. The broker
bounds event bytes, retained bytes/count, live buffer capacity, and concurrent subscribers. A valid
`Last-Event-ID` replays only later retained sequences; an expired sequence or lagged subscriber
receives `stream.resync_required` and the lagged stream closes.

History startup rejects non-private parent directories, symlinks, linked or permissive database
files, unknown migrations, malformed retained JSON/run rows, sequence disagreement, and oversized
events. Schema v2 contains only strict content-safe run metadata, transitions, evidence descriptors,
closed preferences, and safe-event JSON; it never references daemon persistence.

Run and evidence indexes use descending `(timestamp, opaque ID)` pagination. Cursors are URL-safe,
HMAC-authenticated, collection-bound, expire after 15 minutes, and reject duplicate/unknown query
fields, encoding aliases, tampering, cross-endpoint reuse, and oversized limits. They contain no
credential or receipt content and intentionally expire across sidecar restarts.

The internal history backup operation is serialized behind all previously acknowledged writes. It
accepts only an absent absolute path under an owner-only directory, creates one `0600` ordinary file,
uses SQLite's online backup API, verifies the exact schema version plus quick-check and foreign keys,
syncs the snapshot and parent directory, and never overwrites an existing file. Tests reopen the
snapshot and read back events, runs, and evidence while proving writes made after the snapshot are
absent. Relative, existing, symlink, and permissive-parent destinations fail closed. There is no
browser backup/restore route; restore policy remains an explicit post-integration operator concern.

## Browser live-update controls

Pausing live updates preserves the last rendered operational, verification, and release
classifications while closing EventSource and suppressing interval-driven refresh. The refresh
button can still request one bounded observation, with concurrent manual requests coalesced to one
follow-up. Resuming or returning a hidden tab to the foreground performs one immediate refresh;
hidden tabs keep streaming and automatic polling suspended. Pure policy tests cover closed
pause/visibility states. DASH-040 still requires real-browser lifecycle, reconnect, keyboard, and
assistive-label verification after frontend integration.

## Display preferences

The native display menu exposes closed theme (`system|light|dark`), density
(`comfortable|compact`), and motion (`system|standard|reduced`) policies. Each control carries text
and an icon, supports keyboard activation, and restores only its versioned allowlisted value from
local storage. Unknown values and storage denial fall back safely. System motion follows
`prefers-reduced-motion`; explicit reduced motion enforces near-zero durations, while explicit
standard motion deliberately overrides that media query. The menu closes with Escape and keeps the
three controls together at narrow widths. DASH-040 retains real-browser keyboard, media-query,
cross-tab, 200% zoom, and 320 px verification.

## Health details

The health disclosure consumes the same sanitized aggregate response as the persistent status rail;
it never performs an independent daemon probe or derives aggregate health. It exposes exact
aggregate/configuration/diagnostics timestamps, the redacted alias, closed deployment/transports/
limits, failures, stale sources, and public component states/reason codes/latencies. Freshness is a
separate display fact: `<10s` is fresh, `10s..=30s` is stale, and `>30s` is expired. Pure tests cover
both boundaries, malformed ages, closed aggregate/component values, transport selection, and byte
formatting. The reconnect button uses the existing coalesced manual refresh. Typed upstream problem
codes, reviewed runbook links, hostile-text fixtures, and real-browser disclosure/table semantics
remain post-integration gates.

## Cancellation and receipts

When the supervisor and driver are implemented, cancellation creates a terminal `cancelled`
receipt with at least one sorted failure code. It does not count elapsed time toward a later run.
A retry always creates a new plan and run ID. Zero exit status without a strict, current receipt is
failure; browser-visible progress is structured and content-free, never raw stdout or stderr.
