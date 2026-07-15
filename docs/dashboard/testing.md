# Dashboard testing and evidence

Dashboard tests are optional and do not requalify a CIGAR release. The current execution cohort is
native Apple-silicon macOS. Fuzzing and soak execution are excluded from this run; every soak
control therefore remains unavailable.

## Reviewed profile registry

`tests/dashboard/run-profiles-v1.json` is strict, sorted, source-revision bound, and SHA-256 bound at
startup. A profile fixes its executable selector, argv, working-directory class, availability
probes, platform, durations, resource metadata, network mode, concurrency group, cancellation grace,
receipt schema, evidence category, and documentation. The browser supplies only its exact ID.

Current macOS availability:

| Profile | Runtime state | Receipt | Meaning |
|---|---|---|---|
| `dashboard-contracts` | available when control/tool/source checks pass | `cigar.dashboard-schema-check.v1` | validates all strict dashboard schemas and local references |
| `compatibility-matrix` | `tool_missing` on the current Homebrew layout | `cigar.test-matrix-result.v1` | Node/Go/Corepack/uv ancestors are group-writable and are deliberately omitted; development evidence |
| `security-matrix` | available only when every Rust/Python/shell tool lineage passes | `cigar.test-matrix-result.v1` | reviewed offline security matrix; development evidence |
| `conformance-smoke` | `command_not_implemented` | — | command does not produce the required independent receipt |
| `workspace-units` | `command_not_implemented` | — | command does not produce the required independent receipt |
| every `soak-*` profile | `command_not_implemented` | — | production workload driver is unavailable and soak is excluded |

Static `available` is narrowed independently at startup to `control_disabled`,
`platform_unsupported`, `source_checkout_required`, or `tool_missing` when its closed prerequisites
fail. An unsafe optional tool is omitted; it never widens the trust boundary merely to keep a
profile runnable. Other schema-enumerated reasons are retained for future reviewed probes:
`dependency_cache_missing` and `credential_missing`. An unknown availability value fails closed in
both Rust and browser code.

## Run lifecycle

The persisted legal lifecycle is:

```text
queued -> preparing -> running -> passed | failed | timed_out | cancelled
```

Create requires an authenticated session, exact same Origin/Host, current CSRF value, exact JSON
content type, and a body containing only `profile_id`. Cancellation requires the same boundary and a
canonical active UUIDv7. The browser cannot construct a cancellation path for any other value.

Capacity failures do not partially launch a command. A successful spawn is persisted as running
before publication. User cancellation, timeout, and product failure are distinct terminal states.
The sidecar sends TERM to the macOS process group, waits the reviewed grace, then sends KILL and
reaps. Shutdown uses the same settlement path.

## Receipt interpretation

The product receipt and supervisor receipt have different roles:

- The **product receipt** proves the reviewed check's schema-specific result. It must be canonical,
  confined below the exact external run root, match the registry/source/profile/matrix/platform, and
  agree with the process outcome.
- The **supervisor receipt** proves what the sidecar launched and observed: executable/argv/profile/
  registry/source/environment/tool-version digests, the exact dashboard executable digest, an exact
  sorted execution-input manifest, a clean-source assertion and source-tree digest, UTC and
  monotonic timing, output byte counts and hashes, exit status, stop reason, and any resource
  violation.

Exit zero with no, stale, malformed, unsafe, wrongly bound, or contradictory product receipt is
`failed`. Nonzero remains failed even if a forged receipt claims pass. Raw receipt bytes, stdout,
stderr, sandbox contents, and absolute paths are not copied to browser history. Currently available
receipts are always classified `development`, never candidate-bound or release-qualifying.

## Local gates

Run these from the repository root with the pinned toolchains and offline dependency caches:

```sh
python3 tests/dashboard/validate_schemas.py
pnpm --filter @cigar/dashboard build
pnpm --filter @cigar/dashboard test
cargo test --locked --offline -p cigar-dashboard --all-targets
cargo clippy --locked --offline -p cigar-dashboard --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline -p cigar-dashboard --no-deps
```

The schema command validates 18 schemas and 84 local references. With `CIGAR_EVIDENCE_DIR` and
`CIGAR_SOURCE_REVISION` set by the supervisor it additionally emits a create-new canonical
`dashboard-schema-check.v1.json` below the private external evidence root.

The frontend build regenerates the exact-byte asset manifest and then runs both independent
verifiers. Thirty-one browser unit/model cases cover the closed same-origin network wrapper,
redirect/credential/referrer confinement, fail-closed control availability, canonical UUIDv7
cancellation, generated 7-service/45-operation validation, health precedence/freshness,
pause/visibility behavior, and closed display preferences. Twenty-three production-bundle verifier
cases include hostile fixtures for external HTML/CSS, inline content, direct transports, Node APIs,
dynamic code/DOM sinks, missing module dependencies, command/argv/raw-target/authorization fields,
and wrapper weakening. The
asset verifier separately rejects inventory, MIME, digest, size, symlink, source-map, and
undeclared-file disagreement.

The focused Rust package suite contains 86 unit tests and 4 real-binary launcher integration tests.
Its supervisor integration launches the real
`dashboard-contracts` command under a private cleared environment, verifies both receipts, and
persists only sanitized descriptors. It also proves the child inherits its owner-only liveness lock,
a second supervisor refuses the live identity without signalling it, and a dead persisted PID/group
reconciles to `lost`. A separate crash test exits the supervisor OS process without destructors
while the child remains alive, proves restart fails closed, and reconciles only after that exact
process identity disappears. Resource tests exercise actual CPU-time termination, file-size partial
writes, open-file exhaustion, aggregate RSS/process-count stops, exact child CPU/core/file/FD
limits, wrong launcher target digests, aggregate output/evidence accounting, over-limit pass
rejection, disk-full classification, and hostile nested/link evidence trees. Durable retention
tests cover event-byte, terminal-count, and terminal-age caps while preserving evidence-linked
rows. Negative tests cover missing/mismatched receipts and distinct cancellation/timeout/resource
classification. Source hostile tests cover same-HEAD dirty
entrypoints/imports, capture-to-launch swaps, snapshot mutation, hard/symbolic links, unreviewed
imports, unsafe executable ancestors, ancestor replacement, forged clean claims, and execution-input
omission/addition/digest substitution. Ten configuration cases cover endpoint suffix/userinfo/DNS/
mapped-address rejection, duplicate TOML, overflow and limit bounds, private owner/mode/link
metadata, direct symlinks, canonical directory aliases, state/token overlap, and evidence hidden
inside the source checkout. The local installed-artifact verifier binds exact archive/dashboard/
asset-manifest/package-contract bytes and a source identity, requires the contract bytes to equal
the reviewed development contract compiled into the verifier, rejects mutations, substituted
contracts, and links, and can emit only a partial unqualified descriptor; it does not verify a
signature or claim an installed smoke ran. Other tests cover sessions/CSRF, asset verification,
strict JSON, metrics, status, cursor MACs, state transitions, SQLite migration/integrity/retention/
backup, and API security headers.

The exact 2026-07-14 command results and non-claims are recorded in
`docs/dashboard/integration-evidence/nonsoak-macos-closure-20260714.md`.

## Deferred qualification

These commands are not substitutes for the missing gates:

- The current Chromium, Firefox, and WebKit observer/auth/control-disabled slice passes 27/27, but
  live browser launch/cancel/reload/receipt flows and the broader visual/status matrix remain open.
- No PID-reuse campaign, interrupted-preparing/legacy repair, destructive aggregate disk
  exhaustion, exhaustive escaped-descendant, or kernel-hard RSS/process-limit receipt exists. The
  real supervisor-process crash, error-classification, launcher-limit, and polled group-limit tests
  are narrower than those gates.
- No produced/installed archive or image, upgrade/uninstall, installed smoke,
  SBOM/signature/provenance, or candidate binding has been tested. The local byte-binding verifier
  is development source, not installed qualification.
- No fuzzing, 1-hour observation, two-minute/15-minute/24-hour soak, or real soak driver was run.

Do not mark the full dashboard packet or release evidence green until those selected gates exist.
