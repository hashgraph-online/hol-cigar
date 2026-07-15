# Dashboard security boundary

The dashboard is a local, single-operator sidecar. It is not an internet-facing administration
plane or a secure-beta protocol component. Its observer boundary is loopback HTTP; its optional
run-control cohort is native Apple-silicon macOS and development evidence only.

## Trust model

| Boundary | Untrusted input | Enforcement |
|---|---|---|
| Browser to sidecar | headers, cookies, JSON, IDs, cursors | numeric-loopback listener; exact Host/Origin; session; CSRF; request caps; closed schemas |
| Sidecar to daemon | daemon responses and metrics | typed SDK decoding, closed metrics parser, size/time limits, no arbitrary proxy |
| Filesystem | config, token, registry, assets, receipts | absolute normalized paths, no symlink/hard link, owner/mode checks, identity checks, confinement, digests |
| Sidecar to child | profile ID and local toolchain | exact registry lookup, captured executable identity, fixed argv, cleared environment, private PATH, no shell |
| Child to sidecar | exit, stdout/stderr, receipt | byte caps and hashes only; strict canonical receipt; independent binding/outcome verification |

The sidecar never reads daemon persistence and never gives the browser or a child process the daemon
credential. It does not trust loopback alone, proxy headers, child exit status, a UI-selected
evidence class, or unverified receipt content.

## Browser and observer controls

- Startup creates a random one-time bootstrap token in a create-new `0600` file below an exact
  owner-only `0700` runtime directory. Successful exchange consumes the token.
- Sessions are restart-scoped, capacity/TTL bounded, `HttpOnly`, and `SameSite=Strict`; HTTPS would
  additionally set `Secure`. Reload obtains a new in-memory CSRF value only through an authenticated,
  same-origin rotation request. CSRF is never persisted in browser storage.
- `Forwarded` and `X-Forwarded-*` inputs are rejected. Static and API responses carry CSP,
  anti-framing, no-sniff, referrer, permissions, and cache controls appropriate to their content.
- Assets are immutable verified bytes from an exact manifest. A separate production-bundle gate
  scans every HTML, CSS, and JavaScript asset and rejects inline/eval/dynamic code, external-origin
  references, direct transports outside the one reviewed wrapper, Node/runtime APIs, dynamic
  active-content sinks, command/argv/executable/environment/target fields, source maps, undeclared
  files, unreviewed MIME types, and symlinks. The wrapper accepts only closed same-origin sidecar
  paths, rejects redirects, and forces same-origin credentials plus a no-referrer policy.
- The bearer-token file must be bounded, ordinary, single-link, owner-only, and stable across
  metadata/open/read checks. Its bytes are zeroized and excluded from errors, debug output, URLs,
  HTML, local storage, SQLite, evidence, and child environments.
- File-based configuration performs the same fail-closed topology preflight before `--check-config`
  reports success: private runtime/history/control roots are owner-only, protected input files are
  single-link and not peer-writable, canonical aliases cannot duplicate roots, daemon-token and
  dashboard-state paths cannot overlap, and evidence/sandbox roots cannot contain or be contained
  by the configured source checkout. Each subsystem revalidates its object again when opening it.
- Safe events and stored run metadata contain only closed codes, counts, times, digests, categories,
  and opaque identifiers. Source content, prompts, raw effect arguments, raw logs, and arbitrary
  filesystem paths are not part of those models.

## Control-mode isolation

Enabling control is a startup decision, not a browser override. Initialization fails unless the
registry, workspace, sandbox, and evidence roots are absolute and canonically separated; the evidence and
sandbox roots are owner-only external directories. The source `HEAD` must equal the registry's
exact revision.

The supervisor captures the executable path, device/inode identity, byte length, mode, owner,
SHA-256, and complete ancestor lineage of its allowlisted toolchain at startup. Group/other-writable
ancestors are rejected (with only the root-owned sticky `/private/tmp` exception), unsafe optional
tools are omitted, and protected system Git/Python/ps paths are preferred. It constructs a random
private shim directory and revalidates every file and ancestor identity before every spawn. Browser
requests cannot set an executable, argv, cwd, environment name/value, path, duration, evidence
class, or network mode. Shell command strings and interpolation are absent.

For every enabled profile, the supervisor independently proves a clean, non-skip-worktree exact
`HEAD`, rejects Git filters/attributes/sparse/shared-index and related checkout transformations,
securely captures the tracked source through no-follow descriptors, validates the fixed Python
entrypoint/import closure, and creates a detached private snapshot. The child cwd is that snapshot,
never the mutable source checkout. Live source is rechecked immediately before spawn; snapshot and
tool bytes are rechecked after execution. Symlink/hardlink inputs, capture-to-launch swaps,
post-capture mutation, unreviewed imports, and manifest disagreement fail closed.

Each child receives only the fixed registry argv, a private working/evidence directory, null stdin,
and the closed environment needed for canonical offline evidence (`CIGAR_EVIDENCE_DIR`, exact source
revision, locale/time zone, no-bytecode, and the private PATH). Inherited proxy, loader, compiler
wrapper, credential, home, and daemon-token variables are cleared. Ordinary output is never sent to
the browser; each stream has a reviewed byte limit and only length/SHA-256 enters the supervisor
receipt.

On macOS the sidecar owns a fresh child process group. Timeout, cancellation, and shutdown signal
that whole group with TERM, wait the profile's bounded grace, then KILL and reap. Cache-heavy work is
single-flight, read-only checks are bounded to four, and the configured global maximum is always
enforced.

## Evidence verification

The verifier opens only the one receipt path predetermined by the selected profile. It rejects path
escape, symlinks, multiple links, peer-writable files, owner mismatch, replacement races, byte/depth/
node/string/item overflow, duplicate object names, unknown/noncanonical JSON, unsupported schemas,
wrong source or macOS/arm64 platform, wrong profile or matrix digest, case/count inconsistency,
canary output, and process/receipt outcome disagreement.

Only a sanitized descriptor is committed to history. The descriptor's evidence category is taken
from the reviewed registry; all currently available profiles are `development`. A canonical
`dashboard-supervisor-receipt.v1.json` separately binds the executable, fixed argv, registry,
profile, source, environment, tool-version digest, clean-source assertion, source-tree digest, and
the exact sorted execution-input path/role/byte/mode/owner/SHA-256 manifest, plus UTC and monotonic
timing, output counts/digests, exit, stop reason, and any resource violation. The supervisor receipt
itself is create-new, single-link, owner-only, identity-bound, byte-reopened, parent-synced, and
reverified before its descriptor is committed. Neither receipt makes a release claim.

## Known open security gates

- SQLite v4 records supervisor generation, PID/PGID, a bounded macOS creation-identity digest, and
  active/settled/indeterminate aggregate output/evidence reservations and usage.
  Restart reconciliation never signals a recovered PID: it marks only a proven-empty generation-1
  group `lost` and blocks control startup for live, reused, legacy, preparing, malformed, or
  otherwise ambiguous rows. Automatic adoption and exhaustive escaped-descendant recovery remain
  open; do not assume a restarted sidecar owns a pre-crash child.
- A no-unsafe internal launcher applies child-only hard `RLIMIT_CORE`, `RLIMIT_CPU`, `RLIMIT_FSIZE`,
  and `RLIMIT_NOFILE` ceilings before executing the captured digest-bound tool. Aggregate process-
  group RSS and member count are sampled every 100 ms; a violation or malformed/unavailable probe
  terminates the group and cannot pass. macOS has no reliable job-scoped hard RSS ceiling here, and
  `RLIMIT_NPROC` is UID-wide, so memory/process ceilings remain polled rather than kernel-hard.
- Evidence traversal rejects links and non-regular entries, revalidates identity while reading, and
  caps entries plus exact aggregate bytes including the supervisor receipt. Queue reservation and
  terminal lifecycle/process/descriptors/usage settlement are transactional. Free-space preflight
  is not a reservation: concurrent external disk exhaustion remains possible, but `SQLITE_FULL` and
  receipt `ENOSPC` fail closed and cannot leave a partial passing transition. A destructive full-
  volume recovery qualification has not been run.
- There is no structured progress FD; stdout/stderr remain fully content-opaque.
- Cargo/rustup development tools remain operator-owned. Their exact startup file and ancestor
  identities are bound and rechecked, but this is development evidence, not an installed immutable
  toolchain or a claim against a malicious same-UID operator.
- The production soak driver and destructive workload isolation do not exist, so every soak profile
  remains `command_not_implemented`.
- Real-browser, actual sidecar-kill/PID-reuse, packaging, install/uninstall, secret-canary, and
  focused independent security review receipts remain outstanding. Fuzzing and soak were explicitly
  excluded from the current macOS run.

Do not broaden endpoint scope, weaken file checks, make a profile available, or infer release
readiness to work around one of these gates. Report suspected auth, parser, path, process, or content
leaks with stable codes and digests—not secret values, protected content, or private logs.
