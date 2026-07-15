# CIGAR dashboard web application

This directory owns the optional browser experience. The integrated observer v1 contains the
status state machine, generated protocol explorer, semantic design tokens, and a dependency-free
responsive production shell in
`public/`. Its exact bytes are bound by `asset-manifest.v1.json` and verified by the sidecar before
traffic is accepted.

The package is an explicit private pnpm workspace member but no root script builds it implicitly.
The dependency-free implementation keeps the production asset graph minimal and CSP-auditable; a
framework migration is not required for observer v1. The shell never
contacts the daemon: it exchanges the one-time URL fragment for an HttpOnly sidecar session, clears
the fragment from browser history, and communicates only with the `cigar-dashboard` BFF.

All browser network access crosses `browser-security.20260714.js`. It accepts only the closed
same-origin sidecar route set (plus a canonical UUIDv7 cancellation route), refuses redirects, and
forces same-origin credentials plus a no-referrer policy. The production build runs an independent
static policy verifier over every HTML, CSS, and JavaScript asset. The verifier rejects remote
references, inline or dynamically constructed active content, direct network primitives outside
the wrapper, Node/runtime APIs, dynamic code execution, URL credentials, and command, executable,
argv, environment, raw-target, or daemon-token fields.

The dependency-free shell also reads bounded persisted run and sanitized evidence history from the
authenticated sidecar to render independent verification and release states. When control mode is
explicitly enabled, it can launch and cancel only non-soak macOS profiles whose executable and argv
are fixed by the reviewed registry and whose machine receipt has an independent verifier. Soak
profiles remain unavailable in this cohort. Its display menu persists only closed theme, density, and motion
values under `cigar.dashboard.theme.v1`, `cigar.dashboard.density.v1`, and
`cigar.dashboard.motion.v1`. Malformed or unavailable browser storage falls back safely. No
protocol, endpoint, identifier, session, CSRF, or live-update data is stored.

The live-update control is ephemeral. Pausing closes EventSource and suppresses automatic polling
without clearing the last status; manual refresh remains bounded to one active plus one coalesced
request. Hidden tabs suspend streaming/polling, and resume or foreground visibility triggers one
immediate resynchronization. No live-update state is written to browser storage.

The health disclosure reads only the already sanitized aggregate status response. It presents exact
observation times, age/failure facts, the redacted target alias, closed configuration limits and
transports, diagnostics staleness, and readiness component reason codes. Freshness labels never
replace the backend-owned aggregate classification, and reconnect uses the same bounded refresh
path as the top-bar control.

From the repository root, `pnpm --filter @cigar/dashboard build` regenerates and verifies the
exact-byte manifest and browser security policy. `pnpm --filter @cigar/dashboard test` additionally
runs the browser model tests and hostile production-bundle fixtures.
