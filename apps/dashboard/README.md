# CIGAR dashboard web application

This directory owns the optional browser experience. The current conflict-free slice contains the
status state machine, semantic design tokens, and a dependency-free responsive production shell in
`public/`. Its exact bytes are bound by `asset-manifest.v1.json` and verified by the sidecar before
traffic is accepted.

React/Vite dependencies, generated dashboard API models, and root workspace registration remain
deferred until the main codebase finalization pass releases the shared manifests. The shell never
contacts the daemon: it exchanges the one-time URL fragment for an HttpOnly sidecar session, clears
the fragment from browser history, and communicates only with the `cigar-dashboard` BFF.

The dependency-free shell also reads bounded persisted run and sanitized evidence history from the
authenticated sidecar to render independent verification and release states. It deliberately has
no run-creation, cancellation, or receipt-ingestion UI until the allowlisted process supervisor and
receipt verifier are complete. Its display menu persists only closed theme, density, and motion
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
