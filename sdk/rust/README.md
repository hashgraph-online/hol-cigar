# CIGAR Rust SDK

`cigar-sdk` exposes all 45 frozen CIGAR v1 operations through one async `Client`. The same typed
methods run against an embedded production runtime, the built-in bounded HTTP/SSE daemon
transport, or an extension-provided object-safe `ClientTransport`. Operation request and response
types come directly from `cigar-api`; semantic records come directly from `cigar-protocol`.

`cigar_sdk::CONTEXT_ABI` is the installed package's exact Context ABI declaration and equals
`cigar.context.v1`.

## Remote daemon

```rust,no_run
use cigar_sdk::{AuthorizationValue, RemoteClientBuilder, StaticAuthorization};
use std::sync::Arc;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let credentials = Arc::new(StaticAuthorization::new(
    AuthorizationValue::new("Bearer configured-token")?,
));
let (client, compatibility) = RemoteClientBuilder::new("https://cigar.example/")?
    .authorization_provider(credentials)
    .connect()
    .await?;
assert_eq!(compatibility.capabilities.api_version, "v1");
# let _ = client;
# Ok(())
# }
```

The built-in transport disables proxies, redirects, and referrers; requires HTTPS by default;
bounds bodies and SSE frames; validates canonical base64url and frozen problems; and negotiates
the API/protocol line before returning. Cleartext is available only through explicit loopback
opt-in for local test deployments.

## Embedded production runtime

The default `embedded-daemon` feature provides `DaemonEmbeddedRuntimeFactory`. It derives the
local identity from the configured project root and requires the SDK's Full SQLite and local
policy paths to exactly match the daemon's trusted production configuration. Validation happens
before database composition or worker startup. `EmbeddedClient::shutdown()` performs the daemon's
ordered graceful shutdown.

Remote-only applications can disable the heavier embedded implementation with
`default-features = false`; the injectable `EmbeddedRuntimeFactory` seam remains available.

## Calls, pagination, and streams

Every method accepts `CallOptions`. Mutations require a protocol-native `IdempotencyKey`; the two
revisioned mutations additionally require `ExpectedRevision`. Deadlines and cancellation are
bounded and transport-independent. `Client::paginate` lazily follows only server-issued
`PageCursor` values. `subscribe_space_events` returns a typed resumable stream;
`StreamEvent::resume_token` preserves its raw `event_id` for `Last-Event-ID`, and cancellation is
requested when that stream is dropped. Pagination cursors and stream event identities are distinct
types and cannot be accidentally interchanged.

Automatic retry is bounded to transport failures and server `safe`/`after_backoff` classes when
the exact request is repeat-safe. The same idempotency key is preserved on every attempt.
`dispatchEffect` is never retried automatically, even when a transport response is lost; callers
must inspect status and reconcile explicitly.

## Local integrity

`verify_bundle`, `verify_manifest`, `verify_bundle_manifest`, `verify_delta`, and
`apply_verified_delta` enforce protocol validation, domain-separated semantic identities, exact
delta digests, and target reproduction. Bundle, manifest, and delta operation responses are also
verified automatically before the typed method returns.

Run the cross-language quickstart:

```text
cargo run -p cigar-sdk --example quickstart
```

It verifies the packaged copy of `sdk/fixtures/semantic-bundle-v1.json` and prints the shared
semantic bundle ID. Qualification tests require the packaged and shared fixture bytes to match.

## Honey Agent A coordinator

The packaged `agent_a_coordinator` example creates one recipient-bound handoff from a reviewed,
bounded JSON `CreateHandoffRequest`. It reads authorization only through
`CIGAR_AUTHORIZATION_FILE`, requires a caller-provided idempotency key, and prints only
disclosure-safe identifiers and attenuation counts:

```text
CIGAR_ENDPOINT=http://127.0.0.1:8080 \
CIGAR_AUTHORIZATION_FILE=/private/path/agent-a.authorization \
cargo run --example agent_a_coordinator -- handoff-request.json agent-a-handoff-001
```

Agent B acceptance and result recording use a distinct principal. The coordinator example does
not acquire Agent B credentials, bypass recipient reauthorization, or print the task and typed
references from the request.
