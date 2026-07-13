# cigar-daemon

Stability: product surface, pre-v1. Composes the CIGAR service runtime; domain semantics remain in library crates.

`cigard serve --config /absolute/path/cigard.toml` composes the complete frozen 45-operation
application over durable SQLite metadata, encrypted tenant blobs, a persistent encrypted
keystore, compiled protected policy, explicit domain authority, strict built-in source/effect
registries, an activation-backed mandatory index, bounded workers, durable idempotency, and
optional bounded OTLP export. Local mode uses a permission-restricted IPC endpoint or authenticated
loopback TCP. Shared mode uses TLS plus pinned OIDC discovery/JWKS refresh and fails startup when
those concrete dependencies are unavailable.

`DurableContextSpaceService` and `DurableHandoffService` serialize each existing domain mutation,
validate the complete resulting state, publish content-addressed chunks before a tenant-scoped CAS
root, and restore the last durable snapshot on failure. Startup rejects missing, malformed, or
semantically inconsistent chunks and roots. A post-commit repository error is reconciled by exact
generation and byte comparison, while an unresolvable outcome poisons the instance so stale state
cannot be served.
