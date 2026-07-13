# Public API reference

The canonical HTTP description is [OpenAPI v1](../../schemas/openapi/cigar-v1.json), the RPC service
is [cigar_service.proto](../../schemas/proto/cigar_service.proto), and Context ABI records are in
[context_abi.proto](../../schemas/proto/context_abi.proto). JSON Schema documents live under
`schemas/json/`; canonical and replay vectors live under `schemas/vectors/`. Generated clients must
match `schemas/generated-manifest.json` byte-for-byte.

HTTP and gRPC expose the same governed operation IDs. Requests carry bounded deadlines, explicit
authorization, idempotency keys where required, and optimistic revisions where required. Pagination
cursors are opaque, authenticated, bounded, and tenant scoped. Streams preserve item ordering and
terminate with a structured problem rather than silently truncating.

Protocol minimum and maximum versions are reported by compatibility diagnostics. Context ABI v1 is
schema-stable: unknown fields are handled only where the schema explicitly allows extensions, and
unknown enum values fail closed at policy or mutation boundaries.

Errors use the generated [error registry](../../schemas/openapi/error-registry-v1.json). Clients make
retry decisions from the structured code and remediation, not from message text. In particular,
authorization, integrity, revision, unknown-effect, and replay-completeness failures are not generic
retries.
