# Service API v1

Status: frozen v1 contract.

The single source of truth for the service operation surface is
`spec/api/operations-v1.json`. `cargo xtask generate` derives the Protobuf
service declarations, OpenAPI document, and Rust operation registry from that
catalog. Hand-editing any generated artifact is unsupported, and
`cargo xtask generate --check` rejects drift.

## Shared identity

Every operation has one stable Protobuf RPC name and one stable lower-camel
operation identifier. The identifier is shared by HTTP bindings, embedded
facades, SDK methods, CLI JSON envelopes, audit records, and request telemetry.
An OpenAPI `operationId` is exactly the lower-camel form of its RPC name.

CLI and MCP are explicit closed projections, so an operation absent from those
catalogs has no alias on that surface. Request logs retain the generated
identifier through `RequestContext`. Public problem bodies retain the frozen
error code and correlation identifier without a second caller-authored
operation field. Metrics deliberately aggregate API outcomes and structurally
forbid operation identifiers as labels; this is the compatible bounded-metric
projection, not an alternate operation identity.

The Protobuf package is `cigar.v1`. The frozen surface has exactly seven
services and 45 operations. Adding an alias, alternate spelling, extra method
on an existing path, or extra path is an API compatibility change.

## Transport envelopes and bounds

All RPCs use the generated `OperationRequest`, `OperationResponse`, and, for a
server stream, `OperationEvent` envelopes. Operation-specific payloads are
canonical CBOR bytes behind these bounded envelopes. HTTP/JSON and SSE encode
those bytes as unpadded base64url; `+`, `/`, and `=` are rejected.

`spec/api/operation-payloads-v1.json` is the authoritative exact-45 mapping
from operation IDs to typed request, response, and event schema names. It also
records every payload field's authority source and bound. Production handlers
decode through those DTOs; a generic map, JSON value, or opaque byte payload is
not an operation-specific service contract.

- Request payloads are limited to 16 MiB after decompression. The operation ID
  is at most 128 ASCII characters, idempotency keys and revisions at most 256,
  page cursors at most 4096, and page size is server-capped at 1000.
- URI-template bindings are normalized as at most eight sorted, unique
  `PathParameter` records. HTTP extracts them from the exact route and checks
  any body copy; gRPC carries the same records explicitly.
- `dry_run` is an envelope boolean included in the normalized request digest.
  It requests governed preview behavior but does not bypass authentication,
  authorization, idempotency, optimistic revision, or mutation policy.
- Unary response payloads are limited to 16 MiB. Event payloads are limited to
  1 MiB each. Servers also bound stream queue depth and lifetime.
- Every mutation requires `Idempotency-Key`. Revision-sensitive mutations also
  require `If-Match` or the equivalent `expected_revision` request field.
  `discoverSources`, `queryCatalog`, `batchAtoms`, and `previewHandoff` are
  read-only POST bindings and reject mutation-only metadata.
- Immutable responses can carry semantic ETags. Lists use opaque signed
  cursors pinned to the query and snapshot.
- `SubscribeSpaceEvents` is gRPC server-streaming and HTTP SSE. SSE resume uses
  `Last-Event-ID`. All other v1 operations are unary.
- HTTP errors use `application/problem+json` and the frozen numeric error
  registry. Deadlines and trace context are bounded by server policy.
- HTTP accepts gzip request bodies only while it can independently measure the
  compressed bytes, expanded bytes, and expansion ratio. The gRPC servers do
  not accept compressed requests because Tonic exposes application messages
  only after decompression; caller-declared compressed lengths are not trusted.
  Bounded gzip gRPC responses remain supported.

## Exact operation surface

The exact development operation, payload, CLI, MCP, and error-retry tables are generated directly
from their machine authorities in [`../api/operations-v1.md`](../api/operations-v1.md). This prose
specification defines transport semantics; it does not maintain a second operation inventory.

The `health` class is limited to content-free process/readiness probes.
`anonymous` returns compatibility metadata only. `tenant` and `operator`
authentication do not replace semantic authorization inside service facades.

## Conformance

Generation validates exact route equality, unique method/path pairs, unique RPC
names and operation IDs, lower-camel identity, mutation/idempotency consistency,
revision metadata, stream metadata, and authentication metadata. Unit tests
then prove that every catalog RPC appears in Proto, OpenAPI, and Rust and that
stale generated files fail generation checks.
