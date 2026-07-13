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
facades, SDK methods, CLI JSON envelopes, audit records, and error telemetry.
An OpenAPI `operationId` is exactly the lower-camel form of its RPC name.

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

The catalog records mutation, idempotency, revision, stream, and authentication
metadata for every row. `rev` means an expected revision is mandatory; `-`
means no revision is required.

| Service | RPC / operation ID | HTTP binding | Revision | Stream | Auth |
| --- | --- | --- | --- | --- | --- |
| CatalogService | `DiscoverSources` / `discoverSources` | `POST /v1/sources:discover` | - | unary | tenant |
| CatalogService | `IngestCatalog` / `ingestCatalog` | `POST /v1/catalog:ingest` | - | unary | tenant |
| CatalogService | `GetSourceStatus` / `getSourceStatus` | `GET /v1/catalog/sources/{source_id}` | - | unary | tenant |
| CatalogService | `QueryCatalog` / `queryCatalog` | `POST /v1/catalog:query` | - | unary | tenant |
| CatalogService | `BatchAtoms` / `batchAtoms` | `POST /v1/catalog/atoms:batch` | - | unary | tenant |
| CatalogService | `TombstoneAtom` / `tombstoneAtom` | `POST /v1/catalog/atoms/{atom_id}:tombstone` | rev | unary | tenant |
| ContextService | `CreateContextPlan` / `createContextPlan` | `POST /v1/context/plans` | - | unary | tenant |
| ContextService | `CompileContextBundle` / `compileContextBundle` | `POST /v1/context/bundles:compile` | - | unary | tenant |
| ContextService | `CompileContextDelta` / `compileContextDelta` | `POST /v1/context/deltas:compile` | - | unary | tenant |
| ContextService | `GetContextBundle` / `getContextBundle` | `GET /v1/context/bundles/{bundle_id}` | - | unary | tenant |
| ContextService | `GetContextBundleManifest` / `getContextBundleManifest` | `GET /v1/context/bundles/{bundle_id}/manifest` | - | unary | tenant |
| ContextService | `ExplainContextBundle` / `explainContextBundle` | `POST /v1/context/bundles/{bundle_id}:explain` | - | unary | tenant |
| ContextService | `MaterializeContextBundle` / `materializeContextBundle` | `POST /v1/context/bundles/{bundle_id}:materialize` | - | unary | tenant |
| ContextService | `RevalidateContextBundle` / `revalidateContextBundle` | `POST /v1/context/bundles/{bundle_id}:revalidate` | - | unary | tenant |
| SpaceService | `CreateSpace` / `createSpace` | `POST /v1/spaces` | - | unary | tenant |
| SpaceService | `ForkSpace` / `forkSpace` | `POST /v1/spaces/{space_id}:fork` | rev | unary | tenant |
| SpaceService | `PublishSpace` / `publishSpace` | `POST /v1/spaces/{space_id}:publish` | rev | unary | tenant |
| SpaceService | `GetSpaceLog` / `getSpaceLog` | `GET /v1/spaces/{space_id}/log` | - | unary | tenant |
| SpaceService | `SubscribeSpaceEvents` / `subscribeSpaceEvents` | `GET /v1/spaces/{space_id}/events` | - | server stream / SSE | tenant |
| SpaceService | `CreateSpaceCheckpoint` / `createSpaceCheckpoint` | `POST /v1/spaces/{space_id}/checkpoints` | rev | unary | tenant |
| SpaceService | `ListSpaceConflicts` / `listSpaceConflicts` | `GET /v1/spaces/{space_id}/conflicts` | - | unary | tenant |
| SpaceService | `ResolveSpaceConflict` / `resolveSpaceConflict` | `POST /v1/spaces/{space_id}/conflicts/{conflict_id}:resolve` | rev | unary | tenant |
| HandoffService | `CreateHandoff` / `createHandoff` | `POST /v1/handoffs` | - | unary | tenant |
| HandoffService | `PreviewHandoff` / `previewHandoff` | `POST /v1/handoffs/{handoff_id}:preview` | - | unary | tenant |
| HandoffService | `AcceptHandoff` / `acceptHandoff` | `POST /v1/handoffs/{handoff_id}:accept` | rev | unary | tenant |
| HandoffService | `RevokeHandoff` / `revokeHandoff` | `POST /v1/handoffs/{handoff_id}:revoke` | rev | unary | tenant |
| HandoffService | `RecordHandoffResult` / `recordHandoffResult` | `POST /v1/handoffs/{handoff_id}/results` | rev | unary | tenant |
| HandoffService | `MergeHandoff` / `mergeHandoff` | `POST /v1/handoffs/{handoff_id}:merge` | rev | unary | tenant |
| EffectService | `PrepareEffect` / `prepareEffect` | `POST /v1/effects` | - | unary | tenant |
| EffectService | `AuthorizeEffect` / `authorizeEffect` | `POST /v1/effects/{effect_id}:authorize` | rev | unary | tenant |
| EffectService | `DispatchEffect` / `dispatchEffect` | `POST /v1/effects/{effect_id}:dispatch` | rev | unary | tenant |
| EffectService | `GetEffectStatus` / `getEffectStatus` | `GET /v1/effects/{effect_id}` | - | unary | tenant |
| EffectService | `ReconcileEffect` / `reconcileEffect` | `POST /v1/effects/{effect_id}:reconcile` | rev | unary | tenant |
| EffectService | `CompensateEffect` / `compensateEffect` | `POST /v1/effects/{effect_id}:compensate` | rev | unary | tenant |
| ReplayService | `CreateReplay` / `createReplay` | `POST /v1/replays` | - | unary | tenant |
| ReplayService | `RunObservationalReplay` / `runObservationalReplay` | `POST /v1/replays/{replay_id}:run` | - | unary | tenant |
| ReplayService | `CompareLiveReplay` / `compareLiveReplay` | `POST /v1/replays/{replay_id}:compare` | - | unary | tenant |
| ReplayService | `GetReplayCompleteness` / `getReplayCompleteness` | `GET /v1/replays/{replay_id}/completeness` | - | unary | tenant |
| OperationsService | `GetLiveness` / `getLiveness` | `GET /livez` | - | unary | health |
| OperationsService | `GetReadiness` / `getReadiness` | `GET /readyz` | - | unary | health |
| OperationsService | `GetVersion` / `getVersion` | `GET /v1/version` | - | unary | anonymous |
| OperationsService | `GetCapabilities` / `getCapabilities` | `GET /v1/capabilities` | - | unary | anonymous |
| OperationsService | `GetConfiguration` / `getConfiguration` | `GET /v1/configuration` | - | unary | operator |
| OperationsService | `GetDiagnostics` / `getDiagnostics` | `GET /v1/diagnostics` | - | unary | operator |
| OperationsService | `GetMetrics` / `getMetrics` | `GET /metrics` | - | unary | operator |

The `health` class is limited to content-free process/readiness probes.
`anonymous` returns compatibility metadata only. `tenant` and `operator`
authentication do not replace semantic authorization inside service facades.

## Conformance

Generation validates exact route equality, unique method/path pairs, unique RPC
names and operation IDs, lower-camel identity, mutation/idempotency consistency,
revision metadata, stream metadata, and authentication metadata. Unit tests
then prove that every catalog RPC appears in Proto, OpenAPI, and Rust and that
stale generated files fail generation checks.
