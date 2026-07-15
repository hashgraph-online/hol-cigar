# WP14 frozen-operation composition map

Status: post-implementation composition audit. This map records the current ownership and trust
boundaries; it does not declare WP14 complete. WP14 completion remains controlled by the build,
test, and exit gates in `prd.md`.

## Frozen typed boundary

The v1 registry is no longer an opaque-payload placeholder. The authoritative
[`TYPED_OPERATION_MAPPINGS`](../../crates/cigar-api/src/typed.rs) binds every generated operation
to a sealed request, response, and optional event type. Operation DTOs reject unknown fields and
apply bounded semantic validation. The shared codec verifies the envelope operation, accepts only
canonical deterministic CBOR, reconciles generated path bindings, and rejects a conflicting body
copy. Transport metadata such as dry run, idempotency key, expected revision, page cursor, and page
size remains outside caller-authored domain DTOs.

[`ProductionApplicationBuilder`](../../crates/cigar-daemon/src/application.rs) accepts handlers
only through sealed operation markers and refuses to build a missing, duplicated, unknown, or
wrong-kind registry. The production composition registers 44 unary operations and the sole
server-streaming operation, `subscribeSpaceEvents`. The ownership count is
`6 + 8 + 8 + 6 + 6 + 4 + 7 = 45`.

## Exact operation ownership

| Family | Concrete owner | Exact frozen operation and payload bindings |
| --- | --- | --- |
| CatalogService (6) | [`CatalogContextApplication`](../../crates/cigar-daemon/src/catalog_context_application.rs) | `discoverSources`: `DiscoverSourcesRequest` -> `DiscoveryPlanResponse`<br>`ingestCatalog`: `IngestCatalogRequest` -> `IngestionReceiptResponse`<br>`getSourceStatus`: `SourceIdRequest` -> `SourceStatusResponse`<br>`queryCatalog`: `QueryCatalogRequest` -> `CatalogQueryResponse`<br>`batchAtoms`: `BatchAtomsRequest` -> `AtomBatchResponse`<br>`tombstoneAtom`: `AtomIdRequest` -> `MutationReceipt` |
| ContextService (8) | [`CatalogContextApplication`](../../crates/cigar-daemon/src/catalog_context_application.rs) | `createContextPlan`: `CreateContextPlanRequest` -> `ContextPlanResponse`<br>`compileContextBundle`: `CompileContextBundleRequest` -> `ContextBundle`<br>`compileContextDelta`: `CompileContextDeltaRequest` -> `ContextDeltaResponse`<br>`getContextBundle`: `BundleIdRequest` -> `ContextBundle`<br>`getContextBundleManifest`: `BundleIdRequest` -> `SelectionManifest`<br>`explainContextBundle`: `ExplainContextBundleRequest` -> `ContextExplanationResponse`<br>`materializeContextBundle`: `MaterializeContextBundleRequest` -> `MaterializationResponse`<br>`revalidateContextBundle`: `BundleIdRequest` -> `RevalidationResponse` |
| SpaceService (8) | [`SpaceHandoffApplication`](../../crates/cigar-daemon/src/space_handoff_adapters.rs) | `createSpace`: `CreateSpaceRequest` -> `ContextCommit`<br>`forkSpace`: `ForkSpaceRequest` -> `SpaceForkResponse`<br>`publishSpace`: `PublishSpaceRequest` -> `SpacePublishResponse`<br>`getSpaceLog`: `SpaceIdRequest` -> `SpaceLogResponse`<br>`subscribeSpaceEvents`: `SpaceIdRequest` -> `StreamOpenResponse`, events `SpaceEventPayload`<br>`createSpaceCheckpoint`: `CheckpointSpaceRequest` -> `SpaceCheckpointResponse`<br>`listSpaceConflicts`: `SpaceIdRequest` -> `ConflictListResponse`<br>`resolveSpaceConflict`: `ResolveSpaceConflictRequest` -> `ConflictResolutionResponse` |
| HandoffService (6) | [`SpaceHandoffApplication`](../../crates/cigar-daemon/src/space_handoff_adapters.rs) | `createHandoff`: `CreateHandoffRequest` -> `CreateHandoffResponse`<br>`previewHandoff`: `HandoffIdRequest` -> `HandoffPreviewResponse`<br>`acceptHandoff`: `AcceptHandoffRequest` -> `HandoffAcceptance`<br>`revokeHandoff`: `RevokeHandoffRequest` -> `MutationReceipt`<br>`recordHandoffResult`: `RecordHandoffResultRequest` -> `HandoffResultReceipt`<br>`mergeHandoff`: `MergeHandoffRequest` -> `HandoffMergeResponse` |
| EffectService (6) | [`EffectServiceHandlers`](../../crates/cigar-daemon/src/effect_replay_adapters.rs) plus `EffectWorkerProcessor` | `prepareEffect`: `PrepareEffectRequest` -> `EffectStatusResponse`<br>`authorizeEffect`: `AuthorizeEffectRequest` -> `EffectStatusResponse`<br>`dispatchEffect`: `EffectIdRequest` -> `EffectStatusResponse`<br>`getEffectStatus`: `EffectIdRequest` -> `EffectStatusResponse`<br>`reconcileEffect`: `EffectIdRequest` -> `EffectStatusResponse`<br>`compensateEffect`: `CompensateEffectRequest` -> `EffectStatusResponse` |
| ReplayService (4) | [`ReplayServiceHandlers`](../../crates/cigar-daemon/src/effect_replay_adapters.rs) and [`DurableReplayJobService`](../../crates/cigar-daemon/src/replay_jobs.rs) | `createReplay`: `CreateReplayRequest` -> `ReplayJobResponse`<br>`runObservationalReplay`: `ReplayIdRequest` -> `ReplayExecution`<br>`compareLiveReplay`: `CompareLiveReplayRequest` -> `ReplayExecution`<br>`getReplayCompleteness`: `ReplayIdRequest` -> `ReplayCompleteness` |
| OperationsService (7) | [`OperationalHandlers`](../../crates/cigar-daemon/src/composition.rs) | `getLiveness`: `EmptyRequest` -> `LivenessResponse`<br>`getReadiness`: `EmptyRequest` -> `ReadinessResponse`<br>`getVersion`: `EmptyRequest` -> `VersionResponse`<br>`getCapabilities`: `EmptyRequest` -> `CapabilitiesResponse`<br>`getConfiguration`: `EmptyRequest` -> `ConfigurationResponse`<br>`getDiagnostics`: `EmptyRequest` -> `DiagnosticsResponse`<br>`getMetrics`: `EmptyRequest` -> `MetricsResponse` |

## Authority boundaries

1. HTTP, gRPC, and embedded entry points converge on the same `RequestContext` and generated
   operation contract. Transport authentication proves a subject; it does not establish domain
   tenant, project, capability, policy, or record authority.
2. The typed adapter owns exact DTO decoding and path reconciliation. Request bodies cannot supply
   effective capabilities, policy decisions, repository access contexts, trusted clocks,
   server-generated event/receipt identities, connector permits, or worker claims.
3. [`ProductionFacade`](../../crates/cigar-daemon/src/application.rs) is the mandatory outer
   application boundary. It applies global/per-tenant quotas and durable mutation idempotency
   before dispatch into a complete registry.
4. [`ProductionDomainAuthority`](../../crates/cigar-daemon/src/production_authority.rs) maps the
   authenticated transport identity to a tenant and domain principal, then evaluates current
   compiled policy, projects, roles, exact effect rules, revocations, key state, and decision
   lifetime. It implements the catalog/context, space/handoff, effect API, effect-worker, merge,
   tenant-enumeration, and operator authority traits. Missing or inconsistent authority fails
   closed.
5. Catalog/context handlers derive the authorized partition and contract scope server-side. Space
   and handoff handlers reauthorize the addressed resource on every attempt; the event stream also
   reauthorizes every poll. Handoff acceptance recompiles under attenuated recipient authority,
   and merge mappings come from the trusted merge planner.
6. `dispatchEffect` durably claims work and only sends a bounded wakeup. The durable worker reloads
   the exact record, rechecks revision, shutdown gate, current policy, deadline, approval, and
   protected argument binding immediately before connector entry. Unknown outcomes enter the
   reconciliation path instead of being retried as a fresh mutation.
7. Replay handlers resolve the tenant and requester from the authenticated context. Live
   comparison requires a tenant-bound durable one-use authorization; callers cannot construct a
   `LiveReplayAuthorization` through an operation DTO.
8. Operational handlers expose typed, content-safe projections of runtime state. They do not
   serialize `DaemonConfig`, secrets, injected dependencies, or protected repository contents.

## Durable state ownership

| State | Authoritative persistence and restart behavior |
| --- | --- |
| Catalog and context | `SqliteStore` owns atoms, edges, bundles, revisions, and catalog outbox records. The service-repository namespaces `catalog.source-config.v1`, `catalog.discovery-plan.v1`, `context.compile-plan.v1`, and `context.bundle-index.v1` retain source and compile metadata. Strict production source configuration reattaches filesystem/Git connectors at bootstrap. |
| Retrieval index | `RepositoryCatalogIndex` rebuilds the disposable in-process generation from durable catalog outbox truth before readiness opens and advances it through the durable worker poll path. The generation itself is not treated as primary state. |
| Spaces and handoffs | [`DurableContextSpaceService` and `DurableHandoffService`](../../crates/cigar-daemon/src/durable_snapshot.rs) retain tenant-separated, bounded, chunked snapshots with a CAS-published root. Commits, events, checkpoints, conflicts and resolutions, capsules, acceptances, revocations, child results, and merges survive service reconstruction. |
| Effects | `EffectEngine` stores tenant-scoped effect records, state-machine revisions, attempts, approvals, compensation links, reconciliation reports, and outbox claims in the repository. Protected connector argument documents live in the encrypted tenant blob repository and are digest/media-type/schema checked before preparation and restaged only by a claimed worker. |
| Replay | [`DurableReplayArchive`](../../crates/cigar-daemon/src/durable_replay.rs) stores decisions, chunked artifacts, executions, and one-use reservations. `replay.job.v1`, `replay.live-draft.v1`, and `replay.live-authorization.v1` service records retain job and live authorization state. |
| Cross-operation idempotency | [`DurableIdempotencyRepository`](../../crates/cigar-daemon/src/durable_idempotency.rs) retains normalized mutation bindings and exact responses. Indeterminate mutation failures retain their reservation rather than reopening unsafe execution. |
| Operational projections | Liveness, readiness, version, capabilities, safe configuration, diagnostics, and metrics are derived from current runtime state. They are projections, not a second domain store. |

[`compose_production_server`](../../crates/cigar-daemon/src/production_bootstrap.rs) constructs these
owners from the validated configuration, encrypted keystore, compiled policy, authority document,
SQLite metadata repository, encrypted blob repository, source/effect registries, mandatory index,
workers, and readiness checks before a listener can bind.

## Deliberate composition limits and later packets

These limits do not change the exact-45 ownership above, and this section is not a waiver of any
remaining WP14 gate.

- The stock standalone composition injects `RecordedOnlyReplayServices`. A local macOS embedding
  can select the reviewed `cigar.production-live-replay.tenant-bound.v1` profile only through
  `compose_production_server_with_live_replay`, supplying an explicit authorization repository and
  a complete tenant-bound verifier/provider/effect-gate factory. The composer admits only active
  authority-document tenants; the engine consumes one-use current authorization and rejects effect
  identities retained by the source decision. No daemon setting or environment fallback enables
  this path. Provider-specific host qualification remains owned by WP17.
- The built-in effect registry supports demo issue, confined filesystem, and idempotent HTTPS
  connector families. HTTPS composition requires an explicit bounded `HttpTransport`; the stock
  bootstrap supplies none and therefore fails closed if that connector is enabled.
- The mandatory catalog index is a restart-rebuilt in-process projection over local durable truth.
  PostgreSQL, object storage, shared wakeups, shared migrations, rolling deployment, and the shared
  scale profile belong to WP18; enabling shared transport authentication does not imply those
  storage claims.
- User-facing command coverage belongs to WP15, generated SDK parity to WP16, Claude/MCP/hooks to
  WP17, exhaustive conformance/security/chaos qualification to WP19, demos and CIGARBench to WP20,
  packaging and operational exercises to WP21, and release-candidate qualification to WP22.

## Evidence anchors

- [`typed_payload_contract.rs`](../../crates/cigar-api/tests/typed_payload_contract.rs) proves the
  payload manifest and Rust registry contain the same exact 45 identities, exercises canonical
  DTO round trips, and rejects unknown, duplicate, noncanonical, oversized, wrong-operation, and
  path-conflicting payloads.
- [`production_transport_differential.rs`](../../crates/cigar-daemon/src/production_transport_differential.rs)
  statically proves every generated identity has a concrete production handler of the correct
  unary/stream kind and compares a real durable mutation/read across embedded, HTTP, and gRPC.
- Handler-family tests in
  [`catalog_context_application.rs`](../../crates/cigar-daemon/src/catalog_context_application.rs),
  [`space_handoff_adapters.rs`](../../crates/cigar-daemon/src/space_handoff_adapters.rs), and
  [`effect_replay_adapters.rs`](../../crates/cigar-daemon/src/effect_replay_adapters.rs) exercise
  dry-run behavior, current authorization, restart/reopen, durable effects, reconciliation, replay
  jobs, pagination, conflicts, and stream reauthorization against concrete services.
