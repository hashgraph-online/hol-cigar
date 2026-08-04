# Proposal: Atomic context compilation and revision administration vNext

- Status: Future / non-selected for Honey 0.9.2
- Date: 2026-07-20
- Earliest protocol line: a new version after `cigar.context.v1`
- Compatibility rule: do not add any operation or payload below to the frozen v1 registry

## Summary

A future protocol should expose one idempotent atomic context-compilation mutation, separate
semantic artifact identity from execution correlation, and expose authenticated revision-maintenance
preview/execute/status operations. Honey 0.9.2 continues to support the granular v1 sequence and
implements only internal storage, retrieval, telemetry, and local offline administration repairs.

This document is design input, not a shipping API contract. Operation names, package version,
schemas, generators, SDKs, canonical vectors, and compatibility windows require a separate protocol
authority decision.

## Motivation

The current Hiero integration performs eight v1 calls around a compilation and can produce four
durable mutations. Run/job correlation inside the complete current request identity also prevents
safe reuse of semantically identical compilation artifacts. Client-side batching cannot provide an
atomic outcome or safely reconcile an ambiguous transport failure.

Revision migration/compaction similarly needs preview binding, owner authorization, stable recovery
errors, and signed receipts, but adding those as v1 RPCs would violate the frozen 45-operation and
70-payload registry.

## Proposed semantic and execution identities

### Semantic compilation identity

`SemanticCompilationIdentityVNext` is the digest of a strict canonical record containing:

- normalized governed context contract and explicit semantic extensions;
- tenant/privacy domain commitment and authorization subject/authority commitment;
- exact catalog watermark and required snapshot/revision;
- policy and disclosure digests;
- retrieval plan, index generation, and optional embedding model/generation fingerprints;
- compiler profile and content-equivalence/diversity profile digests;
- tokenizer, target, materializer, and rendering profile fingerprints; and
- input/source snapshot identities required by the normalized contract.

It excludes only fields explicitly typed as execution correlation:

- run, job, trace, span, and request transport IDs;
- wall-clock submission/receipt times;
- retry/attempt number; and
- observer/export routing that cannot change semantic output or authorization.

Arbitrary/unknown extensions are semantic by default. A client or server must not guess that an
unknown field is correlation. Unknown semantic extensions either participate in the identity under
the versioned canonical extension contract or cause fail-closed bypass/rejection.

### Execution receipt

Every call produces a unique signed `CompilationExecutionReceiptVNext` binding:

- semantic identity and resulting or reused artifact/bundle/manifest/materialization digests;
- caller authority, privacy domain, run/job/trace/span correlation, attempt, and observed time;
- idempotency scope/key/request digest and transport reconciliation state;
- exact server/store revision, policy/catalog watermarks, implementation/source identity, and
  operation version;
- whether the artifact was newly compiled or reused and one closed reuse/bypass reason; and
- parent/child receipt digests and signature/provider identity.

Reused bytes therefore retain one stable semantic identity while every execution remains separately
auditable. Execution correlation never mutates the shared artifact.

## Atomic compilation operation

Working name: `CompileContextAtomicVNext`.

### Request

The strict request contains:

- normalized governed contract or its canonical bytes and digest;
- exact target/materialization profile;
- requested validation and final revalidation policy, including fail-closed required checks;
- catalog/policy/retrieval/compiler/tokenizer/materializer pins or an explicit server-freeze request
  with required consistency;
- typed execution correlation;
- idempotency identity bound to the complete normalized operation request;
- optional expected repository revision and deadline/cancellation capability; and
- explicit output selection bounded to artifact references and authorized explanations.

Protected content is referenced through existing governed source identities; it is not copied into
untyped extensions.

### Transaction

On a semantic miss, one logical operation:

1. authenticates caller, idempotency, expected revision, and all pins;
2. freezes the catalog/policy/index snapshot;
3. plans requirement-aware retrieval and governance;
4. compiles and content-equivalence groups deterministically;
5. seals bundle, plan, complete protected manifest, citations, and invalidation roots;
6. materializes the requested target deterministically;
7. stages artifact records, execution receipt, causal outbox/effect entries, and idempotency result;
8. publishes at most one repository commit; and
9. returns a deterministic parent receipt plus bounded child receipts/artifact references.

No externally visible partial bundle, manifest, materialization, cache entry, receipt, or revision can
escape. A validation failure commits nothing except a separately specified security audit record
whose semantics and ambiguity are explicit.

On a valid semantic hit, the operation does not rewrite the artifact. It reauthenticates all current
policy/disclosure/authorization/watermark/tokenizer/materializer/compiler/invalidation conditions and
records only the new execution receipt and exact idempotency result. The target expectation is no
artifact rewrite and no semantic repository commit; whether the execution receipt uses a separate
append-only evidence commit must be made explicit by the future store/API contract.

### Response

`AtomicContextCompilationResultVNext` contains or references, under explicit bounded disclosure, the
typed `ContextPlan`, `ContextBundle`, `SelectionManifest`, `MaterializedContext`, and final
`RevalidationResult` records. It also contains:

- closed result state (`compiled`, `reused`, or stable failure/unknown);
- semantic identity;
- exact artifact identities for every returned/referenced record;
- execution receipt, one parent receipt, and bounded deterministic child receipts for plan,
  compile/seal, materialization, and revalidation;
- resulting store revision and exact consistency watermark; and
- stable content-free cache/reuse reason.

Child receipt identity is derived from the parent semantic identity, parent receipt identity, closed
stage name, stage ordinal, exact input/output artifact identities, and implementation version. It is
not derived from completion timing or worker scheduling, so retry/reconciliation reproduces the same
child set for the same committed operation.

It never returns protected denied candidates, arbitrary server diagnostics, or chain-of-thought.

### Idempotency and ambiguous outcomes

Idempotency binds operation scope, secret-safe key, and normalized complete request digest. Repeating
the same identity returns the prior response/receipt; using the same key for different semantics fails
closed. After timeout or transport loss, clients reconcile by idempotency identity through a bounded
status/read operation. They do not resubmit a mutation with a new key or infer failure from silence.

Stable outcome states distinguish:

- definitely not committed;
- committed with complete receipt;
- unknown pending reconciliation; and
- known rejected due to key/semantic mismatch.

### Commit and cache expectations

The future qualification model is explicit:

| Path | Semantic artifact commits | Artifact rewrites | Required execution evidence |
|---|---:|---:|---|
| validated miss | at most one repository commit | one newly staged artifact set | one parent plus deterministic children |
| fully valid hit | zero | zero | one new execution receipt and exact idempotency result |
| rejection before commit | zero | zero | only a separately specified security audit event, if policy requires it |
| ambiguous transport outcome | no second mutation | zero until status is known | reconcile the original idempotency identity |

The receipt/evidence journal transaction boundary remains an explicit selection decision, but it
cannot weaken the zero-artifact-rewrite hit rule or permit more than one semantic repository commit
on a miss.

## Cache and reuse rules

A semantic artifact is reusable only when all identity fields and current invalidation roots match
and authorization/disclosure is freshly evaluated. Reuse is partitioned by privacy domain and cannot
cross tenant or policy boundaries. It is bypassed for:

- policy, disclosure, authorization, watermark, source-version, index, retrieval-plan, tokenizer,
  materializer, compiler, target, or embedding mismatch;
- invalidated member/provenance/dependency;
- unknown semantic extension;
- uncertain authority or stale readiness lease; or
- corrupted/missing artifact or receipt.

Closed reason codes are part of the future schema. Metrics may count them but never label by semantic
identity, tenant, source, run, job, trace, path, or content.

## Required negative vectors

The future conformance suite includes canonical negative cases for:

- same execution correlation but different semantic contract;
- different execution correlation but identical semantic inputs;
- policy or disclosure digest mismatch;
- catalog watermark/revision mismatch;
- authorization subject/privacy-domain mismatch;
- tokenizer/materializer/compiler/target mismatch;
- retrieval/index/embedding generation mismatch;
- unknown extension and extension reordering/duplicate key;
- stale invalidation root;
- idempotency key reused with different request digest;
- ambiguous timeout followed by reconciliation; and
- protected explanation/disposition disclosure attempt.

## Revision administration operations

Working names:

- `PreviewRevisionMaintenanceVNext`;
- `ExecuteRevisionMaintenanceVNext`; and
- `GetRevisionMaintenanceStatusVNext`.

These operations cover revision compaction/retention only. Blob garbage collection, backup, restore,
and migration remain distinct typed operations and receipts.

### Preview

Preview authenticates owner/admin authority and binds:

- exact store path/instance commitment, format/profile, head revision, chain head, and active writer
  lease state;
- effective retention count/age/physical-byte policy and minimum reconstructable range;
- every legal hold and active pin with authority/expiry;
- verified backup identity, restore-verification receipt, and age policy;
- candidate checkpoints/deltas/ranges and expected reconstructable post-range;
- expected logical/physical bytes, temporary/free-space proof, and capacity reserve;
- policy/tool/schema version, expiry, nonce, and signer identity; and
- expected semantic/catalog/chain roots after maintenance.

It returns a signed preview and no state mutation.

### Execute

Execute accepts exactly one unexpired signed preview and idempotency identity. Under exclusive writer
authority it rejects head, chain, policy, backup, pin/hold, free-space, path, tool, signer, or active-
writer drift before the first destructive boundary. It writes recoverable execution state, preserves
every pinned/reconstructable revision, verifies the result, and emits a signed receipt. A failed
post-verification keeps readiness closed and exposes stable recovery status.

### Status and stable errors

Status reconciles by operation/idempotency/preview identity and returns only closed states. Proposed
stable error families include:

- backup missing, stale, mismatched, or not restore-verified;
- legal hold or protected pin;
- insufficient space/capacity reserve;
- active writer or daemon lease;
- head/chain/policy/preview drift;
- preview expired or signer unauthorized;
- unsupported format/downgrade;
- interruption requiring resume;
- failed post-verification; and
- unknown outcome requiring reconciliation.

Diagnostics include only content-free effective retention count/age/physical-byte ceilings, pin and
legal-hold counts/reason classes, checkpoint cadence/count/bytes, delta count/bytes, reconstructable
range, head, and closed status.

## Protocol/version work required before selection

Selecting this proposal requires one coordinated change that:

1. chooses a new protocol/package version (`cigar.context.v2` or later) and compatibility window;
2. updates operation and payload authorities through their generators;
3. adds strict schemas and canonical valid/invalid/differential vectors;
4. regenerates TypeScript, Python, Rust, Go, MCP, daemon, CLI, and other client/server projections;
5. defines transport status and `UNKNOWN` reconciliation across every adapter;
6. adds old-client/new-server and new-client/old-server compatibility tests;
7. updates capability profiles, release gates, documentation, demos, and evidence schema; and
8. independently security-reviews atomic authorization, cache partitioning, receipt signing, and
   destructive administration.

## V1 compatibility

Honey 0.9.2 keeps all granular v1 operations and their current semantics. Downstream clients retain
the eight-call sequence where used and must not emulate atomicity by hiding partial outcomes or blind
retry. Execution correlation remains inside the current v1 contract digest. Local 0.9.1 maintenance
surfaces are offline administration, not public v1 RPCs.

Release generator checks must continue proving exactly seven v1 services, 45 operations, and 70
nominal payload types. Any execution correlation a caller places in current v1 contract extensions
therefore remains inside `contract_digest`; 0.9.1 does not reinterpret it as transport metadata.
The compatibility SDK key requires downstream callers to keep correlation outside semantic inputs.
Any owner decision to ship these operations requires a new product/protocol plan rather than
silently widening 0.9.1.

## Open decisions

- exact new package/version and operation names;
- whether execution receipt append is inside the atomic artifact transaction or a distinct evidence
  journal with a parent receipt;
- maximum atomic operation duration and transport cancellation semantics;
- status retention and receipt privacy/disclosure policy; and
- whether revision administration is local-only, mutually authenticated loopback, or remotely
  administered under a separate enterprise profile.
