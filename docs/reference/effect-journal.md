# Effect journal and connector contract

`cigar-effects` is the intent-first boundary for external mutation. A connector call is unreachable
until the exact intent, current authorization, optional approval, attempt number, fencing token, and
outbox wakeup have been committed. The kernel treats connector errors, panics, timeouts, partial
writes, response loss, and receipt-persistence loss as ambiguous unless non-execution is proven.

## Durable record

Each logical effect has one opaque, integrity-checked current record and an append-only event chain.
Version zero is a durable `Prepared` intent and has no synthetic transition event. Every later
version adds exactly one event whose sequence equals the new effect version and whose digest binds
the effect, prior version and state, target state, actor, payload, prior event digest, and timestamp.
The store publishes the next record, event, and optional outbox message in one optimistic
transaction. Reads compare the journal stored beside the projection with the repository event list
and quarantine any digest, sequence, prior-state, or projection mismatch as `CorruptJournal`.

Production records additionally carry an Ed25519 proof issued by the tenant's current signing
authority over domain-separated tenant identity and exact canonical record bytes. Reads first
verify the seal digest, then the signature and current tenant/key-revocation authority. API
handlers, effect workers, and startup recovery share this same authenticator; none may substitute a
process-local key in production.

Every successfully observed projection version, including prepared version zero, advances a
separate `(tenant, effect)` checkpoint that permanently binds the first intent digest. A lower
version, an intent swap, or a different authenticator at the same version fails closed. The bounded
canonical checkpoint document is reloaded and updated under a cross-process exclusive file lock,
then replaced atomically after data `fsync` and followed by parent-directory `fsync`. On local
first boot it may be created only after proving the effect store is empty. Shared deployments must
preprovision one owner-only, no-symlink, single-link checkpoint file on storage shared by all
replicas; its locks and durability operations must be coherent across nodes. The checkpoint and
effect repository are one restore consistency boundary and must never be rolled back independently.

The intent identity uses the frozen canonical effect envelope. Exact approvals and compensation
specifications use separate domain-framed digests. Public helpers compute the target, approval,
intent, and compensation digests needed by callers without duplicating serialization rules.

## State and authority

The closed protocol transitions are:

```text
Prepared -> PendingApproval | Authorized | Expired | Cancelled
PendingApproval -> Authorized | Rejected | Expired | Cancelled
Authorized -> Dispatching | Expired | Cancelled
Dispatching -> Succeeded | Failed | Unknown
Unknown -> Unknown | Succeeded | Failed | AuthorizedForRetry | ManualResolution
AuthorizedForRetry -> Dispatching | Expired | Cancelled
Succeeded -> CompensationPending -> Compensating
Compensating -> Compensated | CompensationFailed | Unknown
```

`ProposeEffect` permits intent preparation, approval requests, and safe pre-send cancellation.
Authorization and the immediate pre-send check require policy allowance, `ApproveEffect`, and the
intent's exact `required_capability`. Reconciliation and manual resolution require
`ReconcileEffect`. High and critical effects accept only an exact unexpired human approval bound to
the intent, target, risk, and source bundle. Time boundaries are inclusive at creation/approval and
exclusive at expiry.

## Claim, dispatch, and recovery

`claim_dispatch` uses optimistic effect-version comparison so two workers cannot both win. It adds
one monotonic attempt and fence, records the semantic outbox claim, appends `Dispatching`, and
commits a generic wakeup atomically. The returned `DispatchPermit` is opaque and non-cloneable.
`dispatch` reloads the durable record, verifies the permit and current connector declaration,
rechecks policy, capability, approval, intent expiry, attempt deadline, and exact preconditions, and
only then invokes the connector.

The connector-facing `DispatchContext` is also sealed: external code can inspect it only through
read-only getters and cannot construct one to call a connector around the journal. Reference
connector mutation tests therefore go through `EffectEngine`, the durable claim, and the opaque
permit.

If a worker dies after the durable claim, startup recovery projects the attempt to visible
`Unknown`; it never silently reclaims and sends. A definitive result stores one receipt per attempt.
An error after a possible request byte or before a durable receipt remains `Unknown` for explicit
reconciliation.

## Retry and reconciliation

The connector descriptor freezes each operation's safety properties at registration. A later
descriptor change fails before send. An intent using `SameKeyIdempotent` is rejected unless the
operation declares exact same-key idempotency. An intent using `ReconcileBeforeRetry` is rejected
unless lookup is supported.

`Unknown` never transitions directly back to `Dispatching`. Same-key retry first requires an
audited `AuthorizedForRetry` transition and remains bounded by the intent's maximum attempts.
Non-idempotent retry requires a persisted reconciliation report proving non-execution. Confirmed
success or failure becomes definitive; weak or unavailable lookup appends an inconclusive report,
keeps `Unknown`, records a bounded future certainty-window boundary, and performs no dispatch.
Connector errors, panics, and invalid past certainty windows take the same durable inconclusive
path. A human may record `ManualResolution`, but the API does not infer success from that operator
action.

## Compensation

Compensation is a distinct prepared intent whose connector, operation, argument digest, and
protected arguments exactly match the original `CompensationSpec`. Linking it moves a succeeded
original to `CompensationPending`; the child must independently reach `Authorized` before the
original becomes `Compensating`. The original then projects only the child's definitive success,
definitive failure, or explicit unknown. The connector SDK deliberately has no direct
`compensate` method.

## Storage and migrations

The checksum-frozen SQLite v1 migration contains dedicated effect intent, attempt, receipt, event,
outbox, and lease tables. The current implementation's canonical recovery source is the
checksum-protected MVCC state snapshot containing opaque effect envelopes; the effect tables are
disposable projections for later daemon query workers. SQLite runs WAL with `synchronous=FULL`.
Effect-envelope fields added during the pre-v1 packet use decode defaults so prior empty snapshots
remain readable.

## Reference connectors and fault qualification

Reference connectors are hermetic. They demonstrate a deterministic issue service, restricted-root
filesystem writes, injected-transport idempotent HTTP, and GitHub-style marker reconciliation
without making live network calls. The stable `effect.v1.*` crash points and EFX-C01 through C24
reference model are used by the WP12 crash harness. Fast tests run the complete boundary matrix and
a deterministic 100,000-operation logical-effect campaign; process-isolated crash qualification
uses the same stable point identifiers.
