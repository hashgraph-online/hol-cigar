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
Local format-two backup captures the checkpoint while both the SQLite writer exclusion and
checkpoint lock are held, then signs it in the same exact file inventory as the consistent database
snapshot. Verification rejects missing, extra, stale, or substituted checkpoint entries. Restore
requires the archived checkpoint to equal current external truth and holds that lock throughout
copy and publication; it never overwrites the monotonic file. Operators must stop effect writers
before activating the separately restored recovery target.

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

Connector entry consumes the exact attempt through an exclusive idempotency owner in the same
repository transaction that closes its outbox claim and advances the durable projection to
`Unknown`. No connector call happens if that ownership transaction loses its revision race. Once
the transaction commits, no second worker can reconstruct a sending permit: the effect is already
ambiguous until the later receipt transition proves a definitive result. This deliberately places
the durable ambiguity boundary before the remote mutation, covering process death immediately
before the first request byte as well as death after a possible remote commit.

The connector-facing `DispatchContext` is also sealed: external code can inspect it only through
read-only getters and cannot construct one to call a connector around the journal. Reference
connector mutation tests therefore go through `EffectEngine`, the durable claim, and the opaque
permit.

If a worker dies after the durable claim, startup recovery projects the attempt to visible
`Unknown`; it never silently reclaims and sends. A definitive result stores one receipt per attempt.
An error after a possible request byte or before a durable receipt remains `Unknown` for explicit
reconciliation.

## Production daemon boundary

The typed `dispatchEffect` handler never calls a connector. It checks the caller's expected
revision and current server-side policy, commits the claim, attempt, fence, journal event, semantic
outbox entry, and generic wakeup, then queues only a best-effort latency hint. A lost in-memory
wakeup does not lose work because the durable outbox remains the worker's source of truth.

The worker reloads that exact tenant record and revision, reconstructs its permit only from the
durable `Dispatching` attempt, and stages protected arguments only after the claim exists. It
resolves current worker policy before staging and again after staging with a fresh trusted time;
the actor must remain identical. Revocation, approval expiry, intent expiry, or attempt-deadline
expiry is finalized without connector entry. An atomic shutdown/drain gate linearizes immediately
before `EffectEngine::dispatch`, where the kernel repeats the permit, authority, time, descriptor,
and precondition checks before consuming connector ownership.

The reconciliation worker follows the same reload, expected-revision, current-policy,
protected-argument, fresh-time, and shutdown-gate sequence. It accepts only `Unknown` records whose
registered operation supports reconciliation and whose certainty window is due. Reconciliation
calls only the connector's lookup path; it cannot dispatch another mutation.

### Stock macOS HTTPS transport

Development source now includes one disabled-by-default stock transport for local macOS
`idempotent_http` connectors. It is not part of the initial beta and shared-mode composition
rejects it. Enabling one connector requires the exact `cigar.idempotent-effect-http.v1` provider
protocol, one canonical HTTPS endpoint, sorted unique explicit public IP pins, bounded connect and
whole-request timeouts, a bounded response size, and an opaque handle naming an owner-private
credential document. Each connector receives a separately constructed endpoint-bound transport;
one transport is never reused for a different origin.

The endpoint rejects user information, IP-literal and internal/local names, noncanonical case or
encoding, control characters, traversal, queries, and fragments. The client performs no ambient
DNS lookup: it dials only the explicit pins while preserving the configured DNS hostname for the
platform TLS chain and hostname verifier. Redirects, proxy discovery, referrers, automatic retries,
transparent decompression, and idle connection reuse are disabled. Request and response bodies,
connect establishment, the complete request, and the caller's earlier attempt deadline all retain
independent bounds. Daemon shutdown cancels before send as definitely not sent and conservatively
classifies cancellation or timeout after execution starts as ambiguous.

The credential file uses strict schema `cigar.scoped-http-credential.v1`. It binds the opaque
handle, exact HTTPS origin, one project ID, one resource ID, an exclusive validity interval, and a
bearer token. The file is reread through the descriptor-relative no-follow owner-only boundary at
startup and before every mutation or lookup. Credential-file buffers, parsed token strings, and
temporary bearer assembly buffers are zeroized; the unavoidable request-header copy is scoped to
one request. Debug and error surfaces contain neither token, handle, file path, request body, nor
response body. The staged body must use
`application/vnd.cigar.scoped-effect-request+json`, schema
`cigar.scoped-effect-request.v1`, and the same project/resource scope as current authorization and
the credential.

Dispatch sends POST or PUT with the durable same-key identity and exact request-binding headers.
Lookup uses GET on the same endpoint and never resends the mutation. A provider response is accepted
only for HTTP 200, exact media type `application/vnd.cigar.effect-result+json`, strict schema
`cigar.idempotent-effect-result.v1`, and the request binding computed locally. Dispatch accepts only
`succeeded`, `rejected`, or `ambiguous`; lookup accepts only `confirmed_success`,
`confirmed_failure`, `proven_not_executed`, or `inconclusive`. Wrong-channel, malformed, oversized,
redirect, binding-mismatched, or transport-failed observations remain ambiguous/inconclusive. The
selected provider protocol is an explicit operator assertion that the endpoint atomically
coalesces the same idempotency key and implements this lookup contract; a generic REST endpoint is
not compatible.

Hermetic tests exercise configuration closure, public pin validation, credential scope and file
permissions, cancellation classification, strict dispatch-versus-lookup outcomes, and bootstrap
mode gating. A local two-certificate TLS server proves trusted-chain and hostname enforcement,
rejects a wrong hostname and wrong trust anchor, and proves a 302 is returned rather than followed.
These source tests do not by themselves qualify any third-party provider or installed artifact.

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

Reference connectors remain hermetic. They demonstrate a deterministic issue service,
restricted-root filesystem writes, injected-transport idempotent HTTP, and GitHub-style marker
reconciliation without making live network calls. The daemon's separately documented stock macOS
transport is qualified by local TLS and injected-executor tests, never by the reference connector
suite. The stable `effect.v1.*` crash points and EFX-C01 through C24
reference model are used by the WP12 crash harness. Fast tests run the complete boundary matrix and
a deterministic 100,000-operation possible-remote-commit campaign; process-isolated crash
qualification kills and freshly recovers one real child at every stable point identifier. The
campaign asserts zero duplicate logical effects and zero blind redispatches. A real SQLite
failpoint also covers remote success followed by receipt-transaction loss, database reopen,
explicit `Unknown`, and reconciliation without a duplicate remote object.
