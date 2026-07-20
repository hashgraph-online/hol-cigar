# Materialization, governed caches, and exact deltas

WP09 converts a sealed semantic bundle into provider-ready bytes without changing its block set.
Callers supply one exact body for every block ID. Materialization rejects missing or extra bodies and
verifies each body against the block's SHA-256 multihash before rendering. JSON, Markdown, fact-set,
Claude prompt, and MCP profiles encode protected bodies with unpadded base64url; protected bytes are
never interpolated as delimiters, markup, role text, or lane metadata. This makes delimiter and bidi
payloads data rather than control syntax and prevents silent truncation or lane escape.

## Token accounting

`ExactTokenizer` is the only interface accepted by `materialize`. The production registry contains
two provider-neutral reference profiles:

- `cigar.reference-tokenizer.utf8-bytes.v1` validates strict UTF-8 and counts encoded bytes;
- `cigar.reference-tokenizer.unicode-scalars.v1` validates strict UTF-8 and counts Unicode scalar
  values.

Each fingerprint is derived from the profile identifier, strict-UTF-8 input rule, accounting unit,
empty-input rejection, and checked-u32 overflow rule. The exact digest constants and
`ReferenceTokenizerProfile::target_profile` construct the only matching tuple: provider
`cigar-reference`, the profile identifier as model family, and the immutable fingerprint. Resolution
is closed over that complete tuple: an unknown fingerprint, external provider, or cross-paired model
family returns unavailable, with no estimate or reference-profile substitution. Empty or malformed
UTF-8 input fails, and counts that cannot fit in `u32` fail rather than saturating.

These profiles are reference accounting algorithms only. They do not implement or approximate an
Anthropic, OpenAI, or other model/provider tokenizer, and they make no provider materialization or
qualification claim. The initial production-bootstrap integration is for the macOS development
cohort. External provider tokenizer profiles remain unsupported until their independently pinned
algorithm/configuration and qualification evidence exist.

`ByteTokenizer` and `UnicodeScalarTokenizer` remain low-level differential-test adapters whose
fingerprints are caller supplied. `ConservativeEstimator` returns a different
`ConservativeTokenEstimate` type with an explicit maximum error; estimates cannot satisfy the exact
materialization interface or an unknown exact fingerprint.

`TokenAccounting` preserves separate baseline, physical input, stable prefix, delta, deduplication,
extractive, structural, summary, provider-present omission, provider cache read/write, output
reserve, runtime reserve, estimated billable, and provider-reported billable fields. No field is
inferred from another after the provider reports usage.

## Cache governance

`GovernedCache` supports atom, transform, retrieval, plan, bundle, and materialization layers. Every
key includes tenant, disclosure domain, and an immutable input/configuration fingerprint. Every hit
must match the current policy digest and revocation epoch and pass a caller-supplied current
eligibility gate. A mismatch invalidates the entry. Entry digests detect memory or storage
corruption; `get_or_try_insert_with` quarantines the corrupt entry and stores a recomputed value.
Capacity is bounded by entry count and resident bytes with deterministic least-recently-used
eviction.

## Provider-present state and deltas

Provider-present observations bind an exact bundle to a provider session, target fingerprint, policy
digest, revocation epoch, monotonic observation sequence, and confidence. Reuse requires exact
confidence and current governance state. Session reset or compaction invalidates the whole session;
a target configuration change invalidates observations for the obsolete target.

`generate_delta` sorts content-derived additions and removals and seals the exact serialized protocol
record with a SHA-256 multihash. `apply_delta` verifies that digest, requires the exact base and target
identities, applies every operation once, and compares the reconstructed blocks and exact resulting
token count with the expected target. `apply_delta_verified` additionally returns an opaque
`AppliedDelta`; provider acknowledgements accept only this verified-application evidence and bind its
session, target fingerprint, base, target, delta digest, and observation sequence. Provider-present
state permits exact idempotent replay but rejects a changed observation whose sequence does not
strictly advance, preventing stale acknowledgement rollback. Physical overflow produces an explicit
repair request only when observed input tokens exceed the current non-zero target maximum.

## Daemon integration boundary

The local daemon uses the governed materialization cache only after it has rederived the opaque
authorization partition, revalidated policy and revocation state, reloaded every retained body, and
rechecked current body eligibility. The cache is process-local, bounded, integrity checked, and cold
after restart. Its key binds the tenant, disclosure partition, bundle, target profile, tokenizer,
materializer, and framing profile. Before returning a generated delta, the daemon applies it to the
exact retained base and verifies that it reproduces the retained target.

Downstream semantic request reuse is a separate compatibility concern. Honey 0.9.1 does not remove
correlation-like values from the frozen v1 contract digest or expose a new public cache operation.
The safe SDK key, exact mismatch gates, closed bypass reasons, and per-execution artifact binding are
specified in [`semantic-reuse-v1.md`](semantic-reuse-v1.md).

If exact framing exceeds `max_context_tokens`, the daemon constructs overflow evidence from the
validated `MaterializedContext`; callers cannot submit a repair record. The latest evidence is stored
in one tenant-scoped fenced worker checkpoint, which is mutable rather than an append-only service
record and therefore does not grow a key or immutable-version history per failure. A crashed lease
fails closed until its bounded lease expires; exact checkpoint replay is idempotent.

### Trusted provider-adapter lifecycle

The frozen public v1 registry remains exactly 45 operations and contains no provider-session
payload. Provider lifecycle state instead crosses a crate-internal
`cigar.trusted-provider-input.v1` boundary. Inputs are canonical JSON capped at 4 KiB and
HMAC-SHA-256 authenticated under one exact key ID. The authenticated record binds tenant, opaque
session digest, target fingerprint, provider generation, contiguous operation sequence, policy
digest, revocation epoch, issuance/expiry, and a closed action kind. Its lifetime is non-zero and at
most one hour. Debug output redacts the input, tag, session, target, action digest, and repair
identity. An adapter-key substitution, noncanonical encoding, tag or payload mutation, expired
record, cross-tenant use, policy change, or revocation-epoch change fails closed.

Session establishment starts at sequence one. Mutations must advance by exactly one; only an exact
action-digest replay at the current sequence is idempotent. Reset and compaction are distinct signed
actions, clear acknowledgement and present evidence, and require establishment of exactly the next
provider generation before reuse. A session also remains pinned to the key ID that established it.

Delta acknowledgement has no constructor that accepts caller-authored base, target, or delta
fields. The trusted signer and durable consumer both require the opaque `AppliedDelta` returned by
`apply_delta_verified`, and the authenticated commitments must equal that evidence. A successful
checkpoint stores the derived acknowledgement and exact-confidence provider-present observation
under the current target, policy, and revocation epoch. A delta following an existing observation
must use the observed bundle as its exact base.

Provider state is one tenant-scoped `cigar.provider-state.v1` fenced worker checkpoint, bounded to
32 sessions and 60,000 serialized bytes. Capacity rejects new live sessions; only sessions expired
under trusted time are pruned. Every transition validates the complete state, uses repository CAS
plus a digest-derived lease owner, checkpoints once, and releases the fence. A failed checkpoint
publishes no partial transition, a crashed claim can be resumed only by the same authenticated
action, and concurrent distinct actions at one sequence cannot both publish.

Repair preparation returns only an opaque reference to the exact overflow worker version and cursor
digest after rechecking target, policy, and revocation. Consumption rechecks that reference, stores
one global exact-consumption receipt, clears stale present/acknowledgement state, and returns the
daemon-derived `TargetOverflowRepairRequest` only after the receipt commits. A second session cannot
consume the same repair. Exact replay is reconstructed from the bounded receipt even if a newer
overflow has since become latest.

This boundary is intentionally not routed from HTTP, gRPC, CLI, idempotency keys, or any other
caller-controlled public-v1 input. A future installed provider adapter must hold the configured local
authority and invoke these typed methods directly; no public operation-registry expansion or
caller-asserted present state was introduced.
