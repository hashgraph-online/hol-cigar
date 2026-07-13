# Decision and replay records v1

This profile defines the observable decision, replay request, replay execution, completeness,
comparison, and verification-receipt records. It does not define or request hidden reasoning.
Structures reject unknown fields, and every schema-bearing record requires its exact `cigar.*.v1`
family.

## DecisionRecord

`DecisionRecord` contains only observable task, plan, bundle, materialization, runtime and consumer
fingerprints, output artifacts, asserted claims, evidence, uncertainty, verification receipts,
effects, integer usage, timing, and outcome. Hidden chain-of-thought, private model state, and an
untyped transcript have no field in this record.

The output-artifact, claim, evidence, uncertainty, verification-receipt, and effect collections are
sorted, unique, and limited to `MAX_REPLAY_REFERENCES` entries. Completion cannot precede start.
The protocol record calls `decision_id` content-derived; `cigar-replay` derives it from the sealed
decision archive using deterministic CBOR after excluding only the self-referential `decision_id`
field. The archive additionally binds the exact dependency manifest and retained artifacts.
Selected manifest versions, bundle provenance, and source dependency identities must agree. One
policy snapshot and one index generation are mandatory, and the index fingerprint equals the
plan's catalog watermark. Generic output-artifact IDs are their exact raw-byte multihashes; effect
dependencies are canonical `EffectIntent` records bound to their declared effect and bundle IDs.

`UsageRecord` uses unsigned integers for input tokens, output tokens, cached input tokens, and cost
in micros. No floating-point monetary or token value participates in the record.

## ReplayRequest

Every request names one exact content-derived `decision_id`, one unique `request_id`, the
authenticated requester, and one closed replay mode. Resolving an alias such as `latest` is outside
this record; it must produce a pinned `decision_id` before replay begins.

The request invariants are:

| Mode | Live authorization digest | `simulate_effects` | Authorized effect intents |
| --- | --- | --- | --- |
| Evidence reproduction | forbidden | `true` | empty |
| Invocation reproduction | forbidden | `true` | empty |
| Observational | forbidden | `true` | empty |
| Live comparison, simulated effects | required | `true` | empty |
| Live comparison, dispatch permitted | required | `false` | non-empty, sorted, and unique |

All effect-intent collections are bounded by `MAX_REPLAY_REFERENCES`. A live authorization digest
is an exact binding, not proof that authorization is valid. The live service separately verifies
the authorization's signature or policy decision, requester and request binding, validity window,
one-time semantics, and allowed operations at execution time.

## ReplayExecution

Each replay creates a new `execution_id` and references its request; it never changes the source
decision. `Running` has no completion time. `Complete`, `Failed`, and `Incomplete` have a completion
time that is not earlier than start.

Non-live executions set both `egress_permitted` and `effect_dispatch_permitted` to `false`.
`Complete` has no missing dependency categories, while `Incomplete` names at least one. A complete
execution exposes digests by mode as follows:

| Mode | Reconstructed input digest | Observation digest |
| --- | --- | --- |
| Evidence reproduction | optional | absent |
| Invocation reproduction | required | absent |
| Observational | required | required |
| Live comparison | required | required |

The evidence mode permits an input digest when evidence verification also reconstructed it, but it
never permits an observation digest. Permissions on a live execution report what the authorized
execution boundary enabled; they are not themselves authorization credentials.

Invocation-capable replay reconstructs the complete observable invocation: final input, parameter
bytes, provider-ready materialization, and exact runtime, consumer, adapter, tokenizer,
materializer, tool-schema, and environment artifacts. Protected bytes remain outside diagnostic
formatting.

The portable reproduction profile hashes exact bundle and invocation byte strings as raw SHA-256
multihashes (`0x12 0x20` rendered as lowercase `1220`, followed by the 32-byte digest). The aggregate
observation digest hashes recorded response byte strings in ordinal order, prefixing each with its
unsigned 32-bit big-endian byte length. Empty response byte strings are valid and contribute a zero
length frame. [The replay v1 vector](../../schemas/vectors/replay-v1.json) fixes these rules for
independent Rust, TypeScript, Python, and Go verification.

## Completeness

`ReplayCompleteness.available` and `.missing` contain sorted, unique, disjoint
`DependencyKind` values and are each limited to `MAX_REPLAY_REFERENCES` entries. The closed
categories are source, blob, policy, index, manifest, bundle, tokenizer, adapter, consumer, tool
schema, and environment.

Completeness is an exact-evidence claim. A missing digest or exact implementation is reported as
missing; replay must not substitute a current source, policy, index, component, schema, or blob.
Digest or semantic-identity tampering is an integrity failure rather than an incomplete replay.

## ReplayDiff

`ReplayDiff` reports semantic context, materialization, components, output claims, verification,
effect plan, and provider/tool observations independently. Each dimension is `equal`, `different`,
or `unavailable`. `compiler_deterministic` cannot be `true` when semantic context or
materialization is `different`. Observation-only variance therefore does not imply compiler
nondeterminism.

## VerificationReceipt

A receipt has one verifier fingerprint, one semantic subject digest, a verification timestamp, and
between one and `MAX_VERIFICATION_CHECKS` checks. Check names are non-empty, sorted, unique, and at
most `MAX_VERIFICATION_NAME_BYTES` UTF-8 bytes. Each check binds an evidence digest.

The aggregate outcome is derived exactly: any failed check makes the receipt failed; otherwise any
indeterminate check makes it indeterminate; otherwise it passed. A contradictory aggregate is
invalid.

## Execution security boundary

Evidence and invocation reproduction only inspect retained artifacts. Observational replay uses
the ordered recorded consumer, tool, connector, and effect transcript. These non-live modes expose
no live-provider fallback, deny network egress at the operating-system boundary, and cannot dispatch
effects.

Live comparison is a new execution under fresh explicit authorization. Recorded source effects
remain observations. Any actual mutation requires a new effect intent, its own current policy and
capability check, and any required approval. A source decision's intent, approval, attempt, or
receipt is evidence only and cannot authorize the live execution.

The current authorization verifier supplies trusted time for the validity-window check. Both the
authorization nonce and digest have one-use semantics and are atomically reserved with the new
execution ID. Live output framing, comparison dimensions, and the terminal execution record are
validated before a separately authorized effect gate may dispatch. Durable services persist these
reservations; an in-memory ledger is sufficient only for embedded and hermetic test profiles.
