# Decision capture and replay

CIGAR replay is reconstruction from an immutable, observable decision archive. It is not a request
to recover chain-of-thought, rerun against whatever data is current, or reuse an old effect approval.
The source decision remains unchanged and every replay has a new execution identity.

## What capture seals

`DecisionCaptureBuilder` accepts the observable `DecisionRecord` together with the exact task, plan,
selection manifest, semantic bundle, provider-ready materialization, consumer invocation, recorded
observations, verification receipts, and referenced artifacts. Sealing checks all protocol records
and their cross-record bindings before storage:

- task, plan, bundle, and materialization digests agree with the decision;
- manifest and bundle semantic IDs recompute and the bundle names that exact manifest;
- final input and parameter bytes match the invocation envelope;
- runtime, consumer, adapter, tokenizer, materializer, tool-schema, and environment fingerprints are
  exact and agree across the decision and dependencies;
- output artifacts, claims, evidence, uncertainty, verification receipts, and effects are exactly
  the sorted references declared by the decision;
- selected manifest entries, bundle provenance, and retained source semantic IDs are the same set;
- one exact policy snapshot and index generation are retained, with the index fingerprint bound to
  the plan's catalog watermark;
- observations are contiguous, start at one, bind request and response digests plus the producing
  component fingerprint, and bind effect observations to an effect in the source decision; and
- verification-receipt identities and aggregate outcomes recompute.

Arbitrary output artifacts use their exact raw-byte multihash as their `VersionId`. Retained effect
artifacts must be canonical, valid `EffectIntent` records whose effect and bundle identities match
the archive metadata; caller-asserted IDs alone are insufficient.

The final `decision_id` is the SHA-256 multihash of deterministic CBOR for the decision archive with
only the self-referential ID removed. Exact artifacts use raw-byte SHA-256 multihashes. Manifest,
bundle, and verification-receipt semantic identities are verified with their existing canonical
profiles rather than replaced by an archive-specific interpretation.

The portable [replay v1 vector](../../schemas/vectors/replay-v1.json) independently fixes digest
reproduction across Rust, TypeScript, Python, and Go. Exact bundle and invocation bytes use raw
SHA-256 multihashes. The aggregate observation digest hashes response bytes in ordinal order, with
each response preceded by its unsigned 32-bit big-endian byte length. This framing distinguishes
sequences such as `["ab", "c"]` and `["a", "bc"]` without interpreting protected response content.

Task and final invocation input bytes must be non-empty. Empty invocation parameters and empty
recorded responses are valid exact byte strings. Protected artifact and response bytes are not
included in `Debug` output.

## Exact archive lookup

The archive interface has only two replay reads: an immutable decision archive by exact
content-derived `VersionId`, and an artifact by exact `ContentDigest`. There is no `current`,
`nearest`, or `latest` lookup and no provider callback on a miss. A CLI or API may resolve a
human-facing selector before constructing the request, but the replay request itself carries the
resolved immutable decision ID.

Every dependency declares both a public completeness category and its exact role. It also carries
the digest, applicable semantic or record identity, component fingerprint when relevant, and the
replay modes that require it. This lets one archive retain a complete evidence graph without making
every byte mandatory for every mode.

When an exact dependency is absent or its implementation cannot be reproduced, replay is
`Incomplete`. The public `ReplayCompleteness` report lists disjoint available and missing categories.
The detailed report can retain the exact role, requested digest, required mode, and one stable reason:
missing, digest mismatch, semantic mismatch, or unsupported. Missing data is never silently replaced
with a current source, policy, index, component, tool schema, or blob. A supplied artifact whose
bytes, semantic identity, or archive root do not verify is tampering and fails before replay.

## Four modes

### Evidence reproduction

Evidence reproduction verifies the exact retained compilation and decision evidence: sources and
blobs, policy snapshot, index generation, manifest, bundle, output evidence, and verification
receipts required by the archive. It performs no model, consumer, tool, connector, effect, or network
call. A complete execution has no observation digest; it may include a reconstructed-input digest if
the implementation also reconstructed those bytes.

### Invocation reproduction

Invocation reproduction reconstructs the exact final input bytes and checks the exact parameters,
materialization, runtime and consumer, provider adapter, tool schemas, and declared environment. It
returns those protected bytes and fingerprints as one `ReconstructedInvocation` and does not invoke
any component. A complete execution reports the reconstructed-input digest and no observation
digest.

### Observational replay

Observational replay reconstructs the invocation, then substitutes the captured consumer, tool,
connector, and effect responses. `RecordedProviderTape` accepts only the next one-based entry and
matches all of its observable identity: kind, request digest, provider fingerprint, optional subject,
and protected response digest. A mismatch leaves the next entry unconsumed; missing or extra entries
prevent successful completion.

The tape exposes no live call or fallback method. Non-live execution also runs under an injected deny
transport and, for qualification, an operating-system network-denial sandbox. Connector test doubles
panic if reached. Completion requires both the reconstructed-input digest and an ordered observation
digest, with zero network, model, tool, connector, or effect dispatch calls.

### Live comparison

Live comparison is the only mode allowed to invoke configured dependencies. It is always a new
execution and requires an exact live-authorization digest bound to the request, source decision, and
requester. Before any live call, the service must validate the authorization under current policy,
check its validity window using the verifier's trusted clock, and atomically reserve both its nonce
and digest against reuse. Merely deserializing a valid `ReplayRequest` does not satisfy those checks.
`ReplayReservationLedger` is the persistence boundary for execution and authorization reservations;
daemon deployments use a durable implementation, while the reference in-memory ledger is intended
for embedded and test use.

Effects are simulated unless `simulate_effects` is explicitly false. Non-simulated live comparison
must name a non-empty sorted set of new effect-intent IDs. Each intent passes through the normal
intent-first effect kernel with current capability, policy, risk, approval, expiry, journal, and
dispatch checks. The source decision's effects, approvals, attempts, receipts, and reconciliation
records remain evidence only; none can authorize or mutate the live execution.

The live provider receives the complete reconstructed invocation, including parameters,
materialization, tool schemas, environment records, and component artifacts. Its observation
framing, dimension diff, and terminal protocol record are validated before the effect gate may
dispatch. The gate must atomically reject an effect ID already present in the global journal and
issue fresh WP12 dispatch authority; a replay authorization is not an effect dispatch permit.

Live completion reports both reconstructed-input and observation digests. Enabling egress or effect
dispatch is an outcome of the verified live boundary, not authority conferred by the corresponding
Boolean fields in `ReplayExecution`.

## Completeness and comparison

`ReplayCompleteness` classifies source, blob, policy, index, manifest, bundle, tokenizer, adapter,
consumer, tool schema, and environment dependencies. Available and missing sets are sorted, unique,
and disjoint. `Complete` means the missing set is empty; `Incomplete` names at least one category.

`ReplayDiff` compares seven dimensions independently:

| Dimension | What it isolates |
| --- | --- |
| Semantic context | Exact selected meaning and governed context |
| Materialization | Provider-ready bytes |
| Components | Runtime, consumer, adapter, tokenizer, materializer, tools, and environment |
| Output claims | Assertions produced by the execution |
| Verification | Evidence-backed check results |
| Effect plan | Proposed logical effects, not dispatch authority |
| Observations | Model, tool, connector, and effect responses |

Each dimension is equal, different, or unavailable. Observation variance alone does not mark the
compiler nondeterministic. A diff cannot claim compiler determinism when semantic context or
materialization differs.

## Security and resource limits

Replay records and manifests are bounded to 10,000 references or observations. A retained artifact
is limited to 64 MiB and a capture or recorded provider tape to 256 MiB aggregate. Verification
receipts contain 1 through 10,000 sorted unique checks, with names limited to 512 UTF-8 bytes.
Arithmetic is checked and archive collisions fail instead of overwriting different content.

Daemon replay requests carry one linked lifetime through blocking admission, durable archive reads,
reservation writes, engine calls, live verification/provider/effect boundaries, and terminal job
publication. A `ReplayContext` combines the request cancellation observer with one absolute monotonic
deadline. The blocking pool invokes a cancellation callback on caller cancellation, expiry, queue
exit, and future drop; durable replay components share that exact store token rather than creating
fresh defaults. Active checks surround every potentially blocking boundary and immediately precede
effect dispatch and terminal commit, so a result returned after cancellation is quarantined.

An injected synchronous dependency must still cooperate with that context or run behind a terminable
process boundary to guarantee prompt permit release; dropping a running blocking thread is not safe.
The checked-in production live-replay factory remains deny-only. Regardless of provider behavior, a
late result cannot authorize an effect or publish replay completion after its authoritative lifetime.

Errors use stable, content-free categories. Diagnostic formatting reports counts, digests,
fingerprints, media types, and lengths but not protected task, invocation, artifact, or response
bytes. The archive is immutable by identity: storing identical content is idempotent, while binding
the same decision or artifact identity to different content is a collision.

The OS sandbox is defense in depth around a structurally non-live API. Conversely,
`egress_permitted = false` is an auditable execution claim, not a sandbox implementation. Both the
structural boundary and the OS-level no-egress qualification are required for the non-live guarantee.
