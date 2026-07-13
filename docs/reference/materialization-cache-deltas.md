# Materialization, governed caches, and exact deltas

WP09 converts a sealed semantic bundle into provider-ready bytes without changing its block set.
Callers supply one exact body for every block ID. Materialization rejects missing or extra bodies and
verifies each body against the block's SHA-256 multihash before rendering. JSON, Markdown, fact-set,
Claude prompt, and MCP profiles encode protected bodies with unpadded base64url; protected bytes are
never interpolated as delimiters, markup, role text, or lane metadata. This makes delimiter and bidi
payloads data rather than control syntax and prevents silent truncation or lane escape.

## Token accounting

`ExactTokenizer` is the only interface accepted by `materialize`. The byte and Unicode-scalar
adapters demonstrate exact provider-specific implementations. `ConservativeEstimator` returns a
different `ConservativeTokenEstimate` type with an explicit maximum error; estimates cannot satisfy
the exact materialization interface.

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
token count with the expected target. A provider acknowledgement binds session, target fingerprint,
base, target, delta digest, and observation sequence. Physical overflow produces an explicit repair
request only when observed input tokens exceed the current non-zero target maximum.
