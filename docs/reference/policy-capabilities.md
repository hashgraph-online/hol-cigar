# Policy, capability, and redaction kernel

WP07 is the mandatory technical authorization boundary. Prompt text, retrieval score, an adapter
label, or a declarative allow rule cannot bypass it. Every protected operation supplies a normalized
metadata-only `PolicyRequest` and exact input digest. The same hard-gate kernel backs partition,
metadata, content, processor, bundle, handoff, and effect decisions.

## Evaluation and snapshots

Hard gates evaluate current tenant and project scope, principal status, verified delegated
capabilities, purpose and processor, classification/residency/egress, lifecycle and integrity,
world-valid and observation time, freshness, instruction authority, contract exclusions, target
modality, and effect constraints. A denial or quarantine is terminal for that request. High/critical
effects require a distinct approval, and operations marked as fenced require a current verified
fencing token.

The built-in profile is bounded canonical JSON or equivalent TOML. Rules have stable IDs,
dependencies, priorities, indexed selectors, actions, redaction paths, and content-free conditions.
Compilation rejects duplicates, missing dependencies, cycles, invalid pointers, unsupported schema
versions, and excess bounds. Rules are topologically ordered, then deterministically ordered by
priority and ID. Final precedence is `deny`, `quarantine`, `require_refresh`, `redact`,
`require_approval`, then `allow` regardless of evaluation order.

Installing a higher monotonic revision atomically selects a new immutable snapshot, clears cached
decisions, and emits a policy-change invalidation. Cache keys bind every request field, policy digest,
and revocation epoch. Protected policy outage returns a content-free unavailable error; it never
reuses stale policy state.

## Revocation and denied existence

Principal, grant, and exact-resource revocations are checked synchronously and advance the
revocation epoch before their high-priority invalidation event is visible to workers. Bundles,
handoffs, and effects bind their originating policy digest; a mismatch requires refresh before use,
so old artifacts stop serving without waiting for background traversal.

Internal decisions retain input and policy digests, redaction paths, conditions, expiry, and stable
reason codes for protected audit. `caller_view` applies disclosure policy. Denied-existence results
collapse to the same absent disposition and timing class as an unknown resource, omitting IDs,
digests, paths, counts, conditions, and reasons.

## Capabilities and redaction

Anonymous capability discovery is the typed `getCapabilities` operation at
`GET /v1/capabilities`. Its response reports the API/protocol versions, payload/event bounds, and a
sorted closed profile set derived from the validated runtime composition. Exactly one selected
intelligence profile is advertised: `intelligence-balanced-v1`, `intelligence-balanced-v3`, or
`intelligence-balanced-v4`. During 0.9.4 qualification `balanced_v3` remains the default and v4 is
explicitly opt-in. Callers must negotiate from this response and must not infer a profile from a
binary filename, local configuration file, or free-form diagnostic.

Signed grants bind canonical grant bytes to tenant, issuer, signature purpose, key reference,
signature time, and exclusive expiry. Verification also checks the authenticated subject, current
revocation, grant validity, and parent signature. A child must structurally subset capabilities,
projects, processors, time interval, and delegation depth. Current policy still applies after a valid
signature; possession is never sufficient authorization.

Structural redaction operates on canonical typed trees using exact RFC 6901-style pointers. It does
not search serialized strings. Redacted fields receive a typed marker, untouched fields remain exact,
and the derived digest binds canonical output, source digest, policy digest, and sorted paths. A path
overlapping a required field makes the candidate ineligible instead of silently dropping the field.
