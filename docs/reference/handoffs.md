# Signed handoffs and child results

WP11 implements handoff as scoped delegation, not transcript forwarding. Creation requires verified
issuer authority containing `CreateHandoff`. Requested projects and capabilities are intersected with
the issuer's effective scope and current handoff policy. The preview lists accepted and rejected
scope before signing. A capsule contains only typed source, state, decision, artifact, uncertainty,
and effect references; there is no unrestricted transcript field.

## Signature and persistence

The service hashes the unsigned capsule as deterministic CBOR under the
`CIGAR-HANDOFF\0v1\0` domain and signs it with an active tenant-scoped Ed25519 key provider. The
signature binds issuer, key, creation and expiry, audience, recipient selector, nonce, reusable
semantics, task, criteria, projects, capabilities, topics, references, bundle, and budget. The exact
capsule is persisted before it can be accepted. `creation_event` supplies the canonical capsule digest
for an atomic `HandoffCreated` context-space commit.

Persisted capsule inspection is existence-hiding: only the issuer, exact recipient, or a currently
resolved recipient role can read it. Debug output reports sizes and counts instead of task text,
nonce, audience, or signature bytes.

## Recipient acceptance

Acceptance starts over from current authenticated state. It checks the exact persisted capsule,
signature and historical key scope, audience, principal or role, inclusive creation boundary,
exclusive expiry, capsule/key/principal revocation, one-time nonce, recipient effective authority,
current policy, project scope, and target restriction. Every typed reference is independently
reauthorized. Inaccessible references are listed by the already disclosed immutable ID but their
content is never supplied to the compiler. Resolution requires the exact retained version and the
declared reference kind, project, current policy visibility, lifecycle state, tenant, and request
lifetime; an ID that exists under another catalog category is not interchangeable.

The compiler callback receives only accepted projects, attenuated capabilities, reauthorized
references, and the signed budget. The persisted acceptance receipt binds these values, unavailable
references, current policy digest, recipient-specific bundle, timestamp, and acknowledgement digest.
Its internal compilation receipt also binds the source bundle, exact source and target plan revisions
and digests, derivation digest, target profile, and resulting bundle. The acknowledgement digest seals
that complete authority record, preventing a caller-supplied bundle ID or stale plan from being
treated as compiler output.
One-time capsules consume their nonce exactly once. Reusable capsules permit multiple distinct
acceptance receipts, while duplicate receipt identities still fail as replay. Topic subscriptions are
limited to the signed topic set.

## Child result merge

A `HandoffDelta` must match the capsule, authenticated accepted recipient, and exact parent base
commit. Every claim needs currently authorized evidence. Decisions, artifacts, and source changes
require explicit semantic-key mappings and become typed proposals in a private parent overlay.
Ordinary three-way publication then merges independent changes or returns base/current/proposed
conflicts. Effect references remain references, and requested follow-up capabilities are recorded as
ungranted; a child result never amplifies authority. Merge reloads and verifies the persisted capsule,
acceptance authority, current issuer key and principal status, and typed result versions immediately
before mutation. Decision, artifact, and source-change IDs must resolve to their exact declared kind,
and a version cannot be mapped into multiple categories.
