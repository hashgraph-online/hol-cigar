# cigar-daemon

Stability: product surface, pre-v1. Composes the CIGAR service runtime; domain semantics remain in library crates.

`cigard serve --config /absolute/path/cigard.toml` composes the complete frozen 45-operation
application over durable SQLite metadata, encrypted tenant blobs, a persistent encrypted
keystore, compiled protected policy, explicit domain authority, strict built-in source/effect
registries, an activation-backed mandatory index, bounded workers, durable idempotency, and
optional bounded OTLP export. Local mode uses a permission-restricted IPC endpoint or authenticated
loopback TCP. Shared mode uses TLS plus pinned OIDC discovery/JWKS refresh and fails startup when
those concrete dependencies are unavailable.

Standalone replay is recorded-only. A macOS embedding that has independently qualified a live
provider must opt in through `ProductionLiveReplayProfile::tenant_bound_v1` and
`compose_production_server_with_live_replay`, injecting a durable authorization repository and one
complete tenant-bound verifier/provider/effect-gate factory. The profile has no environment or
daemon-file fallback, rejects inactive tenants, and is unavailable to the shared/non-macOS
composition.

Production bootstrap registers the two provider-neutral exact reference tokenizer profiles exposed
by `cigar-compiler`; it no longer starts with an empty tokenizer registry. Context targets can pin
their strict UTF-8 byte or Unicode-scalar reference profile through the safe constructor. Registry
lookup binds provider `cigar-reference`, the profile identifier as model family, and the published
fingerprint. Unknown fingerprints, external providers, and cross-paired model families remain
unavailable and never fall back to a conservative estimate. This is a macOS development-cohort
reference target, not evidence that an
Anthropic, OpenAI, or other provider tokenizer has been implemented, packaged, or qualified.

The daemon also contains a versioned internal trusted-provider lifecycle without changing the
frozen public 45-operation registry. Canonical bounded inputs are HMAC authenticated and bind an
opaque session, exact adapter key, target generation, tenant, policy, revocation epoch, contiguous
sequence, and expiry. Only opaque `AppliedDelta` evidence can create a durable acknowledgement and
provider-present observation. Reset/compaction invalidate reuse, and exact target-overflow repairs
are consumed once through fenced CAS state. The state is capped at 32 sessions and 60,000 bytes per
tenant; caller idempotency keys and public payloads cannot create it. See
[`materialization-cache-deltas.md`](../../docs/reference/materialization-cache-deltas.md#trusted-provider-adapter-lifecycle).

The production source registry accepts only canonical project-confined filesystem or committed-Git
roots. Provisioning verifies that the injected connector's content-free descriptor matches the
durable implementation identity and exact URI. It builds the complete `required_v1` atomizer set in
canonical order and verifies its aggregate digest, which binds every parser identity/version and
its tenant/project scope, governance, quality, lexical, and embedding profile. Root, connector,
profile, parser-substitution, partial-registry, and ordering mismatches fail startup before a source
runtime can be retained.

`DurableContextSpaceService` and `DurableHandoffService` serialize each existing domain mutation,
validate the complete resulting state, publish content-addressed chunks before a tenant-scoped CAS
root, and restore the last durable snapshot on failure. Startup rejects missing, malformed, or
semantically inconsistent chunks and roots. A post-commit repository error is reconciled by exact
generation and byte comparison, while an unresolvable outcome poisons the instance so stale state
cannot be served.
