# cigar-policy

Stability: kernel, pre-v1. Owns hard authorization gates, capabilities, instruction authority, and deterministic policy decisions.

`CompiledPolicyEngine` always evaluates tenant/project scope, current principal and delegated
capabilities, purpose/processor, classification/residency/egress, lifecycle/integrity, bitemporal
validity/freshness, instruction authority, contract exclusions/modality, and effect constraints
before declarative rules. A rule may further deny, quarantine, require refresh, redact, require
approval, or allow; outcome precedence means an allow can never override a denial.

Profiles are bounded canonical JSON or equivalent human-authored TOML compiled into an immutable
rule DAG and policy digest. Installation and revocation emit high-priority invalidations and clear
the decision cache. Existing bundles, handoffs, and effects bind the policy digest and must pass
current reauthorization even while background invalidation is pending.

Capability grants use the protocol’s structural attenuation proof and a tenant-, issuer-, purpose-,
payload-, time-, and key-bound signature envelope. `StructuralRedactor` applies exact JSON pointers
to canonical values and produces a new digest with source and policy lineage. Denied-existence caller
views omit resource and policy identifiers, redaction paths, conditions, scores, and counts.

See [`docs/reference/policy-capabilities.md`](../../docs/reference/policy-capabilities.md) and the
[`policy-profile-v1` schema](../../schemas/policy/policy-profile-v1.schema.json).
