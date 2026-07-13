//! Named structural limits shared by protocol validation and generated schemas.

/// Maximum errors returned by one validation operation.
pub const MAX_VALIDATION_ERRORS: usize = 32;
/// Maximum bytes in a schema family name.
pub const MAX_SCHEMA_FAMILY_BYTES: usize = 64;
/// Maximum bytes in a user-supplied idempotency key.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
/// Exact bytes in a lowercase textual UUID.
pub const UUID_TEXT_BYTES: usize = 36;
/// Maximum bytes in an extension key.
pub const MAX_EXTENSION_KEY_BYTES: usize = 128;
/// Maximum entries in one extension map.
pub const MAX_EXTENSION_ENTRIES: usize = 64;
/// Maximum nested levels in an extension value.
pub const MAX_EXTENSION_DEPTH: usize = 16;
/// Maximum items in one extension array or object.
pub const MAX_EXTENSION_COLLECTION_ITEMS: usize = 256;
/// Maximum UTF-8 bytes in one extension text value.
pub const MAX_EXTENSION_TEXT_BYTES: usize = 65_536;
/// Maximum bytes in one extension byte value.
pub const MAX_EXTENSION_BYTES: usize = 65_536;
/// Maximum bytes in an extension, publisher, operation, or key selector.
pub const MAX_EXTENSION_HOST_SELECTOR_BYTES: usize = 512;
/// Maximum declared extension kinds and schema bindings (the closed v1 kind count).
pub const MAX_EXTENSION_KINDS: usize = 12;
/// Maximum declared processors in one extension manifest.
pub const MAX_EXTENSION_PROCESSORS: usize = 256;
/// Maximum normalized sandbox preopens in one extension manifest.
pub const MAX_EXTENSION_PREOPENS: usize = 64;
/// Maximum normalized network endpoints in one extension manifest.
pub const MAX_EXTENSION_NETWORK_ENDPOINTS: usize = 64;
/// Maximum bytes in one normalized sandbox path.
pub const MAX_EXTENSION_SANDBOX_PATH_BYTES: usize = 1_024;
/// Maximum bytes in one normalized endpoint host.
pub const MAX_EXTENSION_ENDPOINT_HOST_BYTES: usize = 253;
/// Exact Ed25519 publisher public-key bytes in an extension manifest.
pub const EXTENSION_PUBLISHER_KEY_BYTES: usize = 32;
/// Exact Ed25519 publisher signature bytes in an extension manifest.
pub const EXTENSION_SIGNATURE_BYTES: usize = 64;
/// Maximum opaque handles attached to one extension invocation.
pub const MAX_EXTENSION_HANDLES: usize = 1_024;
/// Exact bytes in one unguessable extension handle.
pub const EXTENSION_HANDLE_BYTES: usize = 32;
/// Maximum deterministic seed bytes supplied to one extension invocation.
pub const MAX_EXTENSION_RANDOM_SEED_BYTES: usize = 64;
/// Maximum extension linear-memory declaration: 16 GiB.
pub const MAX_EXTENSION_MEMORY_BYTES: u64 = 17_179_869_184;
/// Maximum deterministic fuel declaration.
pub const MAX_EXTENSION_FUEL: u64 = 1_000_000_000_000_000;
/// Maximum extension CPU or wall duration: one hour in nanoseconds.
pub const MAX_EXTENSION_RUNTIME_NANOS: u64 = 3_600_000_000_000;
/// Maximum bytes in one extension input, output, or host-call payload.
pub const MAX_EXTENSION_IO_BYTES: usize = 67_108_864;
/// Maximum simultaneous invocations declared by one extension.
pub const MAX_EXTENSION_CONCURRENCY: u16 = 1_024;
/// Maximum guest recursion depth declared by one extension.
pub const MAX_EXTENSION_RECURSION_DEPTH: u16 = 256;
/// Maximum brokered host calls in one extension invocation.
pub const MAX_EXTENSION_HOST_CALLS: u32 = 100_000;
/// Maximum bytes in a source URI.
pub const MAX_URI_BYTES: usize = 4_096;
/// Maximum bytes in a source-relative path.
pub const MAX_PATH_BYTES: usize = 4_096;
/// Maximum bytes in a media type.
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
/// Maximum bytes in a source connector revision identifier.
pub const MAX_SOURCE_REVISION_BYTES: usize = 512;
/// Maximum bytes in one purpose or processor selector.
pub const MAX_SELECTOR_BYTES: usize = 512;
/// Maximum bytes in an inline atom payload.
pub const MAX_INLINE_TEXT_BYTES: usize = 1_048_576;
/// Maximum projects in one scope envelope.
pub const MAX_SCOPE_PROJECTS: usize = 256;
/// Maximum string selectors in one governed collection.
pub const MAX_GOVERNANCE_SELECTORS: usize = 256;
/// Maximum exact terms in retrieval metadata.
pub const MAX_RETRIEVAL_TERMS: usize = 1_024;
/// Maximum bytes in one retrieval term.
pub const MAX_RETRIEVAL_TERM_BYTES: usize = 512;
/// Maximum supported semantic duration: ten years in nanoseconds.
pub const MAX_DURATION_NANOS: u64 = 315_576_000_000_000_000;
/// Maximum bytes in a human job goal.
pub const MAX_JOB_GOAL_BYTES: usize = 65_536;
/// Maximum bytes in a purpose or operation selector.
pub const MAX_PURPOSE_BYTES: usize = 512;
/// Maximum context requirements in one contract.
pub const MAX_CONTEXT_REQUIREMENTS: usize = 1_024;
/// Maximum bytes in one retrieval query selector.
pub const MAX_QUERY_BYTES: usize = 16_384;
/// Maximum bytes in a target provider or model-family identifier.
pub const MAX_TARGET_IDENTIFIER_BYTES: usize = 256;
/// Maximum candidate dispositions in one plan.
pub const MAX_PLAN_CANDIDATES: usize = 10_000;
/// Maximum lanes in one plan or bundle.
pub const MAX_PLAN_LANES: usize = 32;
/// Number of closed standard context lane discriminants in v1.
pub const STANDARD_LANE_COUNT: usize = 5;
/// Maximum context blocks in one bundle or delta.
pub const MAX_CONTEXT_BLOCKS: usize = 10_000;
/// Maximum bytes in one materialized context.
pub const MAX_MATERIALIZED_BYTES: usize = 67_108_864;
/// Maximum stable reason codes attached to one manifest entry.
pub const MAX_REASON_CODES: usize = 64;
/// Maximum ordered coordination events or overlay mutations in one record.
pub const MAX_COORDINATION_EVENTS: usize = 10_000;
/// Maximum subscription topics in one handoff.
pub const MAX_COORDINATION_TOPICS: usize = 32;
/// Maximum capabilities in one grant or handoff.
pub const MAX_CAPABILITIES: usize = 128;
/// Maximum references in one handoff reference category.
pub const MAX_HANDOFF_REFERENCES: usize = 10_000;
/// Maximum bytes in one handoff task, criterion, claim, question, or blocker.
pub const MAX_HANDOFF_TEXT_BYTES: usize = 65_536;
/// Maximum bytes in a handoff audience, role, topic selector, or signing-key identifier.
pub const MAX_COORDINATION_SELECTOR_BYTES: usize = 512;
/// Maximum nonce bytes in a signed handoff.
pub const MAX_NONCE_BYTES: usize = 64;
/// Maximum signature bytes in a portable protocol record.
pub const MAX_SIGNATURE_BYTES: usize = 512;
/// Maximum bytes in connector, operation, target, remote ID, or idempotency scope selectors.
pub const MAX_EFFECT_SELECTOR_BYTES: usize = 1_024;
/// Maximum precondition digests bound into one effect intent.
pub const MAX_EFFECT_PRECONDITIONS: usize = 256;
/// Maximum evidence digests in one effect reconciliation report.
pub const MAX_RECONCILIATION_EVIDENCE: usize = 256;
/// Maximum evidence, dependency, artifact, claim, effect, or verification references in replay records.
pub const MAX_REPLAY_REFERENCES: usize = 10_000;
/// Maximum verification checks in one receipt.
pub const MAX_VERIFICATION_CHECKS: usize = 10_000;
/// Maximum bytes in a verification check identifier.
pub const MAX_VERIFICATION_NAME_BYTES: usize = 512;
/// Maximum opaque page-cursor bytes.
pub const MAX_PAGE_CURSOR_BYTES: usize = 1_024;
/// Maximum bytes in one safe public problem message or remediation.
pub const MAX_PROBLEM_TEXT_BYTES: usize = 4_096;
/// Maximum health components in one report.
pub const MAX_HEALTH_COMPONENTS: usize = 256;
/// Maximum bytes in a health component name.
pub const MAX_HEALTH_COMPONENT_NAME_BYTES: usize = 256;
/// Maximum compatibility reasons in one report.
pub const MAX_COMPATIBILITY_REASONS: usize = 256;
/// Maximum bytes in a protocol version selector.
pub const MAX_PROTOCOL_SELECTOR_BYTES: usize = 64;
/// Maximum schema families in one compatibility report.
pub const MAX_SCHEMA_COMPATIBILITY_ENTRIES: usize = 1_024;
