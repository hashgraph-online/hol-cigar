//! Hermetic fixtures, deterministic clocks and identities, failpoints, and conformance helpers.

use cigar_protocol::{
    ApprovalKind, AtomKind, AtomPayload, BlobRef, Budget, CandidateDisposition, CanonicalValue,
    Capability, CapabilityGrant, Classification, CompatibilityReport, CompensationLink,
    ConsistencyMode, ContentDigest, ContextAtomV1, ContextBlock, ContextBundle, ContextCommit,
    ContextContract, ContextDelta, ContextEdge, ContextPlan, ContextRequirement, ContextSpaceId,
    CoordinationEventKind, CoordinationTopic, DecisionOutcome, DecisionRecord, DependencyKind,
    DiffStatus, DispositionReason, DurationNanos, EdgeKind, EffectApproval, EffectAttempt,
    EffectIntent, EffectJournalEvent, EffectReceipt, EffectState, ErrorCode, ExpectedRevision,
    ExtensionKey, ExtensionMap, FixedPoint, GovernanceEnvelope, HandoffAcceptance, HandoffCapsule,
    HandoffDelta, HealthReport, HealthStatus, IdempotencyKey, InstructionAuthority, LaneKind,
    Lease, LeaseKind, LeaseState, Lifecycle, LineageId, MaterializedContext, MediaType,
    OperationClass, Overlay, OverlayMutation, PageCursor, PlanLane, Problem, QualityEnvelope,
    ReceiptOutcome, RecipientSelector, ReconciliationOutcome, ReconciliationReport, RecordId,
    RelativePath, ReplayCompleteness, ReplayDiff, ReplayExecution, ReplayMode, ReplayRequest,
    ReplayStatus, RepresentationKind, RequirementSelector, RetryClass, RetryPolicy, RiskLevel,
    SchemaVersion, SelectionManifest, SourceDescriptor, SourceSnapshot, SourceUri, TargetProfile,
    TemporalEnvelope, UtcTimestamp, Validate, ValidationCode, VerificationOutcome,
    VerificationReceipt, VersionId,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// One portable WP01 conformance example and its expected decode/validation outcome.
#[derive(Clone, Debug, Serialize)]
pub struct ProtocolFixture {
    /// Stable fixture identifier.
    pub id: String,
    /// Semantic type or validation operation exercised by the input.
    pub target: String,
    /// Coverage class such as enum variant, invalid discriminant, or limit boundary.
    pub category: String,
    /// JSON input consumed by every language implementation.
    pub input: Value,
    /// Whether strict decoding and semantic validation must succeed.
    pub expected_valid: bool,
}

fn fixture(
    id: impl Into<String>,
    target: impl Into<String>,
    category: impl Into<String>,
    input: Value,
    expected_valid: bool,
) -> ProtocolFixture {
    ProtocolFixture {
        id: id.into(),
        target: target.into(),
        category: category.into(),
        input,
        expected_valid,
    }
}

fn add_unit_variants(fixtures: &mut Vec<ProtocolFixture>, target: &str, variants: &[&str]) {
    for variant in variants {
        fixtures.push(fixture(
            format!("{target}.variant.{variant}"),
            target,
            "enum_variant",
            json!(variant),
            true,
        ));
    }
    fixtures.push(fixture(
        format!("{target}.invalid.unknown"),
        target,
        "invalid_discriminant",
        json!("__unknown_variant__"),
        false,
    ));
}

fn add_tagged_variants(
    fixtures: &mut Vec<ProtocolFixture>,
    target: &str,
    variants: &[(&str, Value)],
) {
    for (variant, input) in variants {
        fixtures.push(fixture(
            format!("{target}.variant.{variant}"),
            target,
            "union_variant",
            input.clone(),
            true,
        ));
    }
    fixtures.push(fixture(
        format!("{target}.invalid.unknown"),
        target,
        "invalid_discriminant",
        json!({"type": "__unknown_variant__"}),
        false,
    ));
}

/// Returns the deterministic WP01 fixture matrix.
#[must_use]
pub fn protocol_fixtures() -> Vec<ProtocolFixture> {
    let mut fixtures = Vec::new();
    let unit_families: &[(&str, &[&str])] = &[
        (
            "AtomKind",
            &[
                "instruction",
                "source_code",
                "documentation",
                "decision",
                "conversation",
                "tool_result",
                "schema",
                "policy",
                "test",
                "artifact",
            ],
        ),
        (
            "Classification",
            &["public", "internal", "confidential", "restricted"],
        ),
        (
            "InstructionAuthority",
            &["data", "advisory", "project", "system"],
        ),
        (
            "Lifecycle",
            &["active", "superseded", "tombstoned", "quarantined"],
        ),
        (
            "EdgeKind",
            &[
                "depends_on",
                "defines",
                "references",
                "supersedes",
                "contradicts",
                "supports",
                "derived_from",
                "applies_to",
            ],
        ),
        (
            "DispositionReason",
            &[
                "scope_denied",
                "purpose_denied",
                "temporal_mismatch",
                "trust_insufficient",
                "instruction_authority_denied",
                "processor_denied",
                "integrity_failed",
                "budget_displaced",
                "lifecycle_ineligible",
                "conflict_lost",
                "required_missing",
            ],
        ),
        (
            "RepresentationKind",
            &["exact", "extracted", "summarized", "redacted"],
        ),
        (
            "OperationClass",
            &["read", "code_change", "analysis", "external_mutation"],
        ),
        (
            "ConsistencyMode",
            &["snapshot", "strong", "bounded_staleness"],
        ),
        (
            "LaneKind",
            &["rules", "task", "evidence", "history", "tools"],
        ),
        (
            "Capability",
            &[
                "read_context",
                "compile_context",
                "write_overlay",
                "publish_overlay",
                "create_handoff",
                "accept_handoff",
                "invoke_tool",
                "propose_effect",
                "approve_effect",
                "reconcile_effect",
            ],
        ),
        (
            "CoordinationEventKind",
            &[
                "context_committed",
                "atom_invalidated",
                "bundle_invalidated",
                "task_checkpointed",
                "handoff_created",
                "handoff_accepted",
                "handoff_revoked",
                "agent_result_proposed",
                "merge_conflict_created",
                "effect_state_changed",
                "policy_snapshot_changed",
            ],
        ),
        (
            "CoordinationTopic",
            &[
                "atom_invalidation",
                "bundle_invalidation",
                "task_checkpoint",
                "handoff_revocation",
                "effect_state",
                "policy_snapshot",
            ],
        ),
        (
            "LeaseKind",
            &["task", "decision", "effect_reconciliation", "publication"],
        ),
        ("LeaseState", &["active", "released", "expired", "revoked"]),
        (
            "EffectState",
            &[
                "prepared",
                "pending_approval",
                "authorized",
                "dispatching",
                "succeeded",
                "failed",
                "unknown",
                "authorized_for_retry",
                "manual_resolution",
                "rejected",
                "expired",
                "cancelled",
                "compensation_pending",
                "compensating",
                "compensated",
                "compensation_failed",
            ],
        ),
        ("RiskLevel", &["low", "medium", "high", "critical"]),
        ("ApprovalKind", &["human", "policy"]),
        ("ReceiptOutcome", &["succeeded", "failed", "unknown"]),
        (
            "ReconciliationOutcome",
            &[
                "confirmed_success",
                "confirmed_failure",
                "proven_not_executed",
                "inconclusive",
                "manual",
            ],
        ),
        (
            "DecisionOutcome",
            &["succeeded", "failed", "partial", "cancelled"],
        ),
        (
            "ReplayMode",
            &[
                "evidence_reproduction",
                "invocation_reproduction",
                "observational",
                "live_comparison",
            ],
        ),
        (
            "DependencyKind",
            &[
                "source",
                "blob",
                "policy",
                "index",
                "manifest",
                "bundle",
                "tokenizer",
                "adapter",
                "consumer",
                "tool_schema",
                "environment",
            ],
        ),
        (
            "ReplayStatus",
            &["running", "complete", "failed", "incomplete"],
        ),
        ("DiffStatus", &["equal", "different", "unavailable"]),
        (
            "VerificationOutcome",
            &["passed", "failed", "indeterminate"],
        ),
        (
            "RetryClass",
            &[
                "never",
                "safe",
                "after_backoff",
                "after_reauthorization",
                "after_reconciliation",
            ],
        ),
        ("HealthStatus", &["healthy", "degraded", "unhealthy"]),
        (
            "ValidationCode",
            &[
                "LIMIT_EXCEEDED",
                "INVALID_SCHEMA",
                "UNSUPPORTED_SCHEMA",
                "INVALID_IDENTITY",
                "INVALID_EXTENSION_KEY",
                "UNKNOWN_MANDATORY_EXTENSION",
                "INVALID_VALUE",
            ],
        ),
        (
            "ErrorCode",
            &[
                "INVALID_ARGUMENT",
                "LIMIT_EXCEEDED",
                "UNSUPPORTED_SCHEMA",
                "UNKNOWN_PRINCIPAL",
                "INVALID_CAPABILITY",
                "CAPABILITY_EXPIRED",
                "SOURCE_UNAVAILABLE",
                "SNAPSHOT_INCOMPLETE",
                "INTEGRITY_FAILURE",
                "INDEX_STALE",
                "INDEX_UNAVAILABLE",
                "CONSISTENCY_UNSATISFIED",
                "POLICY_DENIED",
                "PROCESSOR_DENIED",
                "INSTRUCTION_AUTHORITY_DENIED",
                "BUDGET_UNSATISFIABLE",
                "MISSING_REQUIRED_CONTEXT",
                "UNRESOLVED_CRITICAL_CONFLICT",
                "DELTA_BASE_MISMATCH",
                "BUNDLE_INVALIDATED",
                "REVISION_CONFLICT",
                "HANDOFF_EXPIRED",
                "HANDOFF_RECIPIENT_MISMATCH",
                "APPROVAL_REQUIRED",
                "APPROVAL_STALE",
                "EFFECT_UNKNOWN",
                "UNSAFE_RETRY",
                "REPLAY_INCOMPLETE",
                "DEPENDENCY_UNAVAILABLE",
                "LIVE_AUTHORIZATION_REQUIRED",
                "RATE_LIMITED",
                "DEADLINE_EXCEEDED",
                "DEPENDENCY_DEGRADED",
                "INTERNAL",
            ],
        ),
    ];
    for (target, variants) in unit_families {
        add_unit_variants(&mut fixtures, target, variants);
    }

    let uuid = json!("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890");
    let digest = json!(format!("1220{}", "00".repeat(32)));
    add_tagged_variants(
        &mut fixtures,
        "AtomPayload",
        &[
            (
                "inline_text",
                json!({"type":"inline_text", "value":"bounded"}),
            ),
            (
                "structured",
                json!({"type":"structured", "value":{"type":"integer", "value":7}}),
            ),
            (
                "blob",
                json!({"type":"blob", "value":{"digest":digest, "size_bytes":7, "media_type":"application/octet-stream"}}),
            ),
        ],
    );
    add_tagged_variants(
        &mut fixtures,
        "CandidateDisposition",
        &[
            (
                "selected",
                json!({"state":"selected", "lane":"evidence", "score":500000}),
            ),
            (
                "excluded",
                json!({"state":"excluded", "reason":"scope_denied"}),
            ),
            (
                "redacted",
                json!({"state":"redacted", "reason":"purpose_denied"}),
            ),
            ("required_missing", json!({"state":"required_missing"})),
        ],
    );
    add_tagged_variants(
        &mut fixtures,
        "RequirementSelector",
        &[
            ("exact", json!({"type":"exact", "value":digest})),
            ("query", json!({"type":"query", "value":"bounded query"})),
        ],
    );
    add_tagged_variants(
        &mut fixtures,
        "OverlayMutation",
        &[
            ("atom", json!({"type":"atom", "digest":digest})),
            ("decision", json!({"type":"decision", "digest":digest})),
            ("state", json!({"type":"state", "digest":digest})),
            ("artifact", json!({"type":"artifact", "digest":digest})),
            (
                "instruction",
                json!({"type":"instruction", "digest":digest}),
            ),
            ("capability", json!({"type":"capability", "digest":digest})),
            ("lease", json!({"type":"lease", "digest":digest})),
            ("effect", json!({"type":"effect", "digest":digest})),
        ],
    );
    add_tagged_variants(
        &mut fixtures,
        "RecipientSelector",
        &[
            ("principal", json!({"type":"principal", "value":uuid})),
            ("role", json!({"type":"role", "value":"reviewer"})),
        ],
    );
    add_tagged_variants(
        &mut fixtures,
        "RetryPolicy",
        &[
            ("never", json!({"type":"never"})),
            (
                "same_key_idempotent",
                json!({"type":"same_key_idempotent", "max_attempts":3}),
            ),
            (
                "reconcile_before_retry",
                json!({"type":"reconcile_before_retry"}),
            ),
        ],
    );
    add_tagged_variants(
        &mut fixtures,
        "CanonicalValue",
        &[
            ("boolean", json!({"type":"boolean", "value":true})),
            ("integer", json!({"type":"integer", "value":-7})),
            ("text", json!({"type":"text", "value":"bounded"})),
            ("bytes", json!({"type":"bytes", "value":"AAE"})),
            ("array", json!({"type":"array", "value":[]})),
            ("object", json!({"type":"object", "value":{}})),
        ],
    );

    add_boundary_fixtures(&mut fixtures);
    add_record_fixtures(&mut fixtures);
    add_inventory_leaf_fixtures(&mut fixtures);
    fixtures
}

/// Returns the deterministic valid constructor fixture for a named protocol record or type.
#[must_use]
pub fn deterministic_protocol_fixture(target: &str) -> Option<ProtocolFixture> {
    protocol_fixtures().into_iter().find(|fixture| {
        fixture.target == target
            && fixture.expected_valid
            && matches!(
                fixture.category.as_str(),
                "record_valid" | "enum_variant" | "union_variant" | "maximum"
            )
    })
}

fn add_record_fixture(fixtures: &mut Vec<ProtocolFixture>, target: &str, input: Value) {
    fixtures.push(fixture(
        format!("{target}.record.minimal"),
        target,
        "record_valid",
        input,
        true,
    ));
}

fn add_inventory_leaf_fixtures(fixtures: &mut Vec<ProtocolFixture>) {
    let id = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7890";
    let digest = format!("1220{}", "a".repeat(64));
    for target in ["RecordId", "LineageId", "ContextSpaceId"] {
        add_record_fixture(fixtures, target, json!(id));
    }
    for target in ["VersionId", "ContentDigest"] {
        add_record_fixture(fixtures, target, json!(digest));
    }
    add_record_fixture(fixtures, "PageCursor", json!("YQ"));
    add_record_fixture(fixtures, "IdempotencyKey", json!("fixture-key"));
    add_record_fixture(fixtures, "ExpectedRevision", json!(1));
    add_record_fixture(
        fixtures,
        "BlobRef",
        json!({"digest":digest, "size_bytes":1, "media_type":"application/octet-stream"}),
    );
    add_record_fixture(
        fixtures,
        "SourceDescriptor",
        json!({"uri":"file:///fixture", "revision":"revision-1", "snapshot_digest":digest}),
    );
    add_record_fixture(
        fixtures,
        "TemporalEnvelope",
        json!({"valid_from":"2026-07-10T00:00:00Z", "observed_at":"2026-07-10T00:00:01Z"}),
    );
    add_record_fixture(
        fixtures,
        "GovernanceEnvelope",
        json!({"classification":"internal", "allowed_purposes":["coding"], "processor_constraints":[], "instruction_authority":"data"}),
    );
    add_record_fixture(
        fixtures,
        "QualityEnvelope",
        json!({"confidence":900000, "coverage":800000, "authority":1}),
    );
    add_record_fixture(
        fixtures,
        "Budget",
        json!({"total_input_tokens":100, "output_reserve_tokens":50, "lane_input_tokens":{"task":100}}),
    );
    add_record_fixture(
        fixtures,
        "ContextRequirement",
        json!({"semantic_type":"documentation", "selector":{"type":"query", "value":"fixture"}, "minimum_authority":1, "minimum_coverage":500000, "blocking":true}),
    );
    add_record_fixture(
        fixtures,
        "TargetProfile",
        json!({"provider":"fixture", "model_family":"fixture-model", "tokenizer_fingerprint":digest, "materializer_fingerprint":digest, "max_context_tokens":1000}),
    );
}

fn add_record_fixtures(fixtures: &mut Vec<ProtocolFixture>) {
    let id = |suffix: char| json!(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f789{suffix}"));
    let digest = |character: char| json!(format!("1220{}", character.to_string().repeat(64)));
    let timestamp = |seconds: u8| json!(format!("2026-07-10T00:00:{seconds:02}Z"));
    let blob = |character: char| {
        json!({
            "digest": digest(character),
            "size_bytes": 1,
            "media_type": "application/octet-stream"
        })
    };
    let block = || {
        json!({
            "block_id": digest('1'),
            "lane": "evidence",
            "representation": "exact",
            "content_digest": digest('2'),
            "token_count": 10,
            "provenance": [digest('3')]
        })
    };

    add_record_fixture(
        fixtures,
        "SourceSnapshot",
        json!({
            "schema_version":"cigar.source-snapshot.v1", "snapshot_id":id('0'),
            "source_uri":"file:///fixture", "source_revision":"revision-1",
            "captured_at":timestamp(0), "manifest_digest":digest('a'), "entry_count":0,
            "total_bytes":0, "complete":true, "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "ContextEdge",
        json!({
            "schema_version":"cigar.edge.v1", "edge_id":id('1'), "from_version":digest('1'),
            "to_version":digest('2'), "kind":"depends_on", "provenance_digest":digest('3'),
            "lifecycle":"active", "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "ContextAtomV1",
        json!({
            "schema_version":"cigar.atom.v1", "atom_id":id('2'), "lineage_id":id('3'),
            "version_id":digest('4'), "content_digest":digest('5'), "kind":"documentation",
            "payload":{"type":"inline_text", "value":"safe fixture"},
            "source":{"uri":"file:///fixture/readme.md", "revision":"revision-1", "snapshot_digest":digest('6')},
            "scope":{"tenant_id":id('4'), "project_ids":[id('5')]},
            "temporal":{"valid_from":timestamp(0), "observed_at":timestamp(1)},
            "governance":{"classification":"internal", "allowed_purposes":["coding"], "processor_constraints":[], "instruction_authority":"data"},
            "quality":{"confidence":900000, "coverage":800000, "authority":1},
            "retrieval":{"exact_terms":["cigar"], "lexical_enabled":true, "embedding_eligible":false},
            "lifecycle":"active", "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "ContextContract",
        json!({
            "schema_version":"cigar.context-contract.v1", "job_goal":"Implement verified change",
            "operation_class":"code_change", "principal_id":id('6'), "purpose":"coding",
            "project_ids":[id('7')],
            "target":{"provider":"fixture", "model_family":"fixture-model", "tokenizer_fingerprint":digest('7'), "materializer_fingerprint":digest('8'), "max_context_tokens":3000},
            "budget":{"total_input_tokens":2000, "output_reserve_tokens":1000, "lane_input_tokens":{"rules":1000,"task":1000}},
            "requirements":[], "consistency":"strong", "extensions":{}
        }),
    );
    let candidate = digest('9');
    add_record_fixture(
        fixtures,
        "PlanLane",
        json!({"kind":"evidence", "budget_tokens":100, "candidate_versions":[candidate.clone()]}),
    );
    add_record_fixture(
        fixtures,
        "ContextPlan",
        json!({
            "schema_version":"cigar.context-plan.v1", "plan_id":id('8'),
            "contract_digest":digest('a'), "catalog_watermark":digest('b'), "total_input_tokens":100,
            "lanes":[{"kind":"evidence", "budget_tokens":100, "candidate_versions":[candidate.clone()]}],
            "dispositions":[[candidate, {"state":"selected", "lane":"evidence", "score":500000}]],
            "extensions":{}
        }),
    );
    add_record_fixture(fixtures, "ContextBlock", block());
    add_record_fixture(
        fixtures,
        "ContextBundle",
        json!({
            "schema_version":"cigar.context-bundle.v1", "bundle_id":digest('a'),
            "contract_digest":digest('b'), "manifest_digest":digest('c'), "blocks":[block()],
            "total_tokens":10, "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "SelectionManifest",
        json!({
            "schema_version":"cigar.selection-manifest.v1", "manifest_id":digest('d'),
            "contract_digest":digest('e'), "entries":[{"version_id":digest('f'),
            "disposition":{"state":"excluded", "reason":"scope_denied"}, "reason_codes":[],
            "provenance_digest":digest('0')}], "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "MaterializedContext",
        json!({
            "schema_version":"cigar.materialized-context.v1", "bundle_id":digest('1'),
            "media_type":"text/plain", "bytes":"YQ", "token_count":1,
            "tokenizer_fingerprint":digest('2'), "materializer_fingerprint":digest('3')
        }),
    );
    add_record_fixture(
        fixtures,
        "ContextDelta",
        json!({
            "schema_version":"cigar.context-delta.v1", "base_bundle_id":digest('4'),
            "target_bundle_id":digest('5'), "added_blocks":[], "removed_block_ids":[],
            "resulting_tokens":0
        }),
    );

    add_record_fixture(
        fixtures,
        "CapabilityGrant",
        json!({
            "schema_version":"cigar.capability-grant.v1", "grant_id":id('9'), "issuer_id":id('a'),
            "subject_id":id('b'), "capabilities":["read_context"], "project_ids":[id('c')],
            "processors":["local"], "not_before":timestamp(0), "expires_at":"2026-07-11T00:00:00Z",
            "delegation_depth":1, "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "ContextCommit",
        json!({
            "schema_version":"cigar.context-commit.v1", "commit_id":digest('6'), "space_id":id('d'),
            "sequence":1, "author_id":id('e'), "purpose":"checkpoint",
            "events":[{"event_id":id('f'), "kind":"task_checkpointed", "payload_digest":digest('7')}],
            "root_digest":digest('8'), "policy_snapshot_digest":digest('9'),
            "committed_at":timestamp(0), "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "Overlay",
        json!({
            "schema_version":"cigar.overlay.v1", "overlay_id":id('0'), "space_id":id('1'),
            "base_commit_id":digest('a'), "owner_id":id('2'), "created_at":timestamp(0),
            "expires_at":timestamp(2), "mutations":[], "extensions":{}
        }),
    );
    let handoff = json!({
        "schema_version":"cigar.handoff.v1", "handoff_id":id('3'), "issuer_id":id('4'),
        "recipient":{"type":"principal", "value":id('5')}, "task":"Verify fixture",
        "acceptance_criteria":["All checks pass"], "project_ids":[id('6')],
        "delegated_capabilities":["read_context"], "rejected_capabilities":["approve_effect"],
        "budget":{"total_input_tokens":1000, "output_reserve_tokens":500, "lane_input_tokens":{"task":1000}},
        "topics":[], "references":{"sources":[],"states":[],"decisions":[],"artifacts":[],"uncertainties":[],"effects":[]},
        "bundle_id":digest('b'), "audience":"fixture-agent", "created_at":timestamp(0),
        "expires_at":"2026-07-11T00:00:00Z", "nonce":"AQEBAQ", "reusable":false,
        "issuer_key_id":"fixture-key", "signature":"AgICAg", "extensions":{}
    });
    add_record_fixture(fixtures, "HandoffCapsule", handoff);
    add_record_fixture(
        fixtures,
        "HandoffAcceptance",
        json!({
            "schema_version":"cigar.handoff-acceptance.v1", "acceptance_id":id('7'),
            "handoff_id":id('3'), "recipient_id":id('5'), "accepted_capabilities":["read_context"],
            "rejected_capabilities":[], "unavailable_references":[], "policy_digest":digest('c'),
            "bundle_id":digest('d'), "accepted_at":timestamp(1), "acknowledgement_digest":digest('e')
        }),
    );
    add_record_fixture(
        fixtures,
        "HandoffDelta",
        json!({
            "schema_version":"cigar.handoff-delta.v1", "delta_id":id('8'), "handoff_id":id('3'),
            "base_commit_id":digest('f'), "producer_id":id('9'), "claims":[], "decisions":[],
            "artifacts":[], "source_changes":[], "verifier_receipts":[], "unresolved_questions":[],
            "blockers":[], "effect_references":[], "requested_followup_capabilities":[], "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "Lease",
        json!({
            "schema_version":"cigar.lease.v1", "lease_id":id('a'), "resource_id":digest('0'),
            "holder_id":id('b'), "kind":"task", "state":"active", "acquired_at":timestamp(0),
            "expires_at":timestamp(2), "expected_revision":1
        }),
    );

    add_effect_record_fixtures(fixtures, &id, &digest, &timestamp, &blob);
    add_replay_service_record_fixtures(fixtures, &id, &digest, &timestamp);
}

fn add_effect_record_fixtures(
    fixtures: &mut Vec<ProtocolFixture>,
    id: &impl Fn(char) -> Value,
    digest: &impl Fn(char) -> Value,
    timestamp: &impl Fn(u8) -> Value,
    blob: &impl Fn(char) -> Value,
) {
    add_record_fixture(
        fixtures,
        "EffectIntent",
        json!({
            "schema_version":"cigar.effect-intent.v1", "effect_id":id('c'),
            "connector":"fixture", "operation":"create", "arguments_digest":digest('1'),
            "encrypted_arguments":blob('2'), "target":"fixture-target", "preconditions":[],
            "result_schema_digest":digest('3'), "risk":"low", "source_decision_id":digest('4'),
            "bundle_id":digest('5'), "required_capability":"propose_effect",
            "idempotency_scope":"fixture-scope", "idempotency_key":"fixture-key",
            "retry_policy":{"type":"never"}, "created_at":timestamp(0), "expires_at":timestamp(2),
            "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "EffectApproval",
        json!({
            "schema_version":"cigar.effect-approval.v1", "approval_id":id('d'), "effect_id":id('c'),
            "intent_digest":digest('6'), "target_digest":digest('7'), "risk":"low",
            "bundle_id":digest('5'), "conditions_digest":digest('8'), "approver_id":id('e'),
            "kind":"policy", "approved_at":timestamp(0), "expires_at":timestamp(2)
        }),
    );
    add_record_fixture(
        fixtures,
        "EffectAttempt",
        json!({
            "schema_version":"cigar.effect-attempt.v1", "attempt_id":id('f'), "effect_id":id('c'),
            "attempt_number":1, "fencing_token":1, "request_digest":digest('9'),
            "started_at":timestamp(0), "deadline":timestamp(2)
        }),
    );
    add_record_fixture(
        fixtures,
        "EffectReceipt",
        json!({
            "schema_version":"cigar.effect-receipt.v1", "receipt_id":id('0'), "effect_id":id('c'),
            "attempt_id":id('f'), "outcome":"failed", "observed_at":timestamp(1)
        }),
    );
    add_record_fixture(
        fixtures,
        "EffectJournalEvent",
        json!({
            "schema_version":"cigar.effect-journal-event.v1", "event_id":id('1'), "effect_id":id('c'),
            "sequence":1, "expected_effect_version":0, "from_state":"prepared",
            "to_state":"pending_approval", "actor_id":id('2'), "payload_digest":digest('a'),
            "event_digest":digest('b'), "recorded_at":timestamp(0)
        }),
    );
    add_record_fixture(
        fixtures,
        "ReconciliationReport",
        json!({
            "schema_version":"cigar.reconciliation-report.v1", "report_id":id('3'),
            "effect_id":id('c'), "outcome":"confirmed_failure", "evidence_digests":[digest('c')],
            "reconciled_at":timestamp(1)
        }),
    );
    add_record_fixture(
        fixtures,
        "CompensationLink",
        json!({
            "schema_version":"cigar.compensation-link.v1", "original_effect_id":id('4'),
            "compensation_effect_id":id('5'), "compensation_spec_digest":digest('d'),
            "created_at":timestamp(1)
        }),
    );
}

fn add_replay_service_record_fixtures(
    fixtures: &mut Vec<ProtocolFixture>,
    id: &impl Fn(char) -> Value,
    digest: &impl Fn(char) -> Value,
    timestamp: &impl Fn(u8) -> Value,
) {
    add_record_fixture(
        fixtures,
        "DecisionRecord",
        json!({
            "schema_version":"cigar.decision-record.v1", "decision_id":digest('1'),
            "task_digest":digest('2'), "plan_id":id('6'), "plan_digest":digest('3'),
            "bundle_id":digest('4'), "materialization_digest":digest('5'),
            "runtime_fingerprint":digest('6'), "consumer_fingerprint":digest('7'),
            "output_artifacts":[], "asserted_claims":[], "evidence":[], "uncertainty":[],
            "verification_receipts":[], "effects":[],
            "usage":{"input_tokens":1,"output_tokens":1,"cached_input_tokens":0,"cost_micros":0},
            "started_at":timestamp(0), "completed_at":timestamp(1), "outcome":"succeeded", "extensions":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "ReplayRequest",
        json!({
            "schema_version":"cigar.replay-request.v1", "request_id":id('7'),
            "decision_id":digest('1'), "mode":"evidence_reproduction", "requested_by":id('8'),
            "simulate_effects":true, "authorized_effect_intents":[]
        }),
    );
    let completeness = json!({"available":["source"], "missing":[]});
    add_record_fixture(fixtures, "ReplayCompleteness", completeness.clone());
    add_record_fixture(
        fixtures,
        "ReplayExecution",
        json!({
            "schema_version":"cigar.replay-execution.v1", "execution_id":id('9'),
            "request_id":id('7'), "mode":"evidence_reproduction", "status":"running",
            "completeness":completeness, "egress_permitted":false,
            "effect_dispatch_permitted":false, "started_at":timestamp(0)
        }),
    );
    add_record_fixture(
        fixtures,
        "ReplayDiff",
        json!({
            "schema_version":"cigar.replay-diff.v1", "decision_id":digest('1'),
            "execution_id":id('9'), "semantic_context":"equal", "materialization":"equal",
            "components":"equal", "output_claims":"equal", "verification":"equal",
            "effect_plan":"equal", "observations":"equal", "compiler_deterministic":true
        }),
    );
    add_record_fixture(
        fixtures,
        "VerificationReceipt",
        json!({
            "schema_version":"cigar.verification-receipt.v1", "receipt_id":digest('8'),
            "verifier_fingerprint":digest('9'), "subject_digest":digest('a'),
            "checks":[{"name":"checksum", "evidence_digest":digest('b'), "outcome":"passed"}],
            "outcome":"passed", "verified_at":timestamp(1)
        }),
    );
    add_record_fixture(
        fixtures,
        "Problem",
        json!({
            "schema_version":"cigar.problem.v1", "code":"POLICY_DENIED", "http_status":403,
            "retry":"after_reauthorization", "message":"request denied",
            "remediation":"request authorized scope", "correlation_id":id('a'), "details":{}
        }),
    );
    add_record_fixture(
        fixtures,
        "HealthReport",
        json!({
            "schema_version":"cigar.health-report.v1", "status":"healthy", "components":[],
            "observed_at":timestamp(1)
        }),
    );
    add_record_fixture(
        fixtures,
        "CompatibilityReport",
        json!({
            "schema_version":"cigar.compatibility-report.v1", "protocol_min":"1.0",
            "protocol_max":"1.x", "writer_protocol":"1.0", "schema_majors":{"cigar.atom":1},
            "compatible":true, "reasons":[]
        }),
    );
}

fn add_boundary_fixtures(fixtures: &mut Vec<ProtocolFixture>) {
    use cigar_protocol::limits::{
        MAX_DURATION_NANOS, MAX_EXTENSION_KEY_BYTES, MAX_IDEMPOTENCY_KEY_BYTES,
        MAX_MEDIA_TYPE_BYTES, MAX_PATH_BYTES, MAX_SCHEMA_FAMILY_BYTES, MAX_URI_BYTES,
    };
    let string_boundaries = [
        (
            "IdempotencyKey",
            "a".repeat(MAX_IDEMPOTENCY_KEY_BYTES - 1),
            true,
        ),
        (
            "IdempotencyKey",
            "a".repeat(MAX_IDEMPOTENCY_KEY_BYTES),
            true,
        ),
        (
            "IdempotencyKey",
            "a".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1),
            false,
        ),
        (
            "ExtensionKey",
            "a".repeat(MAX_EXTENSION_KEY_BYTES - 1),
            true,
        ),
        ("ExtensionKey", "a".repeat(MAX_EXTENSION_KEY_BYTES), true),
        (
            "ExtensionKey",
            "a".repeat(MAX_EXTENSION_KEY_BYTES + 1),
            false,
        ),
        (
            "SourceUri",
            format!("x:{}", "a".repeat(MAX_URI_BYTES - 3)),
            true,
        ),
        (
            "SourceUri",
            format!("x:{}", "a".repeat(MAX_URI_BYTES - 2)),
            true,
        ),
        (
            "SourceUri",
            format!("x:{}", "a".repeat(MAX_URI_BYTES - 1)),
            false,
        ),
        (
            "MediaType",
            format!("a/{}", "b".repeat(MAX_MEDIA_TYPE_BYTES - 3)),
            true,
        ),
        (
            "MediaType",
            format!("a/{}", "b".repeat(MAX_MEDIA_TYPE_BYTES - 2)),
            true,
        ),
        (
            "MediaType",
            format!("a/{}", "b".repeat(MAX_MEDIA_TYPE_BYTES - 1)),
            false,
        ),
        (
            "SchemaVersion",
            format!("{}.v1", "a".repeat(MAX_SCHEMA_FAMILY_BYTES - 1)),
            true,
        ),
        (
            "SchemaVersion",
            format!("{}.v1", "a".repeat(MAX_SCHEMA_FAMILY_BYTES)),
            true,
        ),
        (
            "SchemaVersion",
            format!("{}.v1", "a".repeat(MAX_SCHEMA_FAMILY_BYTES + 1)),
            false,
        ),
    ];
    for (index, (target, value, expected)) in string_boundaries.into_iter().enumerate() {
        let category = boundary_category(index);
        fixtures.push(fixture(
            format!("{target}.boundary.{index}"),
            target,
            category,
            json!(value),
            expected,
        ));
    }
    for (target, values) in [
        (
            "DurationNanos",
            [
                MAX_DURATION_NANOS - 1,
                MAX_DURATION_NANOS,
                MAX_DURATION_NANOS + 1,
            ],
        ),
        ("FixedPoint", [999_999, 1_000_000, 1_000_001]),
    ] {
        for (index, value) in values.into_iter().enumerate() {
            let category = boundary_category(index);
            fixtures.push(fixture(
                format!("{target}.boundary.{index}"),
                target,
                category,
                json!(value),
                index < 2,
            ));
        }
    }
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    for (index, length) in [MAX_PATH_BYTES - 1, MAX_PATH_BYTES, MAX_PATH_BYTES + 1]
        .into_iter()
        .enumerate()
    {
        let category = boundary_category(index);
        fixtures.push(fixture(
            format!("RelativePath.boundary.{index}"),
            "RelativePath",
            category,
            json!(URL_SAFE_NO_PAD.encode(vec![b'a'; length])),
            index < 2,
        ));
    }
    fixtures.push(fixture(
        "SchemaVersion.unsupported_major",
        "SchemaVersionV1",
        "unsupported_version",
        json!("context-atom.v2"),
        false,
    ));
    fixtures.push(fixture(
        "ExtensionMap.unknown_optional",
        "ExtensionMap",
        "optional_extension",
        json!({"vendor/example":{"type":"integer","value":1}}),
        true,
    ));
    fixtures.push(fixture(
        "ExtensionMap.unknown_mandatory",
        "ExtensionMap",
        "mandatory_extension",
        json!({"required/vendor-example":{"type":"integer","value":1}}),
        false,
    ));
}

fn boundary_category(index: usize) -> &'static str {
    match index % 3 {
        0 => "limit_minus_one",
        1 => "maximum",
        _ => "limit_plus_one",
    }
}

fn decodes<T: DeserializeOwned>(input: Value) -> bool {
    serde_json::from_value::<T>(input).is_ok()
}

fn decodes_and_validates<T: DeserializeOwned + Validate>(input: Value) -> bool {
    serde_json::from_value::<T>(input).is_ok_and(|value| value.validate().is_ok())
}

/// Strictly executes a fixture using the Rust semantic decoder and validation hooks.
#[must_use]
pub fn fixture_actual_valid(fixture: &ProtocolFixture) -> bool {
    macro_rules! decode_targets {
        ($($name:literal => $type:ty),+ $(,)?) => {
            match fixture.target.as_str() {
                $($name => decodes::<$type>(fixture.input.clone()),)+
                _ => return fixture_special_valid(fixture),
            }
        };
    }
    decode_targets!(
        "AtomKind" => AtomKind, "AtomPayload" => AtomPayload,
        "Classification" => Classification, "InstructionAuthority" => InstructionAuthority,
        "Lifecycle" => Lifecycle, "EdgeKind" => EdgeKind,
        "DispositionReason" => DispositionReason, "CandidateDisposition" => CandidateDisposition,
        "RepresentationKind" => RepresentationKind, "OperationClass" => OperationClass,
        "ConsistencyMode" => ConsistencyMode, "LaneKind" => LaneKind,
        "RequirementSelector" => RequirementSelector, "Capability" => Capability,
        "CoordinationEventKind" => CoordinationEventKind, "OverlayMutation" => OverlayMutation,
        "RecipientSelector" => RecipientSelector, "CoordinationTopic" => CoordinationTopic,
        "LeaseKind" => LeaseKind, "LeaseState" => LeaseState, "EffectState" => EffectState,
        "RiskLevel" => RiskLevel, "RetryPolicy" => RetryPolicy, "ApprovalKind" => ApprovalKind,
        "ReceiptOutcome" => ReceiptOutcome, "ReconciliationOutcome" => ReconciliationOutcome,
        "DecisionOutcome" => DecisionOutcome, "ReplayMode" => ReplayMode,
        "DependencyKind" => DependencyKind, "ReplayStatus" => ReplayStatus,
        "DiffStatus" => DiffStatus, "VerificationOutcome" => VerificationOutcome,
        "ErrorCode" => ErrorCode, "RetryClass" => RetryClass, "HealthStatus" => HealthStatus,
        "ValidationCode" => ValidationCode, "IdempotencyKey" => IdempotencyKey,
        "ExpectedRevision" => ExpectedRevision,
        "ExtensionKey" => ExtensionKey, "SourceUri" => SourceUri, "MediaType" => MediaType,
        "SchemaVersion" => SchemaVersion, "RelativePath" => RelativePath,
        "DurationNanos" => DurationNanos, "FixedPoint" => FixedPoint,
        "RecordId" => RecordId, "LineageId" => LineageId, "ContextSpaceId" => ContextSpaceId,
        "ContentDigest" => ContentDigest, "VersionId" => VersionId,
        "UtcTimestamp" => UtcTimestamp, "PageCursor" => PageCursor
    )
}

fn fixture_special_valid(fixture: &ProtocolFixture) -> bool {
    macro_rules! validated_record_targets {
        ($($name:literal => $type:ty),+ $(,)?) => {
            match fixture.target.as_str() {
                $($name => decodes_and_validates::<$type>(fixture.input.clone()),)+
                _ => return special_non_record_valid(fixture),
            }
        };
    }
    validated_record_targets!(
        "SourceSnapshot" => SourceSnapshot, "ContextEdge" => ContextEdge,
        "ContextAtomV1" => ContextAtomV1, "ContextContract" => ContextContract,
        "ContextPlan" => ContextPlan, "ContextBundle" => ContextBundle,
        "SelectionManifest" => SelectionManifest, "MaterializedContext" => MaterializedContext,
        "ContextDelta" => ContextDelta, "CapabilityGrant" => CapabilityGrant,
        "ContextCommit" => ContextCommit, "Overlay" => Overlay,
        "HandoffCapsule" => HandoffCapsule, "HandoffAcceptance" => HandoffAcceptance,
        "HandoffDelta" => HandoffDelta, "Lease" => Lease,
        "EffectIntent" => EffectIntent, "EffectApproval" => EffectApproval,
        "EffectAttempt" => EffectAttempt, "EffectReceipt" => EffectReceipt,
        "EffectJournalEvent" => EffectJournalEvent,
        "ReconciliationReport" => ReconciliationReport, "CompensationLink" => CompensationLink,
        "DecisionRecord" => DecisionRecord, "ReplayRequest" => ReplayRequest,
        "ReplayExecution" => ReplayExecution, "ReplayDiff" => ReplayDiff,
        "VerificationReceipt" => VerificationReceipt, "Problem" => Problem,
        "HealthReport" => HealthReport, "CompatibilityReport" => CompatibilityReport
    )
}

fn special_non_record_valid(fixture: &ProtocolFixture) -> bool {
    match fixture.target.as_str() {
        "CanonicalValue" => serde_json::from_value::<CanonicalValue>(fixture.input.clone())
            .is_ok_and(|value| value.validate().is_ok()),
        "SchemaVersionV1" => serde_json::from_value::<SchemaVersion>(fixture.input.clone())
            .is_ok_and(|value| value.require_v1("context-atom").is_ok()),
        "ExtensionMap" => serde_json::from_value::<ExtensionMap>(fixture.input.clone())
            .is_ok_and(|value| value.validate_known(&BTreeSet::new()).is_ok()),
        "PlanLane" => decodes::<PlanLane>(fixture.input.clone()),
        "ContextBlock" => decodes::<ContextBlock>(fixture.input.clone()),
        "ReplayCompleteness" => decodes::<ReplayCompleteness>(fixture.input.clone()),
        "BlobRef" => decodes::<BlobRef>(fixture.input.clone()),
        "SourceDescriptor" => decodes::<SourceDescriptor>(fixture.input.clone()),
        "TemporalEnvelope" => decodes::<TemporalEnvelope>(fixture.input.clone()),
        "GovernanceEnvelope" => decodes::<GovernanceEnvelope>(fixture.input.clone()),
        "QualityEnvelope" => decodes::<QualityEnvelope>(fixture.input.clone()),
        "Budget" => decodes::<Budget>(fixture.input.clone()),
        "ContextRequirement" => decodes::<ContextRequirement>(fixture.input.clone()),
        "TargetProfile" => decodes::<TargetProfile>(fixture.input.clone()),
        _ => false,
    }
}

/// Renders the checked-in portable fixture manifest with stable ordering.
pub fn render_protocol_fixture_manifest() -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Manifest {
        schema_version: u8,
        fixture_count: usize,
        fixtures: Vec<ProtocolFixture>,
    }
    let fixtures = protocol_fixtures();
    let manifest = Manifest {
        schema_version: 1,
        fixture_count: fixtures.len(),
        fixtures,
    };
    let mut rendered = serde_json::to_string_pretty(&manifest)?;
    rendered.push('\n');
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::{deterministic_protocol_fixture, fixture_actual_valid, protocol_fixtures};
    use std::collections::BTreeSet;

    #[test]
    fn protocol_matrix_has_required_size_uniqueness_and_negative_coverage() {
        let fixtures = protocol_fixtures();
        assert!(
            fixtures.len() >= 200,
            "fixture matrix has only {} cases",
            fixtures.len()
        );
        assert!(fixtures.iter().any(|fixture| fixture.expected_valid));
        assert!(fixtures.iter().any(|fixture| !fixture.expected_valid));
        let ids: BTreeSet<&str> = fixtures.iter().map(|fixture| fixture.id.as_str()).collect();
        assert_eq!(ids.len(), fixtures.len());
        for required_category in [
            "enum_variant",
            "union_variant",
            "maximum",
            "limit_minus_one",
            "limit_plus_one",
            "invalid_discriminant",
            "optional_extension",
            "mandatory_extension",
            "unsupported_version",
        ] {
            assert!(
                fixtures
                    .iter()
                    .any(|fixture| fixture.category == required_category),
                "fixture matrix lacks {required_category} coverage"
            );
        }
        let covered_enums: BTreeSet<&str> = fixtures
            .iter()
            .filter(|fixture| matches!(fixture.category.as_str(), "enum_variant" | "union_variant"))
            .map(|fixture| fixture.target.as_str())
            .collect();
        assert_eq!(
            covered_enums.len(),
            37,
            "an enum or union family is missing"
        );
    }

    #[test]
    fn every_protocol_fixture_matches_its_expected_outcome() {
        for fixture in protocol_fixtures() {
            assert_eq!(
                fixture_actual_valid(&fixture),
                fixture.expected_valid,
                "fixture {} produced the wrong outcome",
                fixture.id
            );
        }
    }

    #[test]
    fn every_required_inventory_type_has_a_deterministic_constructor() {
        for target in [
            "RecordId",
            "LineageId",
            "VersionId",
            "ContentDigest",
            "SourceDescriptor",
            "SourceSnapshot",
            "ContextAtomV1",
            "ContextEdge",
            "BlobRef",
            "Lifecycle",
            "TemporalEnvelope",
            "GovernanceEnvelope",
            "QualityEnvelope",
            "ContextContract",
            "ContextRequirement",
            "Budget",
            "TargetProfile",
            "ContextPlan",
            "PlanLane",
            "CandidateDisposition",
            "ContextBlock",
            "ContextBundle",
            "SelectionManifest",
            "MaterializedContext",
            "ContextDelta",
            "ContextSpaceId",
            "ContextCommit",
            "Overlay",
            "CapabilityGrant",
            "HandoffCapsule",
            "HandoffAcceptance",
            "HandoffDelta",
            "Lease",
            "EffectIntent",
            "EffectApproval",
            "EffectAttempt",
            "EffectReceipt",
            "EffectJournalEvent",
            "ReconciliationReport",
            "CompensationLink",
            "DecisionRecord",
            "ReplayRequest",
            "ReplayExecution",
            "ReplayCompleteness",
            "ReplayDiff",
            "VerificationReceipt",
            "PageCursor",
            "IdempotencyKey",
            "ExpectedRevision",
            "Problem",
            "HealthReport",
            "CompatibilityReport",
        ] {
            assert!(
                deterministic_protocol_fixture(target).is_some(),
                "required inventory type {target} lacks a fixture constructor"
            );
        }
    }
}
