//! Immutable context-space commits, overlays, attenuated grants, handoffs, and leases.

use crate::limits::{
    MAX_CAPABILITIES, MAX_COORDINATION_EVENTS, MAX_COORDINATION_SELECTOR_BYTES,
    MAX_COORDINATION_TOPICS, MAX_HANDOFF_REFERENCES, MAX_HANDOFF_TEXT_BYTES, MAX_NONCE_BYTES,
    MAX_SCOPE_PROJECTS, MAX_SIGNATURE_BYTES,
};
use crate::primitive::base64url;
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    Budget, ContentDigest, ContextSpaceId, ExpectedRevision, ExtensionMap, RecordId, SchemaVersion,
    UtcTimestamp, Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Closed capabilities that may be granted and attenuated.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Observe authorized context records.
    ReadContext,
    /// Compile an authorized context bundle.
    CompileContext,
    /// Propose private overlay mutations.
    WriteOverlay,
    /// Publish an overlay through optimistic merge.
    PublishOverlay,
    /// Create a handoff capsule.
    CreateHandoff,
    /// Accept a handoff capsule.
    AcceptHandoff,
    /// Invoke a mediated tool.
    InvokeTool,
    /// Propose an external effect intent.
    ProposeEffect,
    /// Approve an external effect.
    ApproveEffect,
    /// Reconcile an unknown effect.
    ReconcileEffect,
}

/// Attenuable capability grant; possession never bypasses current policy.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    /// Must be `cigar.capability-grant.v1`.
    pub schema_version: SchemaVersion,
    /// Unique grant identity.
    pub grant_id: RecordId,
    /// Principal issuing this grant.
    pub issuer_id: RecordId,
    /// Principal receiving this grant.
    pub subject_id: RecordId,
    /// Optional parent grant for delegated authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<RecordId>,
    /// Sorted unique granted capabilities.
    #[schemars(length(min = 1, max = MAX_CAPABILITIES))]
    pub capabilities: Vec<Capability>,
    /// Sorted unique project scope.
    #[schemars(length(min = 1, max = MAX_SCOPE_PROJECTS))]
    pub project_ids: Vec<RecordId>,
    /// Sorted unique processor identifiers.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES), inner(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES)))]
    pub processors: Vec<String>,
    /// First valid instant.
    pub not_before: UtcTimestamp,
    /// Exclusive expiry instant.
    pub expires_at: UtcTimestamp,
    /// Remaining permitted delegation depth.
    pub delegation_depth: u8,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for CapabilityGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityGrant")
            .field("schema_version", &self.schema_version)
            .field("grant_id", &self.grant_id)
            .field("capability_count", &self.capabilities.len())
            .field("project_count", &self.project_ids.len())
            .field("processor_count", &self.processors.len())
            .field("not_before", &self.not_before)
            .field("expires_at", &self.expires_at)
            .field("delegation_depth", &self.delegation_depth)
            .finish_non_exhaustive()
    }
}

impl CapabilityGrant {
    /// Verifies that this child grant only narrows a parent grant.
    pub fn validate_attenuation_of(&self, parent: &Self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.parent_grant_id.as_ref() != Some(&parent.grant_id)
            || self.issuer_id != parent.subject_id
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/parent_grant_id",
                "delegated grant parent or issuer does not match",
            ));
        }
        if !is_subset(&self.capabilities, &parent.capabilities)
            || !is_subset(&self.project_ids, &parent.project_ids)
            || !is_subset(&self.processors, &parent.processors)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/capabilities",
                "delegated grant cannot broaden capabilities or scope",
            ));
        }
        if self.not_before < parent.not_before
            || self.expires_at > parent.expires_at
            || self.delegation_depth >= parent.delegation_depth
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "delegated grant cannot broaden time or delegation depth",
            ));
        }
        errors.into_result()
    }
}

impl Validate for CapabilityGrant {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.capability-grant", &mut errors);
        validate_sorted_set(
            &self.capabilities,
            MAX_CAPABILITIES,
            true,
            "/capabilities",
            &mut errors,
        );
        validate_sorted_set(
            &self.project_ids,
            MAX_SCOPE_PROJECTS,
            true,
            "/project_ids",
            &mut errors,
        );
        validate_strings(&self.processors, false, "/processors", &mut errors);
        if self.expires_at <= self.not_before {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "grant expiry must be later than not-before",
            ));
        }
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Required coordination event kinds.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationEventKind {
    /// Immutable context commit was published.
    ContextCommitted,
    /// Atom became invalid for current selection.
    AtomInvalidated,
    /// Compiled bundle became invalid.
    BundleInvalidated,
    /// Task checkpoint was recorded.
    TaskCheckpointed,
    /// Handoff capsule was created.
    HandoffCreated,
    /// Handoff was accepted.
    HandoffAccepted,
    /// Handoff was revoked.
    HandoffRevoked,
    /// Child result was proposed.
    AgentResultProposed,
    /// Typed merge conflict was created.
    MergeConflictCreated,
    /// Effect journal state changed.
    EffectStateChanged,
    /// Policy snapshot changed.
    PolicySnapshotChanged,
}

/// One immutable ordered event in a context commit.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationEvent {
    /// Globally unique event identity for deduplication.
    pub event_id: RecordId,
    /// Closed event kind.
    pub kind: CoordinationEventKind,
    /// Digest of the typed event payload.
    pub payload_digest: ContentDigest,
}

/// Immutable context-space commit.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCommit {
    /// Must be `cigar.context-commit.v1`.
    pub schema_version: SchemaVersion,
    /// Content-derived commit identity.
    pub commit_id: VersionId,
    /// Owning context space.
    pub space_id: ContextSpaceId,
    /// Monotonic sequence beginning at one.
    pub sequence: u64,
    /// Parent commit, absent only for sequence one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_commit_id: Option<VersionId>,
    /// Authenticated author.
    pub author_id: RecordId,
    /// Bounded publication purpose.
    #[schemars(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES))]
    pub purpose: String,
    /// Ordered immutable events.
    #[schemars(length(min = 1, max = MAX_COORDINATION_EVENTS))]
    pub events: Vec<CoordinationEvent>,
    /// Resulting context-space root digest.
    pub root_digest: ContentDigest,
    /// Policy snapshot used for publication.
    pub policy_snapshot_digest: ContentDigest,
    /// Commit time.
    pub committed_at: UtcTimestamp,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for ContextCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextCommit")
            .field("schema_version", &self.schema_version)
            .field("commit_id", &self.commit_id)
            .field("sequence", &self.sequence)
            .field("purpose_bytes", &self.purpose.len())
            .field("event_count", &self.events.len())
            .field("root_digest", &self.root_digest)
            .field("policy_snapshot_digest", &self.policy_snapshot_digest)
            .field("committed_at", &self.committed_at)
            .finish_non_exhaustive()
    }
}

impl Validate for ContextCommit {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.context-commit", &mut errors);
        if self.sequence == 0 || (self.sequence == 1) != self.parent_commit_id.is_none() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/parent_commit_id",
                "only sequence one may omit its parent commit",
            ));
        }
        validate_text(&self.purpose, "/purpose", &mut errors);
        if self.events.is_empty() || self.events.len() > MAX_COORDINATION_EVENTS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/events",
                "commit events must be non-empty and bounded",
            ));
        }
        let event_ids: Vec<_> = self.events.iter().map(|event| &event.event_id).collect();
        if !all_unique(&event_ids) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/events",
                "commit event identities must be unique",
            ));
        }
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Typed private overlay mutation; order is semantically significant.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "digest",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OverlayMutation {
    /// Proposed atom version.
    Atom(VersionId),
    /// Proposed decision record.
    Decision(VersionId),
    /// Proposed task-state record.
    State(VersionId),
    /// Proposed artifact record.
    Artifact(VersionId),
    /// Proposed instruction record requiring typed resolution.
    Instruction(VersionId),
    /// Proposed capability record requiring exact-base resolution.
    Capability(VersionId),
    /// Proposed lease record requiring exact-base resolution.
    Lease(VersionId),
    /// Proposed effect-state record requiring exact-base resolution.
    Effect(VersionId),
}

/// Private overlay over one immutable base commit.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    /// Must be `cigar.overlay.v1`.
    pub schema_version: SchemaVersion,
    /// Unique overlay identity.
    pub overlay_id: RecordId,
    /// Owning context space.
    pub space_id: ContextSpaceId,
    /// Exact immutable merge base.
    pub base_commit_id: VersionId,
    /// Principal allowed to observe and mutate this overlay.
    pub owner_id: RecordId,
    /// Creation time.
    pub created_at: UtcTimestamp,
    /// Expiry time.
    pub expires_at: UtcTimestamp,
    /// Ordered proposed mutations.
    #[schemars(length(max = MAX_COORDINATION_EVENTS))]
    pub mutations: Vec<OverlayMutation>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for Overlay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Overlay")
            .field("schema_version", &self.schema_version)
            .field("overlay_id", &self.overlay_id)
            .field("base_commit_id", &self.base_commit_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("mutation_count", &self.mutations.len())
            .finish_non_exhaustive()
    }
}

impl Validate for Overlay {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.overlay", &mut errors);
        if self.expires_at <= self.created_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "overlay expiry must be later than creation",
            ));
        }
        if self.mutations.len() > MAX_COORDINATION_EVENTS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/mutations",
                "overlay mutation collection exceeds the maximum",
            ));
        }
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Recipient selector bound into a handoff capsule.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecipientSelector {
    /// Exact recipient principal.
    Principal(RecordId),
    /// Bounded recipient role resolved again during acceptance.
    Role(#[schemars(length(min = 1, max = MAX_COORDINATION_SELECTOR_BYTES))] String),
}

impl fmt::Debug for RecipientSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Principal(principal) => {
                formatter.debug_tuple("Principal").field(principal).finish()
            }
            Self::Role(role) => formatter
                .debug_struct("Role")
                .field("bytes", &role.len())
                .finish(),
        }
    }
}

/// Closed subscription topics declared by a handoff.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationTopic {
    /// Atom invalidation events.
    AtomInvalidation,
    /// Bundle invalidation events.
    BundleInvalidation,
    /// Task checkpoint events.
    TaskCheckpoint,
    /// Handoff revocation events.
    HandoffRevocation,
    /// Effect state changes.
    EffectState,
    /// Policy snapshot changes.
    PolicySnapshot,
}

/// Typed references carried by a handoff instead of a parent transcript.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffReferences {
    /// Sorted source version references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub sources: Vec<VersionId>,
    /// Sorted task-state references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub states: Vec<VersionId>,
    /// Sorted decision references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub decisions: Vec<VersionId>,
    /// Sorted artifact references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub artifacts: Vec<VersionId>,
    /// Sorted uncertainty references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub uncertainties: Vec<VersionId>,
    /// Sorted effect journal record references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub effects: Vec<VersionId>,
}

/// Signed portable handoff capsule.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffCapsule {
    /// Must be `cigar.handoff.v1`.
    pub schema_version: SchemaVersion,
    /// Unique capsule identity.
    pub handoff_id: RecordId,
    /// Issuing principal.
    pub issuer_id: RecordId,
    /// Recipient selector and audience binding.
    pub recipient: RecipientSelector,
    /// Bounded task statement.
    #[schemars(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES))]
    pub task: String,
    /// Bounded acceptance criteria.
    #[schemars(length(min = 1, max = MAX_HANDOFF_REFERENCES), inner(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES)))]
    pub acceptance_criteria: Vec<String>,
    /// Sorted exact project scope.
    #[schemars(length(min = 1, max = MAX_SCOPE_PROJECTS))]
    pub project_ids: Vec<RecordId>,
    /// Sorted attenuated capabilities delegated by the issuer.
    #[schemars(length(max = MAX_CAPABILITIES))]
    pub delegated_capabilities: Vec<Capability>,
    /// Sorted requested capabilities rejected during creation.
    #[schemars(length(max = MAX_CAPABILITIES))]
    pub rejected_capabilities: Vec<Capability>,
    /// Recipient compilation budget ceiling.
    pub budget: Budget,
    /// Sorted declared subscription topics.
    #[schemars(length(max = MAX_COORDINATION_TOPICS))]
    pub topics: Vec<CoordinationTopic>,
    /// Typed references; unrestricted transcript is intentionally absent.
    pub references: HandoffReferences,
    /// Issuer bundle at handoff creation.
    pub bundle_id: VersionId,
    /// Signed audience identifier.
    #[schemars(length(min = 1, max = MAX_COORDINATION_SELECTOR_BYTES))]
    pub audience: String,
    /// Capsule creation time.
    pub created_at: UtcTimestamp,
    /// Exclusive capsule expiry.
    pub expires_at: UtcTimestamp,
    /// Replay-protection nonce encoded as unpadded base64url in JSON.
    #[schemars(with = "String")]
    #[schemars(length(min = 2, max = 86))]
    #[serde(with = "base64url")]
    pub nonce: Vec<u8>,
    /// Whether multiple valid acceptances are permitted.
    pub reusable: bool,
    /// Issuer signing-key identifier.
    #[schemars(length(min = 1, max = MAX_COORDINATION_SELECTOR_BYTES))]
    pub issuer_key_id: String,
    /// Ed25519 signature bytes populated by WP02.
    #[schemars(with = "String")]
    #[schemars(length(min = 2, max = 683))]
    #[serde(with = "base64url")]
    pub signature: Vec<u8>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for HandoffCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffCapsule")
            .field("schema_version", &self.schema_version)
            .field("handoff_id", &self.handoff_id)
            .field("recipient", &self.recipient)
            .field("task_bytes", &self.task.len())
            .field("criteria_count", &self.acceptance_criteria.len())
            .field("project_count", &self.project_ids.len())
            .field(
                "delegated_capability_count",
                &self.delegated_capabilities.len(),
            )
            .field("reference_counts", &reference_counts(&self.references))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("nonce_bytes", &self.nonce.len())
            .field("signature_bytes", &self.signature.len())
            .finish_non_exhaustive()
    }
}

impl Validate for HandoffCapsule {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.handoff", &mut errors);
        validate_text(&self.task, "/task", &mut errors);
        validate_strings(
            &self.acceptance_criteria,
            true,
            "/acceptance_criteria",
            &mut errors,
        );
        validate_sorted_set(
            &self.project_ids,
            MAX_SCOPE_PROJECTS,
            true,
            "/project_ids",
            &mut errors,
        );
        validate_sorted_set(
            &self.delegated_capabilities,
            MAX_CAPABILITIES,
            false,
            "/delegated_capabilities",
            &mut errors,
        );
        validate_sorted_set(
            &self.rejected_capabilities,
            MAX_CAPABILITIES,
            false,
            "/rejected_capabilities",
            &mut errors,
        );
        if self
            .delegated_capabilities
            .iter()
            .any(|capability| self.rejected_capabilities.contains(capability))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/rejected_capabilities",
                "capability cannot be both delegated and rejected",
            ));
        }
        validate_sorted_set(
            &self.topics,
            MAX_COORDINATION_TOPICS,
            false,
            "/topics",
            &mut errors,
        );
        validate_references(&self.references, &mut errors);
        validate_selector(&self.recipient, &mut errors);
        validate_bounded_selector(&self.audience, "/audience", &mut errors);
        validate_bounded_selector(&self.issuer_key_id, "/issuer_key_id", &mut errors);
        if self.expires_at <= self.created_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "handoff expiry must be later than creation",
            ));
        }
        if self.nonce.is_empty() || self.nonce.len() > MAX_NONCE_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/nonce",
                "handoff nonce must be non-empty and bounded",
            ));
        }
        if self.signature.is_empty() || self.signature.len() > MAX_SIGNATURE_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/signature",
                "handoff signature must be non-empty and bounded",
            ));
        }
        validate_budget(&self.budget, &mut errors);
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Persisted recipient-specific handoff acceptance receipt.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffAcceptance {
    /// Must be `cigar.handoff-acceptance.v1`.
    pub schema_version: SchemaVersion,
    /// Unique acceptance identity.
    pub acceptance_id: RecordId,
    /// Accepted capsule identity.
    pub handoff_id: RecordId,
    /// Actual authenticated recipient.
    pub recipient_id: RecordId,
    /// Sorted capabilities accepted after current-policy reauthorization.
    #[schemars(length(max = MAX_CAPABILITIES))]
    pub accepted_capabilities: Vec<Capability>,
    /// Sorted capabilities rejected at acceptance.
    #[schemars(length(max = MAX_CAPABILITIES))]
    pub rejected_capabilities: Vec<Capability>,
    /// Sorted inaccessible references without content disclosure.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub unavailable_references: Vec<VersionId>,
    /// Current policy decision digest.
    pub policy_digest: ContentDigest,
    /// Recipient-specific bundle identity.
    pub bundle_id: VersionId,
    /// Acceptance time.
    pub accepted_at: UtcTimestamp,
    /// Recipient acknowledgement digest.
    pub acknowledgement_digest: ContentDigest,
}

impl HandoffAcceptance {
    /// Ensures accepted capabilities never exceed the signed capsule delegation.
    pub fn validate_against(&self, capsule: &HandoffCapsule) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.handoff_id != capsule.handoff_id
            || !is_subset(&self.accepted_capabilities, &capsule.delegated_capabilities)
            || self.accepted_at >= capsule.expires_at
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/accepted_capabilities",
                "acceptance does not match or attenuate the signed capsule",
            ));
        }
        if let RecipientSelector::Principal(expected) = &capsule.recipient
            && expected != &self.recipient_id
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/recipient_id",
                "acceptance recipient does not match capsule audience",
            ));
        }
        errors.into_result()
    }
}

impl Validate for HandoffAcceptance {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.handoff-acceptance",
            &mut errors,
        );
        validate_sorted_set(
            &self.accepted_capabilities,
            MAX_CAPABILITIES,
            false,
            "/accepted_capabilities",
            &mut errors,
        );
        validate_sorted_set(
            &self.rejected_capabilities,
            MAX_CAPABILITIES,
            false,
            "/rejected_capabilities",
            &mut errors,
        );
        validate_sorted_set(
            &self.unavailable_references,
            MAX_HANDOFF_REFERENCES,
            false,
            "/unavailable_references",
            &mut errors,
        );
        errors.into_result()
    }
}

/// Evidence-backed claim returned by a child agent.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultClaim {
    /// Bounded claim text.
    #[schemars(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES))]
    pub claim: String,
    /// Sorted unique evidence versions.
    #[schemars(length(min = 1, max = MAX_HANDOFF_REFERENCES))]
    pub evidence: Vec<VersionId>,
}

impl fmt::Debug for ResultClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultClaim")
            .field("claim_bytes", &self.claim.len())
            .field("evidence_count", &self.evidence.len())
            .finish()
    }
}

/// Typed child result proposed against an exact base snapshot.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffDelta {
    /// Must be `cigar.handoff-delta.v1`.
    pub schema_version: SchemaVersion,
    /// Unique result identity.
    pub delta_id: RecordId,
    /// Exact handoff capsule identity.
    pub handoff_id: RecordId,
    /// Exact base context commit.
    pub base_commit_id: VersionId,
    /// Authenticated result producer.
    pub producer_id: RecordId,
    /// Evidence-backed result claims.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub claims: Vec<ResultClaim>,
    /// Sorted decision record references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub decisions: Vec<VersionId>,
    /// Sorted artifact references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub artifacts: Vec<VersionId>,
    /// Sorted source-change references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub source_changes: Vec<VersionId>,
    /// Sorted verifier receipt references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub verifier_receipts: Vec<VersionId>,
    /// Bounded unresolved questions.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES), inner(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES)))]
    pub unresolved_questions: Vec<String>,
    /// Bounded blockers.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES), inner(length(min = 1, max = MAX_HANDOFF_TEXT_BYTES)))]
    pub blockers: Vec<String>,
    /// Sorted effect journal references.
    #[schemars(length(max = MAX_HANDOFF_REFERENCES))]
    pub effect_references: Vec<VersionId>,
    /// Sorted follow-up capabilities requested, not granted.
    #[schemars(length(max = MAX_CAPABILITIES))]
    pub requested_followup_capabilities: Vec<Capability>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for HandoffDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffDelta")
            .field("schema_version", &self.schema_version)
            .field("delta_id", &self.delta_id)
            .field("base_commit_id", &self.base_commit_id)
            .field("claim_count", &self.claims.len())
            .field("decision_count", &self.decisions.len())
            .field("artifact_count", &self.artifacts.len())
            .field("source_change_count", &self.source_changes.len())
            .field("verifier_receipt_count", &self.verifier_receipts.len())
            .field("question_count", &self.unresolved_questions.len())
            .field("blocker_count", &self.blockers.len())
            .field("effect_count", &self.effect_references.len())
            .finish_non_exhaustive()
    }
}

impl Validate for HandoffDelta {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.handoff-delta", &mut errors);
        if self.claims.len() > MAX_HANDOFF_REFERENCES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/claims",
                "claim collection exceeds the maximum",
            ));
        }
        for (index, claim) in self.claims.iter().enumerate() {
            validate_text(&claim.claim, &format!("/claims/{index}/claim"), &mut errors);
            validate_sorted_set(
                &claim.evidence,
                MAX_HANDOFF_REFERENCES,
                true,
                &format!("/claims/{index}/evidence"),
                &mut errors,
            );
        }
        for (path, values) in [
            ("/decisions", &self.decisions),
            ("/artifacts", &self.artifacts),
            ("/source_changes", &self.source_changes),
            ("/verifier_receipts", &self.verifier_receipts),
            ("/effect_references", &self.effect_references),
        ] {
            validate_sorted_set(values, MAX_HANDOFF_REFERENCES, false, path, &mut errors);
        }
        validate_strings(
            &self.unresolved_questions,
            false,
            "/unresolved_questions",
            &mut errors,
        );
        validate_strings(&self.blockers, false, "/blockers", &mut errors);
        validate_sorted_set(
            &self.requested_followup_capabilities,
            MAX_CAPABILITIES,
            false,
            "/requested_followup_capabilities",
            &mut errors,
        );
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Closed lease resource types requiring exact-base merge.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    /// Exclusive task mutation lease.
    Task,
    /// Exclusive decision resolution lease.
    Decision,
    /// Exclusive effect reconciliation lease.
    EffectReconciliation,
    /// Exclusive publication lease.
    Publication,
}

/// Closed lease lifecycle.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// Lease may currently authorize its bounded operation.
    Active,
    /// Holder explicitly released the lease.
    Released,
    /// Lease passed its expiry.
    Expired,
    /// Authority explicitly revoked the lease.
    Revoked,
}

/// Optimistically revised lease over one immutable resource identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    /// Must be `cigar.lease.v1`.
    pub schema_version: SchemaVersion,
    /// Unique lease identity.
    pub lease_id: RecordId,
    /// Immutable leased resource identity.
    pub resource_id: VersionId,
    /// Current holder principal.
    pub holder_id: RecordId,
    /// Lease type.
    pub kind: LeaseKind,
    /// Current lifecycle state.
    pub state: LeaseState,
    /// Acquisition time.
    pub acquired_at: UtcTimestamp,
    /// Exclusive expiry.
    pub expires_at: UtcTimestamp,
    /// Expected revision for the next mutation.
    pub expected_revision: ExpectedRevision,
}

impl Validate for Lease {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.lease", &mut errors);
        if self.expires_at <= self.acquired_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "lease expiry must be later than acquisition",
            ));
        }
        errors.into_result()
    }
}

fn validate_version(version: &SchemaVersion, family: &str, errors: &mut ValidationErrors) {
    if let Err(found) = version.require_v1(family) {
        errors.merge(found);
    }
}

fn validate_extensions(extensions: &ExtensionMap, errors: &mut ValidationErrors) {
    if let Err(found) = extensions.validate_known(&BTreeSet::new()) {
        errors.merge(found);
    }
}

fn validate_text(value: &str, path: &str, errors: &mut ValidationErrors) {
    if value.trim().is_empty() || value.len() > MAX_HANDOFF_TEXT_BYTES {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            path,
            "text must be non-empty and bounded",
        ));
    }
}

fn validate_bounded_selector(value: &str, path: &str, errors: &mut ValidationErrors) {
    if value.is_empty() || value.len() > MAX_COORDINATION_SELECTOR_BYTES {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            path,
            "selector must be non-empty and bounded",
        ));
    }
}

fn validate_selector(selector: &RecipientSelector, errors: &mut ValidationErrors) {
    if let RecipientSelector::Role(role) = selector {
        validate_bounded_selector(role, "/recipient", errors);
    }
}

fn validate_strings(values: &[String], non_empty: bool, path: &str, errors: &mut ValidationErrors) {
    if (non_empty && values.is_empty()) || values.len() > MAX_HANDOFF_REFERENCES {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            path,
            "text collection is empty or exceeds the maximum",
        ));
    }
    for value in values {
        validate_text(value, path, errors);
    }
}

fn validate_sorted_set<T: Ord>(
    values: &[T],
    maximum: usize,
    non_empty: bool,
    path: &str,
    errors: &mut ValidationErrors,
) {
    if (non_empty && values.is_empty()) || values.len() > maximum || !strictly_sorted_unique(values)
    {
        errors.push(issue(
            ValidationCode::InvalidValue,
            path,
            "collection must be bounded, sorted, and unique",
        ));
    }
}

fn validate_references(references: &HandoffReferences, errors: &mut ValidationErrors) {
    for (path, values) in [
        ("/references/sources", &references.sources),
        ("/references/states", &references.states),
        ("/references/decisions", &references.decisions),
        ("/references/artifacts", &references.artifacts),
        ("/references/uncertainties", &references.uncertainties),
        ("/references/effects", &references.effects),
    ] {
        validate_sorted_set(values, MAX_HANDOFF_REFERENCES, false, path, errors);
    }
}

fn validate_budget(budget: &Budget, errors: &mut ValidationErrors) {
    let sum = budget
        .lane_input_tokens
        .values()
        .try_fold(0_u32, |total, value| total.checked_add(*value));
    if budget.total_input_tokens == 0
        || sum != Some(budget.total_input_tokens)
        || budget.lane_input_tokens.values().any(|value| *value == 0)
    {
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/budget",
            "handoff budget lanes must be non-zero and sum exactly to the total",
        ));
    }
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|window| match (window.first(), window.get(1)) {
            (Some(first), Some(second)) => first < second,
            _ => false,
        })
}

fn all_unique<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

fn is_subset<T: Ord>(child: &[T], parent: &[T]) -> bool {
    child
        .iter()
        .all(|value| parent.binary_search(value).is_ok())
}

fn reference_counts(references: &HandoffReferences) -> [usize; 6] {
    [
        references.sources.len(),
        references.states.len(),
        references.decisions.len(),
        references.artifacts.len(),
        references.uncertainties.len(),
        references.effects.len(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, CapabilityGrant, ContextCommit, CoordinationEvent, CoordinationEventKind,
        HandoffAcceptance, HandoffCapsule, HandoffReferences, Lease, LeaseKind, LeaseState,
        RecipientSelector,
    };
    use crate::{
        Budget, ContentDigest, ContextSpaceId, ExpectedRevision, ExtensionMap, LaneKind, RecordId,
        UtcTimestamp, Validate, VersionId,
    };
    use std::collections::BTreeMap;

    fn record(last: char) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f789{last}"
        ))?)
    }

    fn grant() -> Result<CapabilityGrant, Box<dyn std::error::Error>> {
        Ok(CapabilityGrant {
            schema_version: "cigar.capability-grant.v1".parse()?,
            grant_id: record('0')?,
            issuer_id: record('1')?,
            subject_id: record('2')?,
            parent_grant_id: None,
            capabilities: vec![Capability::ReadContext, Capability::WriteOverlay],
            project_ids: vec![record('3')?],
            processors: vec!["local".to_owned()],
            not_before: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            expires_at: UtcTimestamp::parse_rfc3339("2026-07-11T00:00:00Z")?,
            delegation_depth: 2,
            extensions: ExtensionMap::default(),
        })
    }

    fn content(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn capsule() -> Result<HandoffCapsule, Box<dyn std::error::Error>> {
        let mut lane_input_tokens = BTreeMap::new();
        lane_input_tokens.insert(LaneKind::Task, 1_000);
        Ok(HandoffCapsule {
            schema_version: "cigar.handoff.v1".parse()?,
            handoff_id: record('8')?,
            issuer_id: record('1')?,
            recipient: RecipientSelector::Principal(record('2')?),
            task: "Verify the bounded fixture".to_owned(),
            acceptance_criteria: vec!["All checks pass".to_owned()],
            project_ids: vec![record('3')?],
            delegated_capabilities: vec![Capability::ReadContext],
            rejected_capabilities: vec![Capability::ApproveEffect],
            budget: Budget {
                total_input_tokens: 1_000,
                output_reserve_tokens: 500,
                lane_input_tokens,
            },
            topics: Vec::new(),
            references: HandoffReferences::default(),
            bundle_id: version('a')?,
            audience: "fixture-agent".to_owned(),
            created_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            expires_at: UtcTimestamp::parse_rfc3339("2026-07-11T00:00:00Z")?,
            nonce: vec![1; 32],
            reusable: false,
            issuer_key_id: "fixture-key".to_owned(),
            signature: vec![2; 64],
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn capability_attenuation_rejects_scope_broadening() -> Result<(), Box<dyn std::error::Error>> {
        let parent = grant()?;
        let mut child = CapabilityGrant {
            schema_version: "cigar.capability-grant.v1".parse()?,
            grant_id: record('4')?,
            issuer_id: parent.subject_id.clone(),
            subject_id: record('5')?,
            parent_grant_id: Some(parent.grant_id.clone()),
            capabilities: vec![Capability::ReadContext],
            project_ids: parent.project_ids.clone(),
            processors: parent.processors.clone(),
            not_before: parent.not_before,
            expires_at: parent.expires_at,
            delegation_depth: 1,
            extensions: ExtensionMap::default(),
        };
        child.validate_attenuation_of(&parent)?;
        child.capabilities.push(Capability::ApproveEffect);
        child.capabilities.sort();
        assert!(child.validate_attenuation_of(&parent).is_err());
        Ok(())
    }

    #[test]
    fn lease_rejects_non_positive_interval() -> Result<(), Box<dyn std::error::Error>> {
        let instant = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?;
        let lease = Lease {
            schema_version: "cigar.lease.v1".parse()?,
            lease_id: record('6')?,
            resource_id: VersionId::new(format!("1220{}", "a".repeat(64)))?,
            holder_id: record('7')?,
            kind: LeaseKind::Task,
            state: LeaseState::Active,
            acquired_at: instant,
            expires_at: instant,
            expected_revision: ExpectedRevision(1),
        };
        assert!(lease.validate().is_err());
        Ok(())
    }

    #[test]
    fn handoff_acceptance_rechecks_recipient_and_capability_attenuation()
    -> Result<(), Box<dyn std::error::Error>> {
        let capsule = capsule()?;
        capsule.validate()?;
        let mut acceptance = HandoffAcceptance {
            schema_version: "cigar.handoff-acceptance.v1".parse()?,
            acceptance_id: record('9')?,
            handoff_id: capsule.handoff_id.clone(),
            recipient_id: record('2')?,
            accepted_capabilities: vec![Capability::ReadContext],
            rejected_capabilities: Vec::new(),
            unavailable_references: Vec::new(),
            policy_digest: content('b')?,
            bundle_id: version('c')?,
            accepted_at: UtcTimestamp::parse_rfc3339("2026-07-10T12:00:00Z")?,
            acknowledgement_digest: content('d')?,
        };
        acceptance.validate()?;
        acceptance.validate_against(&capsule)?;
        acceptance.accepted_capabilities = vec![Capability::ApproveEffect];
        assert!(acceptance.validate_against(&capsule).is_err());
        Ok(())
    }

    #[test]
    fn handoff_debug_redacts_task_nonce_signature_and_audience()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut capsule = capsule()?;
        capsule.task = "sensitive-task-canary".to_owned();
        capsule.audience = "sensitive-audience-canary".to_owned();
        let rendered = format!("{capsule:?}");
        assert!(!rendered.contains("sensitive"));
        assert!(!rendered.contains("AQEBAQ"));
        Ok(())
    }

    #[test]
    fn context_commit_requires_genesis_parent_invariant() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut commit = ContextCommit {
            schema_version: "cigar.context-commit.v1".parse()?,
            commit_id: version('e')?,
            space_id: ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7880")?,
            sequence: 1,
            parent_commit_id: None,
            author_id: record('1')?,
            purpose: "checkpoint".to_owned(),
            events: vec![CoordinationEvent {
                event_id: record('4')?,
                kind: CoordinationEventKind::TaskCheckpointed,
                payload_digest: content('f')?,
            }],
            root_digest: content('a')?,
            policy_snapshot_digest: content('b')?,
            committed_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            extensions: ExtensionMap::default(),
        };
        commit.validate()?;
        commit.sequence = 2;
        assert!(commit.validate().is_err());
        Ok(())
    }
}
