//! Stable policy inputs, decisions, rule profiles, and invalidation contracts.

use cigar_protocol::{
    Capability, Classification, ContentDigest, InstructionAuthority, Lifecycle, RecordId,
    RiskLevel, UtcTimestamp,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum declarative rules in one compiled profile.
pub const MAX_POLICY_RULES: usize = 10_000;
/// Maximum selector values in one rule or request.
pub const MAX_POLICY_SELECTORS: usize = 1_024;
/// Maximum policy identifier, selector, condition, or pointer bytes.
pub const MAX_POLICY_TEXT_BYTES: usize = 512;

/// Stable content-free policy failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyErrorCode {
    /// A profile, rule, request, pointer, grant, or signature is malformed.
    InvalidInput,
    /// A configured bound was exceeded.
    LimitExceeded,
    /// Required protected policy state is unavailable.
    Unavailable,
    /// A rule dependency graph contains a cycle or missing dependency.
    InvalidRuleGraph,
    /// A capability signature, scope, time, or attenuation proof failed.
    InvalidCapability,
    /// A grant, principal, resource, or dependency is currently revoked.
    Revoked,
    /// Structural redaction cannot preserve a required field.
    RequiredField,
}

/// Secret-safe policy error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PolicyError {
    code: PolicyErrorCode,
}

impl PolicyError {
    /// Creates a stable content-free policy failure.
    #[must_use]
    pub const fn new(code: PolicyErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable category.
    #[must_use]
    pub const fn code(self) -> PolicyErrorCode {
        self.code
    }
}

impl fmt::Debug for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "policy operation failed: {:?}", self.code)
    }
}

impl std::error::Error for PolicyError {}

/// Closed policy resource classes sharing one non-bypassable kernel.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyResource {
    /// Authorization-domain construction before retrieval.
    Partition,
    /// Metadata eligibility before candidate generation.
    Metadata,
    /// Protected content loading or transformation.
    Content,
    /// Local or external processor invocation.
    Processor,
    /// Compiled bundle serving or materialization.
    Bundle,
    /// Handoff creation or acceptance.
    Handoff,
    /// External effect proposal, approval, dispatch, or reconciliation.
    Effect,
}

/// Precedence-ordered policy outcomes; smaller values dominate larger values.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Ineligible without caller-visible existence disclosure.
    Deny,
    /// Withheld due to integrity or security state.
    Quarantine,
    /// A fresher canonical dependency is required.
    RequireRefresh,
    /// Eligible only after exact structural redaction.
    Redact,
    /// Eligible only after a distinct approval record.
    RequireApproval,
    /// Eligible under all hard and declarative gates.
    Allow,
}

/// Stable reason categories that never contain protected identifiers.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReason {
    /// Every applicable gate and rule allowed the operation.
    Allowed,
    /// Tenant identity did not match.
    TenantMismatch,
    /// Project or explicit request scope did not match.
    ScopeDenied,
    /// Principal is disabled or revoked.
    PrincipalDenied,
    /// Required delegated authority is absent, expired, or revoked.
    CapabilityDenied,
    /// Purpose is not authorized.
    PurposeDenied,
    /// Processor is not authorized.
    ProcessorDenied,
    /// Classification exceeds the caller bound.
    ClassificationDenied,
    /// Lifecycle or integrity requires withholding.
    IntegrityDenied,
    /// World-valid, observation, freshness, or expiry time failed.
    TemporalDenied,
    /// Instruction authority exceeds the permitted lane.
    InstructionAuthorityDenied,
    /// Contract exclusion or target modality rejected the resource.
    ContractDenied,
    /// Effect operation, target, risk, approval, retry, or fencing failed.
    EffectDenied,
    /// A compiled declarative rule determined the result.
    DeclarativeRule,
    /// An older policy-bound artifact must be refreshed.
    PolicyChanged,
    /// A current revocation prevents use.
    Revoked,
}

/// Caller disclosure behavior for decisions and metrics.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    /// Caller receives the same absent class as an unknown resource.
    DeniedExistence,
    /// Stable reason may be returned to the authenticated caller.
    CallerVisible,
    /// Details are restricted to protected audit views.
    AuditOnly,
}

/// Fixed response timing buckets used instead of resource-dependent timing detail.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TimingClass {
    /// Denied-existence response bucket.
    Denied,
    /// Eligible or conditionally eligible response bucket.
    Eligible,
}

/// One immutable declarative policy rule.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Stable normalized identifier.
    pub id: String,
    /// Lower values evaluate first; outcome precedence remains authoritative.
    pub priority: i32,
    /// Rule dependencies forming a compiled DAG.
    pub depends_on: BTreeSet<String>,
    /// Resource classes matched by this rule; empty means every class.
    pub resources: BTreeSet<PolicyResource>,
    /// Principal identities matched by this rule; empty means every principal.
    pub principal_ids: BTreeSet<RecordId>,
    /// Tenant identities matched by this rule; empty means every tenant.
    pub tenant_ids: BTreeSet<RecordId>,
    /// Project identities matched by this rule; empty means every project.
    pub project_ids: BTreeSet<RecordId>,
    /// Exact purpose selectors; empty means every purpose.
    pub purposes: BTreeSet<String>,
    /// Exact processor selectors; empty means every processor.
    pub processors: BTreeSet<String>,
    /// Optional minimum classification for the match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_at_least: Option<Classification>,
    /// Deterministic action.
    pub action: PolicyOutcome,
    /// Structural JSON-pointer redactions contributed by matching rules.
    pub redaction_paths: BTreeSet<String>,
    /// Stable content-free conditions recorded in the decision.
    pub conditions: BTreeSet<String>,
}

/// Canonical declarative v1 policy profile.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProfile {
    /// Must be `cigar.policy-profile.v1`.
    pub schema_version: String,
    /// Monotonic policy revision.
    pub revision: u64,
    /// Whether absence or evaluation failure must fail closed.
    pub protected: bool,
    /// Deterministic declarative rule set.
    pub rules: Vec<PolicyRule>,
}

/// Immutable compiled policy snapshot metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    /// Monotonic installed revision.
    pub revision: u64,
    /// Canonical profile and compiled-DAG digest.
    pub policy_digest: ContentDigest,
    /// Deterministic caller-supplied activation time.
    pub activated_at: UtcTimestamp,
    /// Whether protected operations fail when this snapshot is unavailable.
    pub protected: bool,
}

/// Capability resolution fixed before a policy call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityContext {
    /// Authenticated subject.
    pub subject_id: RecordId,
    /// Current grant identity, when delegated authority is used.
    pub grant_id: Option<RecordId>,
    /// Exact effective capabilities after signature and attenuation verification.
    pub capabilities: BTreeSet<Capability>,
    /// Exact effective project scope.
    pub project_ids: BTreeSet<RecordId>,
    /// Exact effective processor scope.
    pub processors: BTreeSet<String>,
    /// Exclusive capability expiry.
    pub expires_at: UtcTimestamp,
}

/// Complete metadata-only hard-gate request shared by all policy entry points.
#[derive(Clone, Eq, PartialEq)]
pub struct PolicyRequest {
    /// Resource class being authorized.
    pub resource: PolicyResource,
    /// Digest of exact normalized protected inputs.
    pub input_digest: ContentDigest,
    /// Authenticated principal.
    pub principal_id: RecordId,
    /// Whether current principal state is active.
    pub principal_active: bool,
    /// Owning resource tenant.
    pub tenant_id: RecordId,
    /// Authenticated tenant boundary.
    pub authenticated_tenant_id: RecordId,
    /// Resource project when project scoped.
    pub project_id: Option<RecordId>,
    /// Explicit requested project scope.
    pub allowed_project_ids: BTreeSet<RecordId>,
    /// Declared non-authoritative purpose.
    pub purpose: String,
    /// Allowed purposes from current metadata/ACL state.
    pub allowed_purposes: BTreeSet<String>,
    /// Processor receiving protected data, when any.
    pub processor: Option<String>,
    /// Allowed processors from current policy/ACL state.
    pub allowed_processors: BTreeSet<String>,
    /// Resource classification.
    pub classification: Classification,
    /// Maximum caller-visible classification.
    pub maximum_classification: Classification,
    /// Whether current residency constraints permit this processing location.
    pub residency_allowed: bool,
    /// Whether current egress constraints permit the selected processor/target.
    pub egress_allowed: bool,
    /// Current immutable lifecycle.
    pub lifecycle: Lifecycle,
    /// Whether canonical integrity verification succeeded.
    pub integrity_verified: bool,
    /// World-valid instant.
    pub valid_at: UtcTimestamp,
    /// Inclusive valid start.
    pub valid_from: UtcTimestamp,
    /// Exclusive valid end.
    pub valid_until: Option<UtcTimestamp>,
    /// Observation time of the resource.
    pub observed_at: UtcTimestamp,
    /// Maximum observation time of the request snapshot.
    pub observed_as_of: UtcTimestamp,
    /// Optional exclusive freshness expiry.
    pub freshness_expires_at: Option<UtcTimestamp>,
    /// Resource instruction authority.
    pub instruction_authority: InstructionAuthority,
    /// Maximum authority permitted in the target lane.
    pub maximum_instruction_authority: InstructionAuthority,
    /// Whether an explicit contract exclusion matched.
    pub excluded: bool,
    /// Whether the target modality supports the resource.
    pub modality_supported: bool,
    /// Pre-resolved capability context.
    pub capability: Option<CapabilityContext>,
    /// Capability required for this operation, when any.
    pub required_capability: Option<Capability>,
    /// Policy digest bound into an older bundle/handoff/effect.
    pub bound_policy_digest: Option<ContentDigest>,
    /// Effect risk when authorizing an external mutation.
    pub effect_risk: Option<RiskLevel>,
    /// Whether a distinct valid approval is present.
    pub effect_approved: bool,
    /// Whether operation, target, retry, and risk-ceiling constraints passed.
    pub effect_constraints_satisfied: bool,
    /// Whether this operation requires a current fencing token.
    pub fencing_required: bool,
    /// Whether a current fencing token was verified when required.
    pub fencing_verified: bool,
    /// Exclusive upper bound for this authorization result.
    pub decision_expires_at: UtcTimestamp,
}

impl fmt::Debug for PolicyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyRequest")
            .field("resource", &self.resource)
            .field("input_digest", &self.input_digest)
            .field("principal_active", &self.principal_active)
            .field("has_project", &self.project_id.is_some())
            .field("allowed_project_count", &self.allowed_project_ids.len())
            .field("purpose_bytes", &self.purpose.len())
            .field("has_processor", &self.processor.is_some())
            .field("classification", &self.classification)
            .field("lifecycle", &self.lifecycle)
            .field("instruction_authority", &self.instruction_authority)
            .field("excluded", &self.excluded)
            .field("modality_supported", &self.modality_supported)
            .field("has_capability", &self.capability.is_some())
            .field("has_bound_policy", &self.bound_policy_digest.is_some())
            .field("effect_risk", &self.effect_risk)
            .finish_non_exhaustive()
    }
}

/// One deterministic hard-gate and declarative-rule result.
#[derive(Clone, Eq, PartialEq)]
pub struct PolicyDecision {
    /// Precedence-resolved result.
    pub outcome: PolicyOutcome,
    /// Stable content-free primary reason.
    pub reason: PolicyReason,
    /// Exact normalized input digest.
    pub input_digest: ContentDigest,
    /// Immutable policy snapshot digest.
    pub policy_digest: ContentDigest,
    /// Sorted exact redaction paths.
    pub redaction_paths: BTreeSet<String>,
    /// Sorted stable conditions.
    pub conditions: BTreeSet<String>,
    /// Decision validity never exceeds this instant.
    pub expires_at: UtcTimestamp,
    /// Caller-visible disclosure behavior.
    pub disclosure: DisclosureClass,
    /// Fixed response timing bucket.
    pub timing_class: TimingClass,
}

impl PolicyDecision {
    /// Produces a disclosure-filtered caller view with denied existence collapsed to absence.
    #[must_use]
    pub fn caller_view(&self) -> PolicyDecisionView {
        match self.disclosure {
            DisclosureClass::DeniedExistence => PolicyDecisionView {
                disposition: CallerDisposition::Absent,
                reason: None,
                timing_class: TimingClass::Denied,
            },
            DisclosureClass::CallerVisible => PolicyDecisionView {
                disposition: disposition(self.outcome),
                reason: Some(self.reason),
                timing_class: self.timing_class,
            },
            DisclosureClass::AuditOnly => PolicyDecisionView {
                disposition: disposition(self.outcome),
                reason: None,
                timing_class: self.timing_class,
            },
        }
    }
}

const fn disposition(outcome: PolicyOutcome) -> CallerDisposition {
    match outcome {
        PolicyOutcome::Deny | PolicyOutcome::Quarantine => CallerDisposition::Denied,
        PolicyOutcome::RequireRefresh | PolicyOutcome::Redact | PolicyOutcome::RequireApproval => {
            CallerDisposition::Conditional
        }
        PolicyOutcome::Allow => CallerDisposition::Allowed,
    }
}

/// Coarsened caller disposition that cannot disclose a denied resource identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerDisposition {
    /// Same response class as an unknown resource.
    Absent,
    /// Known operation denied without protected details.
    Denied,
    /// Known operation requires a stable condition.
    Conditional,
    /// Known operation allowed.
    Allowed,
}

/// Caller-safe decision view without policy/input digests, paths, conditions, or counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDecisionView {
    /// Coarsened disposition.
    pub disposition: CallerDisposition,
    /// Stable reason only when disclosure policy permits it.
    pub reason: Option<PolicyReason>,
    /// Fixed timing bucket.
    pub timing_class: TimingClass,
}

impl fmt::Debug for PolicyDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyDecision")
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("policy_digest", &self.policy_digest)
            .field("redaction_count", &self.redaction_paths.len())
            .field("condition_count", &self.conditions.len())
            .field("expires_at", &self.expires_at)
            .field("disclosure", &self.disclosure)
            .field("timing_class", &self.timing_class)
            .finish()
    }
}

/// High-priority event preventing stale policy-bound artifacts from serving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyInvalidationEvent {
    /// Monotonic policy revision or revocation epoch.
    pub sequence: u64,
    /// Prior installed policy digest, when any.
    pub previous_policy_digest: Option<ContentDigest>,
    /// Current installed policy digest.
    pub policy_digest: ContentDigest,
    /// Stable invalidation category.
    pub reason: PolicyInvalidationReason,
    /// Deterministic event time supplied by the caller.
    pub occurred_at: UtcTimestamp,
}

/// Policy invalidation categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyInvalidationReason {
    /// Compiled policy profile changed.
    PolicyChanged,
    /// Principal, grant, resource, or ACL state was revoked.
    Revoked,
}
