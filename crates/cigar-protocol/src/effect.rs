//! Intent-first external effect records, journal states, receipts, and reconciliation.

use crate::limits::{
    MAX_EFFECT_PRECONDITIONS, MAX_EFFECT_SELECTOR_BYTES, MAX_RECONCILIATION_EVIDENCE,
};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    BlobRef, Capability, ContentDigest, ExtensionMap, IdempotencyKey, RecordId, SchemaVersion,
    UtcTimestamp, Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Closed effect journal projection states.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    /// Durable intent exists and no external action occurred.
    Prepared,
    /// Intent is waiting for required approval.
    PendingApproval,
    /// Current policy, capability, and approval authorize dispatch.
    Authorized,
    /// An approved worker owns a durable fenced attempt.
    Dispatching,
    /// Connector and verification confirm success.
    Succeeded,
    /// Connector or reconciliation confirms failure.
    Failed,
    /// Remote execution outcome is ambiguous.
    Unknown,
    /// Reconciliation proved that another same-key attempt is safe.
    AuthorizedForRetry,
    /// A human or authoritative external record resolved ambiguity.
    ManualResolution,
    /// Approval was explicitly rejected.
    Rejected,
    /// Approval or intent expired before dispatch.
    Expired,
    /// Intent was cancelled before an irreversible transition.
    Cancelled,
    /// Compensation was requested for a succeeded effect.
    CompensationPending,
    /// A fenced compensation attempt is in flight.
    Compensating,
    /// Compensation is confirmed complete.
    Compensated,
    /// Compensation is confirmed failed.
    CompensationFailed,
}

impl EffectState {
    /// Returns whether the v1 effect state machine permits this exact transition.
    #[must_use]
    pub const fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (
                Self::Prepared,
                Self::PendingApproval | Self::Authorized | Self::Expired | Self::Cancelled
            ) | (
                Self::PendingApproval,
                Self::Authorized | Self::Rejected | Self::Expired | Self::Cancelled
            ) | (
                Self::Authorized,
                Self::Dispatching | Self::Expired | Self::Cancelled
            ) | (
                Self::Dispatching,
                Self::Succeeded | Self::Failed | Self::Unknown
            ) | (
                Self::Unknown,
                Self::Unknown
                    | Self::Succeeded
                    | Self::Failed
                    | Self::AuthorizedForRetry
                    | Self::ManualResolution
            ) | (
                Self::AuthorizedForRetry,
                Self::Dispatching | Self::Expired | Self::Cancelled
            ) | (Self::Succeeded, Self::CompensationPending)
                | (Self::CompensationPending, Self::Compensating)
                | (
                    Self::Compensating,
                    Self::Compensated | Self::CompensationFailed | Self::Unknown
                )
        )
    }
}

/// Closed effect risk classification.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Reversible low-impact mutation.
    Low,
    /// Bounded mutation with material consequences.
    Medium,
    /// High-impact or difficult-to-reverse mutation.
    High,
    /// Critical irreversible or security-sensitive mutation.
    Critical,
}

/// Closed safe retry strategies declared at intent creation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetryPolicy {
    /// Never redispatch automatically.
    Never,
    /// Connector guarantees same-key idempotency for a bounded number of attempts.
    SameKeyIdempotent {
        /// Maximum total dispatch attempts including the first.
        #[schemars(range(min = 1))]
        max_attempts: u16,
    },
    /// Reconciliation must prove non-execution before a retry authorization.
    ReconcileBeforeRetry,
}

/// Optional compensation operation bound into an original effect intent.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationSpec {
    /// Connector operation used for compensation.
    #[schemars(length(min = 1, max = MAX_EFFECT_SELECTOR_BYTES))]
    pub operation: String,
    /// Digest of normalized compensation arguments.
    pub arguments_digest: ContentDigest,
    /// Protected compensation arguments.
    pub encrypted_arguments: BlobRef,
}

impl fmt::Debug for CompensationSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompensationSpec")
            .field("operation_bytes", &self.operation.len())
            .field("arguments_digest", &self.arguments_digest)
            .field("encrypted_arguments", &self.encrypted_arguments)
            .finish()
    }
}

/// Durable effect intent created before any external dispatch.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntent {
    /// Must be `cigar.effect-intent.v1`.
    pub schema_version: SchemaVersion,
    /// Unique logical effect identity.
    pub effect_id: RecordId,
    /// Connector identifier.
    #[schemars(length(min = 1, max = MAX_EFFECT_SELECTOR_BYTES))]
    pub connector: String,
    /// Connector operation.
    #[schemars(length(min = 1, max = MAX_EFFECT_SELECTOR_BYTES))]
    pub operation: String,
    /// Digest of normalized arguments.
    pub arguments_digest: ContentDigest,
    /// Encrypted normalized arguments reference.
    pub encrypted_arguments: BlobRef,
    /// Bounded external target selector.
    #[schemars(length(min = 1, max = MAX_EFFECT_SELECTOR_BYTES))]
    pub target: String,
    /// Sorted unique precondition digests.
    #[schemars(length(max = MAX_EFFECT_PRECONDITIONS))]
    pub preconditions: Vec<ContentDigest>,
    /// Expected result-schema digest.
    pub result_schema_digest: ContentDigest,
    /// Risk classification.
    pub risk: RiskLevel,
    /// Source decision record.
    pub source_decision_id: VersionId,
    /// Source context bundle.
    pub bundle_id: VersionId,
    /// Capability required at authorization and dispatch time.
    pub required_capability: Capability,
    /// Normalized connector idempotency scope.
    #[schemars(length(min = 1, max = MAX_EFFECT_SELECTOR_BYTES))]
    pub idempotency_scope: String,
    /// Secret-safe idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Safe retry strategy.
    pub retry_policy: RetryPolicy,
    /// Intent creation time.
    pub created_at: UtcTimestamp,
    /// Exclusive dispatch expiry.
    pub expires_at: UtcTimestamp,
    /// Optional compensation specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compensation: Option<CompensationSpec>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for EffectIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectIntent")
            .field("schema_version", &self.schema_version)
            .field("effect_id", &self.effect_id)
            .field("connector_bytes", &self.connector.len())
            .field("operation_bytes", &self.operation.len())
            .field("arguments_digest", &self.arguments_digest)
            .field("target_bytes", &self.target.len())
            .field("precondition_count", &self.preconditions.len())
            .field("risk", &self.risk)
            .field("required_capability", &self.required_capability)
            .field("idempotency_scope_bytes", &self.idempotency_scope.len())
            .field("idempotency_key", &self.idempotency_key)
            .field("retry_policy", &self.retry_policy)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("has_compensation", &self.compensation.is_some())
            .finish_non_exhaustive()
    }
}

impl Validate for EffectIntent {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.effect-intent", &mut errors);
        for (path, value) in [
            ("/connector", &self.connector),
            ("/operation", &self.operation),
            ("/target", &self.target),
            ("/idempotency_scope", &self.idempotency_scope),
        ] {
            validate_selector(value, path, &mut errors);
        }
        if self.preconditions.len() > MAX_EFFECT_PRECONDITIONS
            || !strictly_sorted_unique(&self.preconditions)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/preconditions",
                "effect preconditions must be bounded, sorted, and unique",
            ));
        }
        if self.expires_at <= self.created_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "effect expiry must be later than creation",
            ));
        }
        if let RetryPolicy::SameKeyIdempotent { max_attempts } = self.retry_policy
            && max_attempts == 0
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/retry_policy/max_attempts",
                "same-key retry attempt maximum must be non-zero",
            ));
        }
        if let Some(compensation) = &self.compensation {
            validate_selector(
                &compensation.operation,
                "/compensation/operation",
                &mut errors,
            );
        }
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Closed approval provenance.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Explicit human approval.
    Human,
    /// Policy-authorized automated approval for eligible risk.
    Policy,
}

/// Approval binding the exact intent semantics and limits.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectApproval {
    /// Must be `cigar.effect-approval.v1`.
    pub schema_version: SchemaVersion,
    /// Unique approval identity.
    pub approval_id: RecordId,
    /// Bound effect identity.
    pub effect_id: RecordId,
    /// Bound intent digest.
    pub intent_digest: ContentDigest,
    /// Bound target digest without disclosing the target.
    pub target_digest: ContentDigest,
    /// Bound risk.
    pub risk: RiskLevel,
    /// Bound source bundle.
    pub bundle_id: VersionId,
    /// Digest of approval conditions and limits.
    pub conditions_digest: ContentDigest,
    /// Approver identity.
    pub approver_id: RecordId,
    /// Approval provenance.
    pub kind: ApprovalKind,
    /// Approval time.
    pub approved_at: UtcTimestamp,
    /// Exclusive expiry.
    pub expires_at: UtcTimestamp,
}

impl fmt::Debug for EffectApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectApproval")
            .field("schema_version", &self.schema_version)
            .field("approval_id", &self.approval_id)
            .field("effect_id", &self.effect_id)
            .field("intent_digest", &self.intent_digest)
            .field("target_digest", &self.target_digest)
            .field("risk", &self.risk)
            .field("bundle_id", &self.bundle_id)
            .field("kind", &self.kind)
            .field("approved_at", &self.approved_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Validate for EffectApproval {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.effect-approval", &mut errors);
        if self.expires_at <= self.approved_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/expires_at",
                "approval expiry must be later than approval time",
            ));
        }
        if matches!(self.risk, RiskLevel::High | RiskLevel::Critical)
            && self.kind != ApprovalKind::Human
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/kind",
                "high and critical risk require explicit human approval",
            ));
        }
        errors.into_result()
    }
}

/// Durable fenced connector dispatch attempt.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAttempt {
    /// Must be `cigar.effect-attempt.v1`.
    pub schema_version: SchemaVersion,
    /// Unique attempt identity.
    pub attempt_id: RecordId,
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// One-based attempt number.
    #[schemars(range(min = 1))]
    pub attempt_number: u16,
    /// Monotonic fencing token.
    #[schemars(range(min = 1))]
    pub fencing_token: u64,
    /// Exact request digest committed before dispatch.
    pub request_digest: ContentDigest,
    /// Claimed time.
    pub started_at: UtcTimestamp,
    /// Dispatch deadline.
    pub deadline: UtcTimestamp,
}

impl Validate for EffectAttempt {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.effect-attempt", &mut errors);
        if self.attempt_number == 0 || self.fencing_token == 0 || self.deadline <= self.started_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/attempt_number",
                "attempt number, fencing token, and deadline must be positive",
            ));
        }
        errors.into_result()
    }
}

/// Closed receipt outcome after a dispatch observation.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    /// Remote mutation and response are confirmed successful.
    Succeeded,
    /// Remote rejection or failure is definitive.
    Failed,
    /// Request may have executed but cannot yet be proven.
    Unknown,
}

/// Protected connector receipt for one fenced attempt.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    /// Must be `cigar.effect-receipt.v1`.
    pub schema_version: SchemaVersion,
    /// Unique receipt identity.
    pub receipt_id: RecordId,
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// Source attempt identity.
    pub attempt_id: RecordId,
    /// Definitive or ambiguous outcome.
    pub outcome: ReceiptOutcome,
    /// Remote operation identifier when available.
    #[schemars(inner(length(min = 1, max = MAX_EFFECT_SELECTOR_BYTES)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_operation_id: Option<String>,
    /// Protected raw response reference when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_response: Option<BlobRef>,
    /// Normalized response digest when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<ContentDigest>,
    /// Observation time.
    pub observed_at: UtcTimestamp,
    /// Verification evidence digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_digest: Option<ContentDigest>,
}

impl fmt::Debug for EffectReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectReceipt")
            .field("schema_version", &self.schema_version)
            .field("receipt_id", &self.receipt_id)
            .field("effect_id", &self.effect_id)
            .field("attempt_id", &self.attempt_id)
            .field("outcome", &self.outcome)
            .field(
                "has_remote_operation_id",
                &self.remote_operation_id.is_some(),
            )
            .field("has_protected_response", &self.protected_response.is_some())
            .field("response_digest", &self.response_digest)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

impl Validate for EffectReceipt {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.effect-receipt", &mut errors);
        if let Some(remote_id) = &self.remote_operation_id {
            validate_selector(remote_id, "/remote_operation_id", &mut errors);
        }
        if self.outcome == ReceiptOutcome::Succeeded
            && (self.response_digest.is_none() || self.verification_digest.is_none())
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/verification_digest",
                "successful receipt requires response and verification digests",
            ));
        }
        errors.into_result()
    }
}

/// One append-only hash-chained state transition event.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectJournalEvent {
    /// Must be `cigar.effect-journal-event.v1`.
    pub schema_version: SchemaVersion,
    /// Unique journal event identity.
    pub event_id: RecordId,
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// One-based event sequence.
    #[schemars(range(min = 1))]
    pub sequence: u64,
    /// Expected prior effect version.
    pub expected_effect_version: u64,
    /// Prior projection state.
    pub from_state: EffectState,
    /// Resulting projection state.
    pub to_state: EffectState,
    /// Actor authorizing the transition.
    pub actor_id: RecordId,
    /// Typed transition payload digest.
    pub payload_digest: ContentDigest,
    /// Prior event digest; absent only for sequence one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_event_digest: Option<ContentDigest>,
    /// This complete event digest.
    pub event_digest: ContentDigest,
    /// Commit time.
    pub recorded_at: UtcTimestamp,
}

impl Validate for EffectJournalEvent {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.effect-journal-event",
            &mut errors,
        );
        if self.sequence == 0
            || (self.sequence == 1) != self.previous_event_digest.is_none()
            || !self.from_state.can_transition_to(self.to_state)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/to_state",
                "journal sequence, hash-chain, or state transition is invalid",
            ));
        }
        errors.into_result()
    }
}

/// Closed reconciliation conclusion.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationOutcome {
    /// Remote mutation is confirmed successful.
    ConfirmedSuccess,
    /// Remote mutation is confirmed failed.
    ConfirmedFailure,
    /// Connector proved that no remote mutation occurred.
    ProvenNotExecuted,
    /// Available evidence cannot resolve the outcome.
    Inconclusive,
    /// Authorized human resolution was recorded.
    Manual,
}

/// Evidence-bearing reconciliation report for an unknown effect.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationReport {
    /// Must be `cigar.reconciliation-report.v1`.
    pub schema_version: SchemaVersion,
    /// Unique report identity.
    pub report_id: RecordId,
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// Source attempt when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<RecordId>,
    /// Reconciliation conclusion.
    pub outcome: ReconciliationOutcome,
    /// Sorted unique evidence digests.
    #[schemars(length(min = 1, max = MAX_RECONCILIATION_EVIDENCE))]
    pub evidence_digests: Vec<ContentDigest>,
    /// Observation time.
    pub reconciled_at: UtcTimestamp,
    /// End of a connector certainty window when outcome remains inconclusive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certainty_window_end: Option<UtcTimestamp>,
}

impl Validate for ReconciliationReport {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.reconciliation-report",
            &mut errors,
        );
        if self.evidence_digests.is_empty()
            || self.evidence_digests.len() > MAX_RECONCILIATION_EVIDENCE
            || !strictly_sorted_unique(&self.evidence_digests)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/evidence_digests",
                "reconciliation evidence must be non-empty, sorted, and unique",
            ));
        }
        if self.outcome == ReconciliationOutcome::Inconclusive
            && self.certainty_window_end.is_none()
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/certainty_window_end",
                "inconclusive reconciliation requires a certainty-window end",
            ));
        }
        errors.into_result()
    }
}

/// Link from a succeeded original effect to a separately authorized compensation effect.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationLink {
    /// Must be `cigar.compensation-link.v1`.
    pub schema_version: SchemaVersion,
    /// Original succeeded effect identity.
    pub original_effect_id: RecordId,
    /// Separately journaled compensation effect identity.
    pub compensation_effect_id: RecordId,
    /// Digest binding the original compensation specification.
    pub compensation_spec_digest: ContentDigest,
    /// Creation time.
    pub created_at: UtcTimestamp,
}

impl Validate for CompensationLink {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.compensation-link", &mut errors);
        if self.original_effect_id == self.compensation_effect_id {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/compensation_effect_id",
                "compensation must be a distinct logical effect",
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

fn validate_selector(value: &str, path: &str, errors: &mut ValidationErrors) {
    if value.is_empty() || value.len() > MAX_EFFECT_SELECTOR_BYTES {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            path,
            "effect selector must be non-empty and bounded",
        ));
    }
}

fn validate_extensions(extensions: &ExtensionMap, errors: &mut ValidationErrors) {
    if let Err(found) = extensions.validate_known(&BTreeSet::new()) {
        errors.merge(found);
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

#[cfg(test)]
mod tests {
    use super::{ApprovalKind, EffectApproval, EffectJournalEvent, EffectState, RiskLevel};
    use crate::{ContentDigest, RecordId, UtcTimestamp, Validate};

    fn record(last: char) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f789{last}"
        ))?)
    }

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    #[test]
    fn effect_transition_table_rejects_unsafe_shortcuts() {
        assert!(EffectState::Authorized.can_transition_to(EffectState::Dispatching));
        assert!(EffectState::Dispatching.can_transition_to(EffectState::Unknown));
        assert!(!EffectState::Prepared.can_transition_to(EffectState::Succeeded));
        assert!(!EffectState::Unknown.can_transition_to(EffectState::Dispatching));
    }

    #[test]
    fn journal_event_validates_transition_and_hash_chain() -> Result<(), Box<dyn std::error::Error>>
    {
        let event = EffectJournalEvent {
            schema_version: "cigar.effect-journal-event.v1".parse()?,
            event_id: record('0')?,
            effect_id: record('1')?,
            sequence: 2,
            expected_effect_version: 1,
            from_state: EffectState::Prepared,
            to_state: EffectState::Succeeded,
            actor_id: record('2')?,
            payload_digest: digest('a')?,
            previous_event_digest: None,
            event_digest: digest('b')?,
            recorded_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
        };
        assert!(event.validate().is_err());
        Ok(())
    }

    #[test]
    fn critical_risk_requires_human_approval() -> Result<(), Box<dyn std::error::Error>> {
        let approved_at = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?;
        let approval = EffectApproval {
            schema_version: "cigar.effect-approval.v1".parse()?,
            approval_id: record('3')?,
            effect_id: record('4')?,
            intent_digest: digest('c')?,
            target_digest: digest('d')?,
            risk: RiskLevel::Critical,
            bundle_id: crate::VersionId::new(format!("1220{}", "e".repeat(64)))?,
            conditions_digest: digest('f')?,
            approver_id: record('5')?,
            kind: ApprovalKind::Policy,
            approved_at,
            expires_at: UtcTimestamp::parse_rfc3339("2026-07-11T00:00:00Z")?,
        };
        assert!(approval.validate().is_err());
        Ok(())
    }
}
