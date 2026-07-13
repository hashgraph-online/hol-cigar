//! Observable decision evidence, replay requests/executions, diffs, and verification receipts.

use crate::limits::{MAX_REPLAY_REFERENCES, MAX_VERIFICATION_CHECKS, MAX_VERIFICATION_NAME_BYTES};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    ContentDigest, ExtensionMap, RecordId, SchemaVersion, UtcTimestamp, Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Closed observed decision outcome.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// Declared job completed and verification passed.
    Succeeded,
    /// Job failed or verification contradicted its claims.
    Failed,
    /// Some declared work remains incomplete.
    Partial,
    /// Execution was cancelled before completion.
    Cancelled,
}

/// Exact integer consumer usage; monetary values use integer micros.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageRecord {
    /// Physical input tokens.
    pub input_tokens: u64,
    /// Physical output tokens.
    pub output_tokens: u64,
    /// Provider-reported cached input tokens.
    pub cached_input_tokens: u64,
    /// Cost in millionths of the configured currency unit.
    pub cost_micros: u64,
}

/// Observable, evidence-backed decision record; hidden reasoning is intentionally absent.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    /// Must be `cigar.decision-record.v1`.
    pub schema_version: SchemaVersion,
    /// Content-derived decision identity.
    pub decision_id: VersionId,
    /// Digest of the observable task statement.
    pub task_digest: ContentDigest,
    /// Planner output identity.
    pub plan_id: RecordId,
    /// Digest of the full plan.
    pub plan_digest: ContentDigest,
    /// Context bundle identity.
    pub bundle_id: VersionId,
    /// Exact materialization digest.
    pub materialization_digest: ContentDigest,
    /// Runtime implementation fingerprint.
    pub runtime_fingerprint: ContentDigest,
    /// Consumer implementation fingerprint.
    pub consumer_fingerprint: ContentDigest,
    /// Sorted output artifact records.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub output_artifacts: Vec<VersionId>,
    /// Sorted asserted-claim record digests.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub asserted_claims: Vec<ContentDigest>,
    /// Sorted evidence record digests.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub evidence: Vec<ContentDigest>,
    /// Sorted uncertainty record digests.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub uncertainty: Vec<ContentDigest>,
    /// Sorted verification receipt identities.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub verification_receipts: Vec<VersionId>,
    /// Sorted logical effect identities.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub effects: Vec<RecordId>,
    /// Exact usage accounting.
    pub usage: UsageRecord,
    /// Execution start.
    pub started_at: UtcTimestamp,
    /// Execution completion.
    pub completed_at: UtcTimestamp,
    /// Observed outcome.
    pub outcome: DecisionOutcome,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for DecisionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionRecord")
            .field("schema_version", &self.schema_version)
            .field("decision_id", &self.decision_id)
            .field("task_digest", &self.task_digest)
            .field("plan_id", &self.plan_id)
            .field("plan_digest", &self.plan_digest)
            .field("bundle_id", &self.bundle_id)
            .field("output_artifact_count", &self.output_artifacts.len())
            .field("claim_count", &self.asserted_claims.len())
            .field("evidence_count", &self.evidence.len())
            .field("uncertainty_count", &self.uncertainty.len())
            .field("verification_count", &self.verification_receipts.len())
            .field("effect_count", &self.effects.len())
            .field("usage", &self.usage)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl Validate for DecisionRecord {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.decision-record", &mut errors);
        for (path, valid) in [
            ("/output_artifacts", valid_set(&self.output_artifacts)),
            ("/asserted_claims", valid_set(&self.asserted_claims)),
            ("/evidence", valid_set(&self.evidence)),
            ("/uncertainty", valid_set(&self.uncertainty)),
            (
                "/verification_receipts",
                valid_set(&self.verification_receipts),
            ),
            ("/effects", valid_set(&self.effects)),
        ] {
            if !valid {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    path,
                    "decision reference collection must be bounded, sorted, and unique",
                ));
            }
        }
        if self.completed_at < self.started_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/completed_at",
                "decision completion cannot precede its start",
            ));
        }
        validate_extensions(&self.extensions, &mut errors);
        errors.into_result()
    }
}

/// Closed replay execution mode.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    /// Verify retained source, policy, index, manifest, and bundle evidence.
    EvidenceReproduction,
    /// Reconstruct exact declared invocation without invoking dependencies.
    InvocationReproduction,
    /// Substitute recorded observations under denied egress.
    Observational,
    /// Invoke configured dependencies as a new explicitly authorized execution.
    LiveComparison,
}

/// Request for one replay operation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    /// Must be `cigar.replay-request.v1`.
    pub schema_version: SchemaVersion,
    /// Unique request identity.
    pub request_id: RecordId,
    /// Source decision identity.
    pub decision_id: VersionId,
    /// Replay mode.
    pub mode: ReplayMode,
    /// Authenticated requester.
    pub requested_by: RecordId,
    /// Explicit live rerun authorization digest, required only for live mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_authorization_digest: Option<ContentDigest>,
    /// Whether all effects remain simulated.
    pub simulate_effects: bool,
    /// New separately authorized effect intents permitted only in live mode.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub authorized_effect_intents: Vec<RecordId>,
}

impl Validate for ReplayRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.replay-request", &mut errors);
        let live = self.mode == ReplayMode::LiveComparison;
        if live != self.live_authorization_digest.is_some() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/live_authorization_digest",
                "live mode requires authorization and non-live modes forbid it",
            ));
        }
        if !valid_set(&self.authorized_effect_intents)
            || (!live && !self.authorized_effect_intents.is_empty())
            || (self.simulate_effects && !self.authorized_effect_intents.is_empty())
            || (!self.simulate_effects && self.authorized_effect_intents.is_empty())
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/authorized_effect_intents",
                "effect intents must be new, sorted, and restricted to authorized live replay",
            ));
        }
        if !live && !self.simulate_effects {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/simulate_effects",
                "non-live replay must simulate every effect",
            ));
        }
        errors.into_result()
    }
}

/// Dependency categories reported by replay completeness.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Source snapshot or atom.
    Source,
    /// Protected blob.
    Blob,
    /// Policy snapshot.
    Policy,
    /// Index generation.
    Index,
    /// Selection manifest.
    Manifest,
    /// Context bundle.
    Bundle,
    /// Tokenizer implementation.
    Tokenizer,
    /// Provider adapter.
    Adapter,
    /// Consumer runtime.
    Consumer,
    /// Tool schema.
    ToolSchema,
    /// Declared environment component.
    Environment,
}

/// Explicit available and missing replay dependencies.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCompleteness {
    /// Sorted available dependency categories.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub available: Vec<DependencyKind>,
    /// Sorted missing dependency categories.
    #[schemars(length(max = MAX_REPLAY_REFERENCES))]
    pub missing: Vec<DependencyKind>,
}

impl ReplayCompleteness {
    fn validate_into(&self, errors: &mut ValidationErrors) {
        if !valid_set(&self.available)
            || !valid_set(&self.missing)
            || self
                .available
                .iter()
                .any(|dependency| self.missing.binary_search(dependency).is_ok())
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/completeness",
                "available and missing dependencies must be sorted, unique, and disjoint",
            ));
        }
    }
}

/// Closed replay execution status.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    /// Execution is currently running.
    Running,
    /// Requested replay completed.
    Complete,
    /// Replay failed validation or execution.
    Failed,
    /// Replay stopped due to missing dependencies.
    Incomplete,
}

/// One new replay execution; never mutates the source decision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayExecution {
    /// Must be `cigar.replay-execution.v1`.
    pub schema_version: SchemaVersion,
    /// Unique execution identity.
    pub execution_id: RecordId,
    /// Source request identity.
    pub request_id: RecordId,
    /// Executed mode.
    pub mode: ReplayMode,
    /// Execution status.
    pub status: ReplayStatus,
    /// Dependency completeness.
    pub completeness: ReplayCompleteness,
    /// Reconstructed consumer input digest when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstructed_input_digest: Option<ContentDigest>,
    /// Recorded or live observation digest when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_digest: Option<ContentDigest>,
    /// Whether network egress was enabled.
    pub egress_permitted: bool,
    /// Whether newly authorized effect dispatch was enabled.
    pub effect_dispatch_permitted: bool,
    /// Start time.
    pub started_at: UtcTimestamp,
    /// Completion time when terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<UtcTimestamp>,
}

impl Validate for ReplayExecution {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.replay-execution", &mut errors);
        self.completeness.validate_into(&mut errors);
        if self.mode != ReplayMode::LiveComparison
            && (self.egress_permitted || self.effect_dispatch_permitted)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/egress_permitted",
                "non-live replay must deny egress and effect dispatch",
            ));
        }
        let terminal = self.status != ReplayStatus::Running;
        if terminal != self.completed_at.is_some()
            || self
                .completed_at
                .is_some_and(|value| value < self.started_at)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/completed_at",
                "only terminal replay has a non-regressing completion time",
            ));
        }
        if (self.status == ReplayStatus::Complete && !self.completeness.missing.is_empty())
            || (self.status == ReplayStatus::Incomplete && self.completeness.missing.is_empty())
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/status",
                "complete replay cannot miss dependencies and incomplete replay must name one",
            ));
        }
        if self.status == ReplayStatus::Complete {
            let invocation_reconstructed = self.reconstructed_input_digest.is_some();
            let observation_reconstructed = self.observation_digest.is_some();
            let digests_valid = match self.mode {
                ReplayMode::EvidenceReproduction => !observation_reconstructed,
                ReplayMode::InvocationReproduction => {
                    invocation_reconstructed && !observation_reconstructed
                }
                ReplayMode::Observational | ReplayMode::LiveComparison => {
                    invocation_reconstructed && observation_reconstructed
                }
            };
            if !digests_valid {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    "/reconstructed_input_digest",
                    "complete replay must expose exactly the digests required by its mode",
                ));
            }
        }
        errors.into_result()
    }
}

/// Closed comparison result for one replay dimension.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    /// Dimension is semantically equal.
    Equal,
    /// Dimension differs.
    Different,
    /// Dimension could not be compared due to incomplete evidence.
    Unavailable,
}

/// Separated semantic and observational replay differences.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayDiff {
    /// Must be `cigar.replay-diff.v1`.
    pub schema_version: SchemaVersion,
    /// Original decision identity.
    pub decision_id: VersionId,
    /// New replay execution identity.
    pub execution_id: RecordId,
    /// Semantic context comparison.
    pub semantic_context: DiffStatus,
    /// Materialized byte comparison.
    pub materialization: DiffStatus,
    /// Runtime component fingerprint comparison.
    pub components: DiffStatus,
    /// Output claim comparison.
    pub output_claims: DiffStatus,
    /// Verification result comparison.
    pub verification: DiffStatus,
    /// Effect-plan comparison.
    pub effect_plan: DiffStatus,
    /// Provider/tool observation comparison.
    pub observations: DiffStatus,
    /// Whether compiler determinism held independently of provider variance.
    pub compiler_deterministic: bool,
}

impl Validate for ReplayDiff {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.replay-diff", &mut errors);
        if self.compiler_deterministic
            && matches!(
                (self.semantic_context, self.materialization),
                (DiffStatus::Different, _) | (_, DiffStatus::Different)
            )
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/compiler_deterministic",
                "compiler cannot be deterministic when semantic context or materialization differs",
            ));
        }
        errors.into_result()
    }
}

/// Closed verification check outcome.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Check passed.
    Passed,
    /// Check failed.
    Failed,
    /// Check could not reach a conclusion.
    Indeterminate,
}

/// One named verification check with evidence digest.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCheck {
    /// Bounded check identifier.
    #[schemars(length(min = 1, max = MAX_VERIFICATION_NAME_BYTES))]
    pub name: String,
    /// Check-specific evidence digest.
    pub evidence_digest: ContentDigest,
    /// Check result.
    pub outcome: VerificationOutcome,
}

impl fmt::Debug for VerificationCheck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationCheck")
            .field("name_bytes", &self.name.len())
            .field("evidence_digest", &self.evidence_digest)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Evidence-bearing verification receipt over one semantic subject.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    /// Must be `cigar.verification-receipt.v1`.
    pub schema_version: SchemaVersion,
    /// Content-derived receipt identity.
    pub receipt_id: VersionId,
    /// Verifier implementation fingerprint.
    pub verifier_fingerprint: ContentDigest,
    /// Verified semantic subject digest.
    pub subject_digest: ContentDigest,
    /// Ordered named checks.
    #[schemars(length(min = 1, max = MAX_VERIFICATION_CHECKS))]
    pub checks: Vec<VerificationCheck>,
    /// Aggregate outcome consistent with every check.
    pub outcome: VerificationOutcome,
    /// Verification time.
    pub verified_at: UtcTimestamp,
}

impl Validate for VerificationReceipt {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.verification-receipt",
            &mut errors,
        );
        if self.checks.is_empty() || self.checks.len() > MAX_VERIFICATION_CHECKS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/checks",
                "verification checks must be non-empty and bounded",
            ));
        }
        let names: Vec<_> = self.checks.iter().map(|check| &check.name).collect();
        if !strictly_sorted_unique(&names)
            || self.checks.iter().any(|check| {
                check.name.is_empty() || check.name.len() > MAX_VERIFICATION_NAME_BYTES
            })
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/checks",
                "verification check names must be bounded, sorted, and unique",
            ));
        }
        let expected = if self
            .checks
            .iter()
            .any(|check| check.outcome == VerificationOutcome::Failed)
        {
            VerificationOutcome::Failed
        } else if self
            .checks
            .iter()
            .any(|check| check.outcome == VerificationOutcome::Indeterminate)
        {
            VerificationOutcome::Indeterminate
        } else {
            VerificationOutcome::Passed
        };
        if expected != self.outcome {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/outcome",
                "verification aggregate outcome disagrees with its checks",
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

fn valid_set<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REPLAY_REFERENCES && strictly_sorted_unique(values)
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
    use super::{
        DependencyKind, ReplayCompleteness, ReplayExecution, ReplayMode, ReplayRequest,
        ReplayStatus,
    };
    use crate::{ContentDigest, RecordId, UtcTimestamp, Validate, VersionId};

    fn record(last: char) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f789{last}"
        ))?)
    }

    fn version() -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!("1220{}", "a".repeat(64)))?)
    }

    fn digest() -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!("1220{}", "b".repeat(64)))?)
    }

    #[test]
    fn non_live_replay_forbids_egress_and_effect_dispatch() -> Result<(), Box<dyn std::error::Error>>
    {
        let start = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?;
        let execution = ReplayExecution {
            schema_version: "cigar.replay-execution.v1".parse()?,
            execution_id: record('0')?,
            request_id: record('1')?,
            mode: ReplayMode::Observational,
            status: ReplayStatus::Running,
            completeness: ReplayCompleteness {
                available: vec![DependencyKind::Source],
                missing: Vec::new(),
            },
            reconstructed_input_digest: None,
            observation_digest: None,
            egress_permitted: true,
            effect_dispatch_permitted: false,
            started_at: start,
            completed_at: None,
        };
        assert!(execution.validate().is_err());
        Ok(())
    }

    #[test]
    fn live_replay_requires_new_explicit_authorization() -> Result<(), Box<dyn std::error::Error>> {
        let request = ReplayRequest {
            schema_version: "cigar.replay-request.v1".parse()?,
            request_id: record('2')?,
            decision_id: version()?,
            mode: ReplayMode::LiveComparison,
            requested_by: record('3')?,
            live_authorization_digest: None,
            simulate_effects: true,
            authorized_effect_intents: Vec::new(),
        };
        assert!(request.validate().is_err());
        Ok(())
    }

    #[test]
    fn completeness_rejects_available_missing_overlap() -> Result<(), Box<dyn std::error::Error>> {
        let start = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?;
        let execution = ReplayExecution {
            schema_version: "cigar.replay-execution.v1".parse()?,
            execution_id: record('4')?,
            request_id: record('5')?,
            mode: ReplayMode::EvidenceReproduction,
            status: ReplayStatus::Running,
            completeness: ReplayCompleteness {
                available: vec![DependencyKind::Source],
                missing: vec![DependencyKind::Source],
            },
            reconstructed_input_digest: None,
            observation_digest: None,
            egress_permitted: false,
            effect_dispatch_permitted: false,
            started_at: start,
            completed_at: None,
        };
        assert!(execution.validate().is_err());
        Ok(())
    }

    #[test]
    fn simulated_live_replay_cannot_also_authorize_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = ReplayRequest {
            schema_version: "cigar.replay-request.v1".parse()?,
            request_id: record('6')?,
            decision_id: version()?,
            mode: ReplayMode::LiveComparison,
            requested_by: record('7')?,
            live_authorization_digest: Some(digest()?),
            simulate_effects: true,
            authorized_effect_intents: vec![record('8')?],
        };
        assert!(request.validate().is_err());
        Ok(())
    }

    #[test]
    fn terminal_status_and_mode_require_exact_completeness_and_digests()
    -> Result<(), Box<dyn std::error::Error>> {
        let start = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?;
        let mut execution = ReplayExecution {
            schema_version: "cigar.replay-execution.v1".parse()?,
            execution_id: record('9')?,
            request_id: record('a')?,
            mode: ReplayMode::InvocationReproduction,
            status: ReplayStatus::Complete,
            completeness: ReplayCompleteness {
                available: vec![DependencyKind::Bundle],
                missing: Vec::new(),
            },
            reconstructed_input_digest: None,
            observation_digest: None,
            egress_permitted: false,
            effect_dispatch_permitted: false,
            started_at: start,
            completed_at: Some(start),
        };
        assert!(execution.validate().is_err());
        execution.reconstructed_input_digest = Some(digest()?);
        assert!(execution.validate().is_ok());
        execution.status = ReplayStatus::Incomplete;
        assert!(execution.validate().is_err());
        Ok(())
    }
}
