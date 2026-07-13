//! Normalized compilation request contracts and exact token budgets.

use crate::limits::{
    MAX_CONTEXT_REQUIREMENTS, MAX_JOB_GOAL_BYTES, MAX_PURPOSE_BYTES, MAX_QUERY_BYTES,
    MAX_SCOPE_PROJECTS, MAX_TARGET_IDENTIFIER_BYTES, STANDARD_LANE_COUNT,
};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    AtomKind, ContentDigest, ContextSpaceId, DurationNanos, ExtensionMap, FixedPoint, RecordId,
    SchemaVersion, Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Closed operation classes used by capability and policy gates.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    /// Read-only context use.
    Read,
    /// Local source or artifact modification.
    CodeChange,
    /// Analysis that must not dispatch mutations.
    Analysis,
    /// Operation that may request a mediated external effect.
    ExternalMutation,
}

/// Closed catalog/index consistency modes.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyMode {
    /// Require the requested immutable snapshot exactly.
    Snapshot,
    /// Require indexes caught up to the current catalog watermark.
    Strong,
    /// Permit bounded index staleness described by the contract.
    BoundedStaleness,
}

/// Standard deterministic context lanes.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    /// Non-bypassable rules and instructions.
    Rules,
    /// Current task statement and exact constraints.
    Task,
    /// Source, documentation, and verification evidence.
    Evidence,
    /// Prior decisions and relevant history.
    History,
    /// Tool contracts and capability descriptions.
    Tools,
}

/// Exact integer token budget and lane allocation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Total physical input-token maximum.
    pub total_input_tokens: u32,
    /// Output tokens reserved at the target consumer.
    pub output_reserve_tokens: u32,
    /// Exact input allocation by standard lane.
    #[schemars(extend("minProperties" = 1, "maxProperties" = STANDARD_LANE_COUNT))]
    pub lane_input_tokens: BTreeMap<LaneKind, u32>,
}

impl Budget {
    fn validate_into(&self, errors: &mut ValidationErrors) {
        if self.total_input_tokens == 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/budget/total_input_tokens",
                "total input budget must be non-zero",
            ));
        }
        let sum = self
            .lane_input_tokens
            .values()
            .try_fold(0_u32, |total, value| total.checked_add(*value));
        if sum != Some(self.total_input_tokens) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/budget/lane_input_tokens",
                "lane allocations must sum exactly to total input tokens",
            ));
        }
        if self.lane_input_tokens.values().any(|value| *value == 0) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/budget/lane_input_tokens",
                "declared lane allocations must be non-zero",
            ));
        }
    }
}

/// Exact or query selector for required semantic context.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RequirementSelector {
    /// Require one exact immutable semantic version.
    Exact(VersionId),
    /// Execute a bounded authorized retrieval query.
    Query(#[schemars(length(min = 1, max = MAX_QUERY_BYTES))] String),
}

impl fmt::Debug for RequirementSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(version) => formatter.debug_tuple("Exact").field(version).finish(),
            Self::Query(query) => formatter
                .debug_struct("Query")
                .field("bytes", &query.len())
                .finish(),
        }
    }
}

/// One semantic context requirement in a compilation contract.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRequirement {
    /// Required semantic atom kind.
    pub semantic_type: AtomKind,
    /// Exact or retrieval selector.
    pub selector: RequirementSelector,
    /// Minimum accepted authority tier.
    pub minimum_authority: u16,
    /// Maximum observation age when temporal selection applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_age: Option<DurationNanos>,
    /// Minimum fixed-point source coverage.
    pub minimum_coverage: FixedPoint,
    /// Whether missing authorized data blocks compilation.
    pub blocking: bool,
}

impl ContextRequirement {
    fn validate_into(&self, index: usize, errors: &mut ValidationErrors) {
        if self.minimum_authority == 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                format!("/requirements/{index}/minimum_authority"),
                "minimum authority must be non-zero",
            ));
        }
        if let RequirementSelector::Query(query) = &self.selector
            && (query.is_empty() || query.len() > MAX_QUERY_BYTES)
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                format!("/requirements/{index}/selector"),
                "query selector must be non-empty and bounded",
            ));
        }
    }
}

/// Consumer, tokenizer, and materializer compatibility target.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfile {
    /// Provider family identifier.
    #[schemars(length(min = 1, max = MAX_TARGET_IDENTIFIER_BYTES))]
    pub provider: String,
    /// Model or consumer family identifier.
    #[schemars(length(min = 1, max = MAX_TARGET_IDENTIFIER_BYTES))]
    pub model_family: String,
    /// Immutable tokenizer implementation fingerprint.
    pub tokenizer_fingerprint: ContentDigest,
    /// Immutable materializer implementation fingerprint.
    pub materializer_fingerprint: ContentDigest,
    /// Target context-window maximum.
    pub max_context_tokens: u32,
}

impl fmt::Debug for TargetProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetProfile")
            .field("provider_bytes", &self.provider.len())
            .field("model_family_bytes", &self.model_family.len())
            .field("tokenizer_fingerprint", &self.tokenizer_fingerprint)
            .field("materializer_fingerprint", &self.materializer_fingerprint)
            .field("max_context_tokens", &self.max_context_tokens)
            .finish()
    }
}

impl TargetProfile {
    fn validate_into(&self, errors: &mut ValidationErrors) {
        for (path, value) in [
            ("/target/provider", &self.provider),
            ("/target/model_family", &self.model_family),
        ] {
            if value.is_empty() || value.len() > MAX_TARGET_IDENTIFIER_BYTES {
                errors.push(issue(
                    ValidationCode::LimitExceeded,
                    path,
                    "target identifier must be non-empty and bounded",
                ));
            }
        }
        if self.max_context_tokens == 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/target/max_context_tokens",
                "target context window must be non-zero",
            ));
        }
    }
}

/// Canonical normalized input to deterministic context compilation.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextContract {
    /// Must be `cigar.context-contract.v1`.
    pub schema_version: SchemaVersion,
    /// Human job goal; normalized before this record is hashed.
    #[schemars(length(min = 1, max = MAX_JOB_GOAL_BYTES))]
    pub job_goal: String,
    /// Capability-relevant operation class.
    pub operation_class: OperationClass,
    /// Authenticated principal identity.
    pub principal_id: RecordId,
    /// Declared use purpose.
    #[schemars(length(min = 1, max = MAX_PURPOSE_BYTES))]
    pub purpose: String,
    /// Context space when compiling from a branch or overlay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_space_id: Option<ContextSpaceId>,
    /// Sorted unique project scope; may be empty only with a context space.
    #[schemars(length(max = MAX_SCOPE_PROJECTS))]
    pub project_ids: Vec<RecordId>,
    /// Target consumer compatibility profile.
    pub target: TargetProfile,
    /// Exact input and output budget.
    pub budget: Budget,
    /// Required semantic context selectors.
    #[schemars(length(max = MAX_CONTEXT_REQUIREMENTS))]
    pub requirements: Vec<ContextRequirement>,
    /// Catalog/index consistency mode.
    pub consistency: ConsistencyMode,
    /// Maximum permitted staleness for bounded-staleness mode only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_staleness: Option<DurationNanos>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for ContextContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextContract")
            .field("schema_version", &self.schema_version)
            .field("job_goal_bytes", &self.job_goal.len())
            .field("operation_class", &self.operation_class)
            .field("purpose_bytes", &self.purpose.len())
            .field("has_context_space", &self.context_space_id.is_some())
            .field("project_count", &self.project_ids.len())
            .field("target", &self.target)
            .field("budget", &self.budget)
            .field("requirement_count", &self.requirements.len())
            .field("consistency", &self.consistency)
            .field("extensions", &self.extensions)
            .finish_non_exhaustive()
    }
}

impl Validate for ContextContract {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.context-contract") {
            errors.merge(found);
        }
        if self.job_goal.trim().is_empty() || self.job_goal.len() > MAX_JOB_GOAL_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/job_goal",
                "job goal must be non-empty and bounded",
            ));
        }
        if self.purpose.is_empty() || self.purpose.len() > MAX_PURPOSE_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/purpose",
                "purpose must be non-empty and bounded",
            ));
        }
        if self.project_ids.len() > MAX_SCOPE_PROJECTS
            || (self.project_ids.is_empty() && self.context_space_id.is_none())
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/project_ids",
                "project scope must be bounded and cannot be empty without a context space",
            ));
        }
        if !strictly_sorted_unique(&self.project_ids) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/project_ids",
                "project identities must be sorted and unique",
            ));
        }
        self.target.validate_into(&mut errors);
        self.budget.validate_into(&mut errors);
        let requested_tokens = self
            .budget
            .total_input_tokens
            .checked_add(self.budget.output_reserve_tokens);
        if requested_tokens.is_none_or(|tokens| tokens > self.target.max_context_tokens) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/budget",
                "input budget plus output reserve exceeds the target context window",
            ));
        }
        if self.requirements.len() > MAX_CONTEXT_REQUIREMENTS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/requirements",
                "context requirement collection exceeds the maximum",
            ));
        }
        for (index, requirement) in self.requirements.iter().enumerate() {
            requirement.validate_into(index, &mut errors);
        }
        match (self.consistency, self.maximum_staleness) {
            (ConsistencyMode::BoundedStaleness, None) => errors.push(issue(
                ValidationCode::InvalidValue,
                "/maximum_staleness",
                "bounded-staleness mode requires an explicit maximum",
            )),
            (ConsistencyMode::Snapshot | ConsistencyMode::Strong, Some(_)) => errors.push(issue(
                ValidationCode::InvalidValue,
                "/maximum_staleness",
                "maximum staleness is valid only in bounded-staleness mode",
            )),
            (ConsistencyMode::BoundedStaleness, Some(_))
            | (ConsistencyMode::Snapshot | ConsistencyMode::Strong, None) => {}
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
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
    use super::{
        Budget, ConsistencyMode, ContextContract, LaneKind, OperationClass, TargetProfile,
    };
    use crate::{ContentDigest, ExtensionMap, RecordId, Validate};
    use std::collections::BTreeMap;

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn contract() -> Result<ContextContract, Box<dyn std::error::Error>> {
        let mut lanes = BTreeMap::new();
        lanes.insert(LaneKind::Rules, 1_000);
        lanes.insert(LaneKind::Task, 1_000);
        Ok(ContextContract {
            schema_version: "cigar.context-contract.v1".parse()?,
            job_goal: "Implement a verified change".to_owned(),
            operation_class: OperationClass::CodeChange,
            principal_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7820")?,
            purpose: "coding".to_owned(),
            context_space_id: None,
            project_ids: vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7821")?],
            target: TargetProfile {
                provider: "fixture".to_owned(),
                model_family: "fixture-model".to_owned(),
                tokenizer_fingerprint: digest('a')?,
                materializer_fingerprint: digest('b')?,
                max_context_tokens: 3_000,
            },
            budget: Budget {
                total_input_tokens: 2_000,
                output_reserve_tokens: 1_000,
                lane_input_tokens: lanes,
            },
            requirements: Vec::new(),
            consistency: ConsistencyMode::Strong,
            maximum_staleness: None,
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn normalized_contract_validates_and_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let contract = contract()?;
        contract.validate()?;
        let json = serde_json::to_string(&contract)?;
        let decoded: ContextContract = serde_json::from_str(&json)?;
        decoded.validate()?;
        assert_eq!(decoded, contract);
        Ok(())
    }

    #[test]
    fn budget_arithmetic_and_consistency_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut contract = contract()?;
        contract.budget.total_input_tokens += 1;
        contract.consistency = ConsistencyMode::BoundedStaleness;
        let Err(errors) = contract.validate() else {
            return Err("invalid contract unexpectedly passed".into());
        };
        assert!(errors.len() >= 2);
        Ok(())
    }

    #[test]
    fn contract_debug_redacts_goal_purpose_and_target_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut contract = contract()?;
        contract.job_goal = "sensitive-goal-canary".to_owned();
        contract.purpose = "sensitive-purpose-canary".to_owned();
        contract.target.provider = "sensitive-provider-canary".to_owned();
        let rendered = format!("{contract:?}");
        assert!(!rendered.contains("sensitive"));
        Ok(())
    }
}
