//! Frozen operation-specific payloads, canonical codecs, and typed handler adapters.

use crate::generated::{OperationContract, operation_by_id};
use crate::{
    ApiError, EventEnvelope, FacadeErrorFactory, FacadeEventStream, MAX_EVENT_PAYLOAD_BYTES,
    MAX_OPERATION_PAYLOAD_BYTES, RequestContext, RequestEnvelope, ResponseEnvelope, ServiceFuture,
    StreamOperationHandler, UnaryOperationHandler,
};
use cigar_canon::{
    CanonicalNode, from_deterministic_cbor, parse_strict_json, to_deterministic_cbor,
    to_normalized_json,
};
use cigar_protocol::{
    ApprovalKind, BlobRef, Budget, CandidateDisposition, Capability, CompensationSpec,
    ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextContract, ContextDelta,
    ContextPlan, ContextRequirement, ContextSpaceId, CoordinationEvent, CoordinationTopic,
    EffectState, HandoffAcceptance, HandoffCapsule, HandoffReferences, HealthReport,
    MaterializedContext, RecipientSelector, RecordId, ReplayCompleteness, ReplayExecution,
    ReplayMode, ResultClaim, RetryPolicy, RiskLevel, SelectionManifest, Validate, VersionId,
};
use futures_core::Stream;
use schemars::{JsonSchema, Schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const MAX_LIST_ITEMS: usize = 1_024;
const MAX_SMALL_LIST_ITEMS: usize = 256;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_SELECTOR_BYTES: usize = 256;
const MAX_TTL_SECONDS: u32 = 86_400;

/// Stable failure while decoding or encoding one operation-specific payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedPayloadError {
    /// The envelope operation does not match the sealed marker.
    WrongOperation,
    /// The input is malformed, noncanonical, contains unknown fields, or fails validation.
    InvalidPayload,
    /// A path binding is missing or disagrees with its payload copy.
    PathMismatch,
    /// A payload exceeds its frozen request, response, event, or collection limit.
    LimitExceeded,
}

impl TypedPayloadError {
    fn error_code(self) -> cigar_protocol::ErrorCode {
        match self {
            Self::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
            Self::WrongOperation | Self::InvalidPayload | Self::PathMismatch => {
                cigar_protocol::ErrorCode::InvalidArgument
            }
        }
    }
}

impl fmt::Display for TypedPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongOperation => "typed payload operation mismatch",
            Self::InvalidPayload => "typed payload is invalid",
            Self::PathMismatch => "typed payload path binding mismatch",
            Self::LimitExceeded => "typed payload exceeds a frozen limit",
        })
    }
}

impl std::error::Error for TypedPayloadError {}

/// A bounded serializable value eligible for a frozen operation payload.
pub trait OperationPayload:
    Serialize + DeserializeOwned + JsonSchema + Send + Sync + 'static
{
    /// Applies operation-specific semantic and collection validation.
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        Ok(())
    }

    /// Returns path-template values duplicated in the typed payload.
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }
}

fn validate_protocol(value: &impl Validate) -> Result<(), TypedPayloadError> {
    value
        .validate()
        .map_err(|_error| TypedPayloadError::InvalidPayload)
}

fn validate_text(value: &str, maximum: usize) -> Result<(), TypedPayloadError> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(TypedPayloadError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_sorted_unique<T: Ord>(values: &[T], maximum: usize) -> Result<(), TypedPayloadError> {
    if values.len() > maximum
        || !values
            .windows(2)
            .all(|window| matches!((window.first(), window.get(1)), (Some(a), Some(b)) if a < b))
    {
        Err(TypedPayloadError::InvalidPayload)
    } else {
        Ok(())
    }
}

fn validate_unique<T: Ord>(values: &[T], maximum: usize) -> Result<(), TypedPayloadError> {
    if values.len() > maximum || values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        Err(TypedPayloadError::InvalidPayload)
    } else {
        Ok(())
    }
}

/// Exact empty-map request used by operational methods.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

impl OperationPayload for EmptyRequest {}

/// Placeholder event type for unary operations.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoEvent {}

impl OperationPayload for NoEvent {}

macro_rules! path_request {
    ($name:ident, $field:ident, $ty:ty, $binding:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            /// Exact resource identity, reconciled with the transport path.
            pub $field: $ty,
        }

        impl OperationPayload for $name {
            fn path_bindings(&self) -> Vec<(&'static str, String)> {
                vec![($binding, self.$field.as_str().to_owned())]
            }
        }
    };
}

path_request!(
    SourceIdRequest,
    source_id,
    RecordId,
    "source_id",
    "Request addressing one persisted source."
);
path_request!(
    AtomIdRequest,
    atom_id,
    RecordId,
    "atom_id",
    "Request addressing one logical atom."
);
path_request!(
    BundleIdRequest,
    bundle_id,
    VersionId,
    "bundle_id",
    "Request addressing one immutable context bundle."
);
path_request!(
    SpaceIdRequest,
    space_id,
    ContextSpaceId,
    "space_id",
    "Request addressing one context space."
);
path_request!(
    HandoffIdRequest,
    handoff_id,
    RecordId,
    "handoff_id",
    "Request addressing one persisted handoff."
);
path_request!(
    EffectIdRequest,
    effect_id,
    RecordId,
    "effect_id",
    "Request addressing one durable effect."
);
path_request!(
    ReplayIdRequest,
    replay_id,
    RecordId,
    "replay_id",
    "Request addressing one persisted replay job."
);

/// Bounded source-discovery request; roots and policy remain server-owned.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverSourcesRequest {
    /// Persisted source configuration selected by the caller.
    pub source_id: RecordId,
    /// Sorted source-relative paths requested as policy-subordinate overrides.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub include_paths: Vec<cigar_protocol::RelativePath>,
}

impl OperationPayload for DiscoverSourcesRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.include_paths, MAX_LIST_ITEMS)
    }
}

/// Source ingestion request bound to one accepted discovery plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngestCatalogRequest {
    /// Persisted source configuration.
    pub source_id: RecordId,
    /// Exact discovery-plan digest accepted by the caller.
    pub plan_digest: ContentDigest,
}

impl OperationPayload for IngestCatalogRequest {}

/// Authorized catalog query inputs; authorization partitions remain server-owned.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryCatalogRequest {
    /// Ordered context requirements to query.
    #[schemars(length(min = 1, max = MAX_SMALL_LIST_ITEMS))]
    pub requirements: Vec<ContextRequirement>,
    /// Caller ceiling, additionally capped by envelope and server limits.
    pub max_results: u16,
}

impl OperationPayload for QueryCatalogRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.requirements.is_empty()
            || self.requirements.len() > MAX_SMALL_LIST_ITEMS
            || self.max_results == 0
            || self.max_results > 1_000
        {
            Err(TypedPayloadError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

/// Ordered exact atom lookup request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchAtomsRequest {
    /// Sorted unique atom identities.
    #[schemars(length(min = 1, max = 1_000))]
    pub atom_ids: Vec<RecordId>,
}

impl OperationPayload for BatchAtomsRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.atom_ids.is_empty() {
            return Err(TypedPayloadError::InvalidPayload);
        }
        validate_unique(&self.atom_ids, 1_000)
    }
}

/// Full planning request whose trusted frozen inputs are derived by the service.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateContextPlanRequest {
    /// Caller-authored context contract.
    pub contract: ContextContract,
}

impl OperationPayload for CreateContextPlanRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.contract)
    }
}

/// Request to persist or retrieve the bundle produced by a retained plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompileContextBundleRequest {
    /// Persisted plan identity.
    pub plan_id: RecordId,
}

impl OperationPayload for CompileContextBundleRequest {}

/// Request for an exact delta from a base bundle to a retained target plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompileContextDeltaRequest {
    /// Exact immutable base bundle.
    pub base_bundle_id: VersionId,
    /// Persisted target plan whose output becomes the delta target.
    pub target_plan_id: RecordId,
}

impl OperationPayload for CompileContextDeltaRequest {}

/// Disclosure-filtered bundle explanation query.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainContextBundleRequest {
    /// Immutable bundle addressed by the route.
    pub bundle_id: VersionId,
    /// Sorted candidate versions the caller asks to explain; authorization is re-derived.
    #[schemars(length(max = 1_000))]
    pub version_ids: Vec<VersionId>,
}

impl OperationPayload for ExplainContextBundleRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.version_ids, 1_000)
    }

    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("bundle_id", self.bundle_id.as_str().to_owned())]
    }
}

/// Closed materialization profile exposed by the v1 service boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationProfile {
    /// Canonical structured JSON materialization.
    CanonicalJson,
    /// Claude-compatible structured prompt materialization.
    ClaudePrompt,
}

/// Materialization request over one retained bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializeContextBundleRequest {
    /// Immutable bundle addressed by the route.
    pub bundle_id: VersionId,
    /// Closed requested framing profile.
    pub profile: MaterializationProfile,
}

impl OperationPayload for MaterializeContextBundleRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("bundle_id", self.bundle_id.as_str().to_owned())]
    }
}

/// Content-safe receipt for a durable mutation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReceipt {
    /// Logical resource changed by the mutation.
    pub resource_id: RecordId,
    /// Monotonic durable revision after the change.
    pub revision: u64,
    /// Whether the exact idempotent result was replayed.
    pub replayed: bool,
}

impl OperationPayload for MutationReceipt {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.revision == 0 {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Disclosure-safe discovery result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPlanResponse {
    /// Persisted source configuration.
    pub source_id: RecordId,
    /// Eligible source item count.
    pub included_count: u64,
    /// Eligible aggregate source bytes.
    pub included_bytes: u64,
    /// Exact normalized discovery-plan digest.
    pub plan_digest: ContentDigest,
}

impl OperationPayload for DiscoveryPlanResponse {}

/// Content-safe ingestion publication result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngestionReceiptResponse {
    /// Repository revision after publication.
    pub revision: u64,
    /// Published immutable snapshot identity.
    pub snapshot_id: RecordId,
    /// Newly published atom versions.
    pub published_atoms: u64,
    /// Newly published tombstones.
    pub tombstoned_atoms: u64,
    /// Exact publication digest.
    pub publication_digest: ContentDigest,
}

impl OperationPayload for IngestionReceiptResponse {}

/// Closed content-free source health state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// Source can serve bounded operations.
    Ready,
    /// Source can serve reads but requires refresh.
    Degraded,
    /// Source cannot safely serve requests.
    Unavailable,
}

/// Content-free source health response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStatusResponse {
    /// Persisted source configuration.
    pub source_id: RecordId,
    /// Current health state.
    pub status: SourceStatus,
    /// Last observed connector watermark.
    pub watermark: u64,
}

impl OperationPayload for SourceStatusResponse {}

/// Bounded metadata-only catalog query response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogQueryResponse {
    /// Ordered authorized semantic versions.
    #[schemars(length(max = 1_000))]
    pub version_ids: Vec<VersionId>,
    /// Fingerprint of the exact query plan and snapshot.
    pub query_digest: ContentDigest,
    /// Whether an optional index channel degraded safely.
    pub degraded: bool,
}

impl OperationPayload for CatalogQueryResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.version_ids, 1_000)
    }
}

/// One result in an ordered exact atom lookup.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomLookupResult {
    /// The exact atom was visible and retained.
    Found {
        /// Authorized immutable atom.
        atom: Box<ContextAtomV1>,
    },
    /// The atom was absent or existence-hidden.
    Missing {
        /// Requested logical atom identity.
        atom_id: RecordId,
    },
}

impl AtomLookupResult {
    fn atom_id(&self) -> &RecordId {
        match self {
            Self::Found { atom } => &atom.atom_id,
            Self::Missing { atom_id } => atom_id,
        }
    }
}

/// Ordered atom lookup response preserving exact request order.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AtomBatchResponse {
    /// Exactly one result for each requested atom identity, in request order.
    #[schemars(length(min = 1, max = 1_000))]
    pub results: Vec<AtomLookupResult>,
}

impl OperationPayload for AtomBatchResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.results.is_empty() || self.results.len() > 1_000 {
            return Err(TypedPayloadError::LimitExceeded);
        }
        for result in &self.results {
            if let AtomLookupResult::Found { atom } = result {
                validate_protocol(atom.as_ref())?;
            }
        }
        let identities: Vec<_> = self.results.iter().map(AtomLookupResult::atom_id).collect();
        validate_unique(&identities, 1_000)
    }
}

/// Persisted plan-backed compile output returned by planning.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPlanResponse {
    /// Deterministic context plan.
    pub plan: ContextPlan,
    /// Bundle already compiled and persisted from the plan.
    pub bundle_id: VersionId,
    /// Complete protected manifest digest.
    pub manifest_digest: ContentDigest,
}

impl OperationPayload for ContextPlanResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.plan)
    }
}

/// Sealed delta and its exact canonical digest.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextDeltaResponse {
    /// Deterministic block delta.
    pub delta: ContextDelta,
    /// Digest of the exact delta record.
    pub delta_digest: ContentDigest,
}

impl OperationPayload for ContextDeltaResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.delta)
    }
}

/// One disclosure-filtered explanation entry.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextExplanationEntry {
    /// Authorized semantic version.
    pub version_id: VersionId,
    /// Final deterministic disposition.
    pub disposition: CandidateDisposition,
}

/// Disclosure-filtered explanation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextExplanationResponse {
    /// Sorted authorized entries only.
    #[schemars(length(max = 1_000))]
    pub entries: Vec<ContextExplanationEntry>,
}

impl OperationPayload for ContextExplanationResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.entries.len() > 1_000
            || !self.entries.windows(2).all(|window| {
                matches!((window.first(), window.get(1)), (Some(a), Some(b)) if a.version_id < b.version_id)
            })
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Exact materialization plus physical token accounting.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationResponse {
    /// Provider-ready immutable materialization.
    pub context: MaterializedContext,
    /// Exact physical input tokens.
    pub physical_input_tokens: u32,
}

impl OperationPayload for MaterializationResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.context)?;
        if self.physical_input_tokens == 0 || self.physical_input_tokens != self.context.token_count
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Current validity result for a retained bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidationResponse {
    /// Revalidated immutable bundle.
    pub bundle_id: VersionId,
    /// Whether every frozen dependency remains valid and authorized.
    pub valid: bool,
    /// Sorted stable invalidation reason symbols.
    #[schemars(
        length(max = MAX_SMALL_LIST_ITEMS),
        inner(length(min = 1, max = MAX_SELECTOR_BYTES))
    )]
    pub reasons: Vec<String>,
}

impl OperationPayload for RevalidationResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.reasons, MAX_SMALL_LIST_ITEMS)?;
        if self.valid != self.reasons.is_empty()
            || self
                .reasons
                .iter()
                .any(|reason| validate_text(reason, MAX_SELECTOR_BYTES).is_err())
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Caller-controlled context-space hierarchy excluding the server-derived tenant and author.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSpaceRequest {
    /// Workspace identity.
    pub workspace_id: RecordId,
    /// Active project identity.
    pub project_id: RecordId,
    /// Branch or worktree identity.
    pub branch_id: RecordId,
    /// Task identity.
    pub task_id: RecordId,
    /// Session identity.
    pub session_id: RecordId,
    /// Bounded semantic purpose.
    #[schemars(length(min = 1, max = MAX_TEXT_BYTES))]
    pub purpose: String,
}

impl OperationPayload for CreateSpaceRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_text(&self.purpose, MAX_TEXT_BYTES)
    }
}

/// Closed kind of context-space fork.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpaceFork {
    /// Creates a private overlay over one exact immutable base.
    PrivateOverlay {
        /// Exact merge base.
        base_commit_id: VersionId,
        /// Requested bounded lifetime from server observation time.
        ttl_seconds: u32,
    },
    /// Creates a resumable focus branch.
    FocusBranch {
        /// Caller-selected focus identity.
        focus_id: RecordId,
        /// Bounded display label.
        #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
        label: String,
        /// Whether the new focus begins offline.
        offline: bool,
    },
}

/// Tagged private-overlay or focus-branch fork request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForkSpaceRequest {
    /// Context space addressed by the route.
    pub space_id: ContextSpaceId,
    /// Closed fork specification.
    pub fork: SpaceFork,
}

impl OperationPayload for ForkSpaceRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        match &self.fork {
            SpaceFork::PrivateOverlay { ttl_seconds, .. }
                if *ttl_seconds == 0 || *ttl_seconds > MAX_TTL_SECONDS =>
            {
                Err(TypedPayloadError::LimitExceeded)
            }
            SpaceFork::FocusBranch { label, .. } => validate_text(label, MAX_SELECTOR_BYTES),
            SpaceFork::PrivateOverlay { .. } => Ok(()),
        }
    }

    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("space_id", self.space_id.as_str().to_owned())]
    }
}

/// Optimistic overlay publication request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSpaceRequest {
    /// Context space addressed by the route.
    pub space_id: ContextSpaceId,
    /// Exact owner-private overlay.
    pub overlay_id: RecordId,
    /// Bounded publication purpose.
    #[schemars(length(min = 1, max = MAX_TEXT_BYTES))]
    pub purpose: String,
}

impl OperationPayload for PublishSpaceRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_text(&self.purpose, MAX_TEXT_BYTES)
    }

    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("space_id", self.space_id.as_str().to_owned())]
    }
}

/// Explicit focus checkpoint request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSpaceRequest {
    /// Context space addressed by the route.
    pub space_id: ContextSpaceId,
    /// Exact focus to checkpoint.
    pub focus_id: RecordId,
}

impl OperationPayload for CheckpointSpaceRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("space_id", self.space_id.as_str().to_owned())]
    }
}

/// Closed typed conflict resolution choice.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "choice", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConflictResolution {
    /// Retains the immutable base value.
    Base,
    /// Retains the current canonical value.
    Current,
    /// Accepts the owner-private proposed value.
    Proposed,
    /// Applies a separately persisted typed decision.
    TypedDecision {
        /// Exact decision record version.
        decision_id: VersionId,
    },
}

/// Request resolving one durable stable conflict identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveSpaceConflictRequest {
    /// Context space addressed by the route.
    pub space_id: ContextSpaceId,
    /// Stable conflict addressed by the route.
    pub conflict_id: RecordId,
    /// Closed typed resolution.
    pub resolution: ConflictResolution,
}

impl OperationPayload for ResolveSpaceConflictRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![
            ("conflict_id", self.conflict_id.as_str().to_owned()),
            ("space_id", self.space_id.as_str().to_owned()),
        ]
    }
}

/// Disclosure-safe fork result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpaceForkResponse {
    /// A private overlay was created.
    PrivateOverlay {
        /// New overlay identity.
        overlay_id: RecordId,
        /// Exact immutable merge base.
        base_commit_id: VersionId,
    },
    /// A focus branch was created.
    FocusBranch {
        /// New focus identity.
        focus_id: RecordId,
        /// Exact fork commit.
        fork_commit_id: VersionId,
    },
}

impl OperationPayload for SpaceForkResponse {}

/// Closed publication outcome without exposing private conflicting values.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpacePublishResponse {
    /// A new commit became canonical.
    Published {
        /// Immutable published commit.
        commit: ContextCommit,
    },
    /// Publication made no semantic change.
    Deduplicated {
        /// Existing immutable head.
        commit: ContextCommit,
    },
    /// Conflicts were durably retained for later resolution.
    Conflicted {
        /// Sorted stable conflict identities.
        #[schemars(length(min = 1, max = MAX_LIST_ITEMS))]
        conflict_ids: Vec<RecordId>,
    },
}

impl OperationPayload for SpacePublishResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        match self {
            Self::Published { commit } | Self::Deduplicated { commit } => validate_protocol(commit),
            Self::Conflicted { conflict_ids } => {
                if conflict_ids.is_empty() {
                    return Err(TypedPayloadError::InvalidPayload);
                }
                validate_sorted_unique(conflict_ids, MAX_LIST_ITEMS)
            }
        }
    }
}

/// Bounded immutable context-space history page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceLogResponse {
    /// Ordered commits for the pinned snapshot.
    #[schemars(length(max = 1_000))]
    pub commits: Vec<ContextCommit>,
}

impl OperationPayload for SpaceLogResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.commits.len() > 1_000 {
            return Err(TypedPayloadError::LimitExceeded);
        }
        for commit in &self.commits {
            validate_protocol(commit)?;
        }
        if !self.commits.windows(2).all(|window| {
            matches!((window.first(), window.get(1)), (Some(a), Some(b)) if a.sequence < b.sequence)
        }) {
            return Err(TypedPayloadError::InvalidPayload);
        }
        Ok(())
    }
}

/// Marker response for successful stream establishment.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOpenResponse {}

impl OperationPayload for StreamOpenResponse {}

/// Typed context-space stream event.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceEventPayload {
    /// Owning context space.
    pub space_id: ContextSpaceId,
    /// Disclosure-scoped project identity.
    pub project_id: RecordId,
    /// Immutable coordination event.
    pub event: CoordinationEvent,
}

impl OperationPayload for SpaceEventPayload {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        Ok(())
    }
}

/// Durable focus checkpoint response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCheckpointResponse {
    /// Checkpointed focus identity.
    pub focus_id: RecordId,
    /// Exact immutable checkpoint commit.
    pub commit_id: VersionId,
}

impl OperationPayload for SpaceCheckpointResponse {}

/// Disclosure-safe durable conflict summary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSummary {
    /// Stable conflict identity.
    pub conflict_id: RecordId,
    /// Exact immutable merge base.
    pub base_commit_id: VersionId,
    /// Required resolver class symbol.
    #[schemars(length(min = 1, max = 64))]
    pub resolver: String,
}

/// Bounded conflict list response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictListResponse {
    /// Sorted conflict summaries.
    #[schemars(length(max = 1_000))]
    pub conflicts: Vec<ConflictSummary>,
}

impl OperationPayload for ConflictListResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.conflicts.len() > 1_000
            || !self.conflicts.windows(2).all(|window| {
                matches!((window.first(), window.get(1)), (Some(a), Some(b)) if a.conflict_id < b.conflict_id)
            })
            || self
                .conflicts
                .iter()
                .any(|conflict| validate_text(&conflict.resolver, 64).is_err())
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Receipt for one resolved stable conflict.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionResponse {
    /// Consumed conflict identity.
    pub conflict_id: RecordId,
    /// Immutable commit produced after resolution.
    pub commit: ContextCommit,
}

impl OperationPayload for ConflictResolutionResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.commit)
    }
}

/// Caller-authored handoff draft excluding authority, clock, key, and nonce fields.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHandoffRequest {
    /// Intended principal or role.
    pub recipient: RecipientSelector,
    /// Bounded task statement.
    #[schemars(length(min = 1, max = MAX_TEXT_BYTES))]
    pub task: String,
    /// Bounded acceptance criteria.
    #[schemars(
        length(min = 1, max = MAX_SMALL_LIST_ITEMS),
        inner(length(min = 1, max = MAX_TEXT_BYTES))
    )]
    pub acceptance_criteria: Vec<String>,
    /// Sorted requested project scope.
    #[schemars(length(max = 64))]
    pub requested_projects: Vec<RecordId>,
    /// Sorted requested capabilities.
    #[schemars(length(max = 64))]
    pub requested_capabilities: Vec<Capability>,
    /// Recipient compilation ceiling.
    pub budget: Budget,
    /// Sorted requested event topics.
    #[schemars(length(max = 64))]
    pub topics: Vec<CoordinationTopic>,
    /// Typed references only.
    pub references: HandoffReferences,
    /// Source bundle identity.
    pub bundle_id: VersionId,
    /// Runtime audience selector.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub audience: String,
    /// Requested lifetime from server observation time.
    pub ttl_seconds: u32,
    /// Whether multiple acceptances are requested.
    pub reusable: bool,
}

impl OperationPayload for CreateHandoffRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_text(&self.task, MAX_TEXT_BYTES)?;
        validate_text(&self.audience, MAX_SELECTOR_BYTES)?;
        if self.ttl_seconds == 0 || self.ttl_seconds > MAX_TTL_SECONDS {
            return Err(TypedPayloadError::LimitExceeded);
        }
        if self.acceptance_criteria.is_empty()
            || self.acceptance_criteria.len() > MAX_SMALL_LIST_ITEMS
            || self
                .acceptance_criteria
                .iter()
                .any(|value| validate_text(value, MAX_TEXT_BYTES).is_err())
        {
            return Err(TypedPayloadError::InvalidPayload);
        }
        validate_sorted_unique(&self.requested_projects, 64)?;
        validate_sorted_unique(&self.requested_capabilities, 64)?;
        validate_sorted_unique(&self.topics, 64)
    }
}

/// Existing handoff acceptance request; recipient authority is server-derived.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptHandoffRequest {
    /// Handoff addressed by the route.
    pub handoff_id: RecordId,
    /// Persisted recipient-specific target plan.
    pub target_plan_id: RecordId,
}

impl OperationPayload for AcceptHandoffRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("handoff_id", self.handoff_id.as_str().to_owned())]
    }
}

/// Handoff revocation request with content-safe evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeHandoffRequest {
    /// Handoff addressed by the route.
    pub handoff_id: RecordId,
    /// Digest of the authorized revocation reason/evidence.
    pub reason_digest: ContentDigest,
}

impl OperationPayload for RevokeHandoffRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("handoff_id", self.handoff_id.as_str().to_owned())]
    }
}

/// Child-result payload excluding the authenticated producer and server-generated delta identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHandoffResultRequest {
    /// Handoff addressed by the route.
    pub handoff_id: RecordId,
    /// Exact parent base commit.
    pub base_commit_id: VersionId,
    /// Evidence-backed result claims.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub claims: Vec<ResultClaim>,
    /// Sorted decision references.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub decisions: Vec<VersionId>,
    /// Sorted artifact references.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub artifacts: Vec<VersionId>,
    /// Sorted source-change references.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub source_changes: Vec<VersionId>,
    /// Sorted verifier receipt references.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub verifier_receipts: Vec<VersionId>,
    /// Bounded unresolved questions.
    #[schemars(
        length(max = MAX_LIST_ITEMS),
        inner(length(min = 1, max = MAX_TEXT_BYTES))
    )]
    pub unresolved_questions: Vec<String>,
    /// Bounded blockers.
    #[schemars(
        length(max = MAX_LIST_ITEMS),
        inner(length(min = 1, max = MAX_TEXT_BYTES))
    )]
    pub blockers: Vec<String>,
    /// Sorted effect references.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub effect_references: Vec<VersionId>,
    /// Sorted follow-up capabilities requested but not granted.
    #[schemars(length(max = 64))]
    pub requested_followup_capabilities: Vec<Capability>,
}

impl OperationPayload for RecordHandoffResultRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.claims.len() > MAX_LIST_ITEMS
            || self.unresolved_questions.len() > MAX_LIST_ITEMS
            || self.blockers.len() > MAX_LIST_ITEMS
            || self
                .unresolved_questions
                .iter()
                .chain(&self.blockers)
                .any(|value| validate_text(value, MAX_TEXT_BYTES).is_err())
        {
            return Err(TypedPayloadError::LimitExceeded);
        }
        validate_sorted_unique(&self.decisions, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.artifacts, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.source_changes, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.verifier_receipts, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.effect_references, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.requested_followup_capabilities, 64)
    }

    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("handoff_id", self.handoff_id.as_str().to_owned())]
    }
}

/// Request merging one previously recorded child result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeHandoffRequest {
    /// Handoff addressed by the route.
    pub handoff_id: RecordId,
    /// Persisted child-result identity.
    pub delta_id: RecordId,
    /// Parent context space.
    pub space_id: ContextSpaceId,
    /// Parent owner-private overlay.
    pub overlay_id: RecordId,
}

impl OperationPayload for MergeHandoffRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("handoff_id", self.handoff_id.as_str().to_owned())]
    }
}

/// Exact disclosure and attenuation preview for an existing handoff.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffPreviewResponse {
    /// Persisted handoff identity.
    pub handoff_id: RecordId,
    /// Projects retained after attenuation.
    #[schemars(length(max = 64))]
    pub accepted_projects: Vec<RecordId>,
    /// Projects rejected without content disclosure.
    #[schemars(length(max = 64))]
    pub rejected_projects: Vec<RecordId>,
    /// Capabilities retained after attenuation.
    #[schemars(length(max = 64))]
    pub accepted_capabilities: Vec<Capability>,
    /// Capabilities rejected during attenuation.
    #[schemars(length(max = 64))]
    pub rejected_capabilities: Vec<Capability>,
    /// Typed reference count.
    pub reference_count: u32,
}

impl OperationPayload for HandoffPreviewResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.accepted_projects, 64)?;
        validate_sorted_unique(&self.rejected_projects, 64)?;
        validate_sorted_unique(&self.accepted_capabilities, 64)?;
        validate_sorted_unique(&self.rejected_capabilities, 64)
    }
}

/// Signed handoff and its disclosure preview.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHandoffResponse {
    /// Persisted signed capsule.
    pub capsule: HandoffCapsule,
    /// Disclosure-safe attenuation preview.
    pub preview: HandoffPreviewResponse,
}

impl OperationPayload for CreateHandoffResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.capsule)?;
        self.preview.validate_payload()?;
        if self.capsule.handoff_id != self.preview.handoff_id {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Receipt for one immutable child result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffResultReceipt {
    /// Persisted child-result identity.
    pub delta_id: RecordId,
    /// Owning handoff identity.
    pub handoff_id: RecordId,
    /// Exact result digest.
    pub result_digest: ContentDigest,
    /// Durable revision after publication.
    pub revision: u64,
}

impl OperationPayload for HandoffResultReceipt {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.revision == 0 {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Result of proposing and publishing a recorded handoff delta.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffMergeResponse {
    /// Recorded delta identity.
    pub delta_id: RecordId,
    /// Versions proposed into the parent overlay.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub proposed_versions: Vec<VersionId>,
    /// Versions rejected by current authorization.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub rejected_versions: Vec<VersionId>,
    /// Conflicts retained for typed resolution.
    #[schemars(length(max = MAX_LIST_ITEMS))]
    pub conflict_ids: Vec<RecordId>,
    /// New or deduplicated parent commit when publication completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<ContextCommit>,
}

impl OperationPayload for HandoffMergeResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.proposed_versions, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.rejected_versions, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.conflict_ids, MAX_LIST_ITEMS)?;
        if let Some(commit) = &self.commit {
            validate_protocol(commit)?;
        }
        if self.commit.is_some() != self.conflict_ids.is_empty() {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Caller-authored effect intent excluding clocks, actor authority, and dispatch permits.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareEffectRequest {
    /// Registered connector selector.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub connector: String,
    /// Connector operation selector.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub operation: String,
    /// Digest of normalized arguments.
    pub arguments_digest: ContentDigest,
    /// Protected normalized argument reference.
    pub encrypted_arguments: BlobRef,
    /// Bounded target selector.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub target: String,
    /// Sorted precondition digests.
    #[schemars(length(max = MAX_SMALL_LIST_ITEMS))]
    pub preconditions: Vec<ContentDigest>,
    /// Expected result schema digest.
    pub result_schema_digest: ContentDigest,
    /// Risk classification.
    pub risk: RiskLevel,
    /// Source decision record.
    pub source_decision_id: VersionId,
    /// Source context bundle.
    pub bundle_id: VersionId,
    /// Capability the service must verify at authorization and dispatch.
    pub required_capability: Capability,
    /// Normalized connector idempotency scope.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub idempotency_scope: String,
    /// Safe retry strategy.
    pub retry_policy: RetryPolicy,
    /// Requested lifetime from server observation time.
    pub ttl_seconds: u32,
    /// Optional separately authorized compensation description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compensation: Option<CompensationSpec>,
}

impl OperationPayload for PrepareEffectRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        for value in [
            &self.connector,
            &self.operation,
            &self.target,
            &self.idempotency_scope,
        ] {
            validate_text(value, MAX_SELECTOR_BYTES)?;
        }
        validate_sorted_unique(&self.preconditions, MAX_SMALL_LIST_ITEMS)?;
        if self.ttl_seconds == 0 || self.ttl_seconds > MAX_TTL_SECONDS {
            Err(TypedPayloadError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

/// Approval semantics supplied by a caller; approver identity and times are server-derived.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectApprovalDraft {
    /// Caller-selected approval identity.
    pub approval_id: RecordId,
    /// Digest of approval conditions and limits.
    pub conditions_digest: ContentDigest,
    /// Approval provenance class.
    pub kind: ApprovalKind,
    /// Requested approval lifetime from server observation time.
    pub ttl_seconds: u32,
}

impl EffectApprovalDraft {
    fn validate_draft(&self) -> Result<(), TypedPayloadError> {
        if self.ttl_seconds == 0 || self.ttl_seconds > MAX_TTL_SECONDS {
            Err(TypedPayloadError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

/// Effect authorization request over one exact durable revision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeEffectRequest {
    /// Effect addressed by the route.
    pub effect_id: RecordId,
    /// Optional explicit approval; low-risk policy may permit absence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<EffectApprovalDraft>,
}

impl OperationPayload for AuthorizeEffectRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if let Some(approval) = &self.approval {
            approval.validate_draft()?;
        }
        Ok(())
    }

    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("effect_id", self.effect_id.as_str().to_owned())]
    }
}

/// Requests compensation through one separately prepared and authorized child effect.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompensateEffectRequest {
    /// Original effect addressed by the route.
    pub effect_id: RecordId,
    /// Separately authorized compensation effect.
    pub compensation_effect_id: RecordId,
    /// Digest of the original compensation specification.
    pub compensation_spec_digest: ContentDigest,
}

impl OperationPayload for CompensateEffectRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.effect_id == self.compensation_effect_id {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }

    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("effect_id", self.effect_id.as_str().to_owned())]
    }
}

/// Disclosure-safe current effect projection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectStatusResponse {
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// Current closed state.
    pub state: EffectState,
    /// Monotonic effect version.
    pub effect_version: u64,
    /// Exact intent digest.
    pub intent_digest: ContentDigest,
    /// Number of durable dispatch attempts.
    pub attempt_count: u32,
    /// Number of reconciliation observations.
    pub reconciliation_count: u32,
}

impl OperationPayload for EffectStatusResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.effect_version == 0 && (self.attempt_count != 0 || self.reconciliation_count != 0) {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Replay job creation input excluding requester identity and live authorization proof.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReplayRequest {
    /// Source decision to reconstruct.
    pub decision_id: VersionId,
    /// Requested replay mode.
    pub mode: ReplayMode,
    /// Whether all effects remain simulated.
    pub simulate_effects: bool,
}

impl OperationPayload for CreateReplayRequest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.mode != ReplayMode::LiveComparison && !self.simulate_effects {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Live comparison request referencing a separately verified one-use authorization.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompareLiveReplayRequest {
    /// Persisted replay job addressed by the route.
    pub replay_id: RecordId,
    /// Server-persisted live authorization identity.
    pub live_authorization_id: RecordId,
}

impl OperationPayload for CompareLiveReplayRequest {
    fn path_bindings(&self) -> Vec<(&'static str, String)> {
        vec![("replay_id", self.replay_id.as_str().to_owned())]
    }
}

/// Closed persisted replay-job state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayJobStatus {
    /// Evidence or invocation replay is executing.
    Running,
    /// Evidence or invocation replay completed during creation.
    Complete,
    /// Observational replay is retained for the run operation.
    PendingObservational,
    /// Live comparison is retained for explicit authorization and compare.
    PendingLive,
    /// Replay lacks one or more exact dependencies.
    Incomplete,
    /// Replay failed without exposing protected details.
    Failed,
}

/// Persisted replay job and optional immediate evidence/invocation execution.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayJobResponse {
    /// Stable replay job identity.
    pub replay_id: RecordId,
    /// Requested replay mode.
    pub mode: ReplayMode,
    /// Current job status.
    pub status: ReplayJobStatus,
    /// Immediate execution for evidence or invocation mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ReplayExecution>,
}

impl OperationPayload for ReplayJobResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if let Some(execution) = &self.execution {
            validate_protocol(execution)?;
            if execution.mode != self.mode {
                return Err(TypedPayloadError::InvalidPayload);
            }
        }
        let immediate = matches!(
            self.mode,
            ReplayMode::EvidenceReproduction | ReplayMode::InvocationReproduction
        );
        let terminal = matches!(
            self.status,
            ReplayJobStatus::Complete | ReplayJobStatus::Incomplete | ReplayJobStatus::Failed
        );
        if immediate && terminal != self.execution.is_some()
            || (!immediate && self.execution.is_some())
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Content-free liveness response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessResponse {
    /// True while the process event loop can serve requests.
    pub live: bool,
}

impl OperationPayload for LivenessResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.live {
            Ok(())
        } else {
            Err(TypedPayloadError::InvalidPayload)
        }
    }
}

/// Structured readiness response retaining every content-free component observation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessResponse {
    /// Whether startup and shutdown admission gate is open.
    pub gate_open: bool,
    /// Whether the process is ready for governed traffic.
    pub ready: bool,
    /// Complete dependency report.
    pub dependency_report: HealthReport,
}

impl OperationPayload for ReadinessResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(&self.dependency_report)?;
        let healthy = self.dependency_report.status == cigar_protocol::HealthStatus::Healthy;
        if self.ready != (self.gate_open && healthy) {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Stable build and protocol compatibility response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionResponse {
    /// Package semantic version.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub version: String,
    /// Source revision or `unknown`.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub source_revision: String,
    /// Minimum accepted protocol.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub protocol_min: String,
    /// Maximum accepted protocol line.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub protocol_max: String,
    /// Release or debug build class.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub build_profile: String,
    /// Sorted compile-time public feature names.
    #[schemars(
        length(max = MAX_SMALL_LIST_ITEMS),
        inner(length(min = 1, max = MAX_SELECTOR_BYTES))
    )]
    pub enabled_features: Vec<String>,
}

impl OperationPayload for VersionResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        for value in [
            &self.version,
            &self.source_revision,
            &self.protocol_min,
            &self.protocol_max,
            &self.build_profile,
        ] {
            validate_text(value, MAX_SELECTOR_BYTES)?;
        }
        validate_sorted_unique(&self.enabled_features, MAX_SMALL_LIST_ITEMS)
    }
}

/// Public compatibility and bounded capability document.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesResponse {
    /// Supported API line.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub api_version: String,
    /// Supported protocol line.
    #[schemars(length(min = 1, max = MAX_SELECTOR_BYTES))]
    pub protocol_version: String,
    /// Sorted enabled deployment profiles.
    #[schemars(
        length(max = MAX_SMALL_LIST_ITEMS),
        inner(length(min = 1, max = MAX_SELECTOR_BYTES))
    )]
    pub profiles: Vec<String>,
    /// Sorted enabled extension identifiers.
    #[schemars(
        length(max = MAX_SMALL_LIST_ITEMS),
        inner(length(min = 1, max = MAX_SELECTOR_BYTES))
    )]
    pub extensions: Vec<String>,
    /// Maximum canonical operation payload bytes.
    pub max_payload_bytes: u32,
    /// Maximum event payload bytes.
    pub max_event_bytes: u32,
    /// Maximum page size.
    pub max_page_size: u16,
}

impl OperationPayload for CapabilitiesResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_text(&self.api_version, MAX_SELECTOR_BYTES)?;
        validate_text(&self.protocol_version, MAX_SELECTOR_BYTES)?;
        validate_sorted_unique(&self.profiles, MAX_SMALL_LIST_ITEMS)?;
        validate_sorted_unique(&self.extensions, MAX_SMALL_LIST_ITEMS)?;
        if self.max_payload_bytes == 0
            || usize::try_from(self.max_payload_bytes).ok() > Some(MAX_OPERATION_PAYLOAD_BYTES)
            || self.max_event_bytes == 0
            || usize::try_from(self.max_event_bytes).ok() > Some(MAX_EVENT_PAYLOAD_BYTES)
            || self.max_page_size == 0
            || self.max_page_size > 1_000
        {
            Err(TypedPayloadError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

/// Closed redacted daemon deployment mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicDeploymentMode {
    /// Permission-restricted local service.
    Local,
    /// TLS-authenticated shared service.
    Shared,
}

/// Redacted public configuration summary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationResponse {
    /// Deployment mode.
    pub mode: PublicDeploymentMode,
    /// Whether local IPC is enabled.
    pub local_ipc: bool,
    /// Whether HTTP is enabled.
    pub http_enabled: bool,
    /// Whether gRPC is enabled.
    pub grpc_enabled: bool,
    /// Maximum expanded request bytes.
    pub max_request_bytes: u32,
    /// Maximum request timeout milliseconds.
    pub max_timeout_ms: u64,
}

impl OperationPayload for ConfigurationResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.max_request_bytes == 0 || self.max_timeout_ms == 0 {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// One bounded content-free worker queue diagnostic.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueDiagnostic {
    /// Stable queue name.
    #[schemars(length(min = 1, max = 64))]
    pub name: String,
    /// Fixed queue capacity.
    pub capacity: u32,
    /// Current queue depth.
    pub depth: u32,
    /// Rejected enqueue count.
    pub rejected: u64,
    /// Whether a worker heartbeat is currently healthy.
    pub worker_healthy: bool,
}

/// One explicitly typed public telemetry counter.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticCounter {
    /// Stable public metric name.
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    /// Monotonic or point-in-time unsigned value.
    pub value: u64,
}

/// Content-safe bounded diagnostic response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsResponse {
    /// Whether request admission is currently open.
    pub ready: bool,
    /// Sorted queue diagnostics.
    #[schemars(length(max = 64))]
    pub queues: Vec<QueueDiagnostic>,
    /// Sorted stable public telemetry counters.
    #[schemars(length(max = 512))]
    pub counters: Vec<DiagnosticCounter>,
}

impl OperationPayload for DiagnosticsResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.queues.len() > 64
            || self.counters.len() > 512
            || !self.queues.windows(2).all(|window| {
                matches!((window.first(), window.get(1)), (Some(a), Some(b)) if a.name < b.name)
            })
            || !self.counters.windows(2).all(|window| {
                matches!((window.first(), window.get(1)), (Some(a), Some(b)) if a.name < b.name)
            })
            || self.queues.iter().any(|queue| {
                validate_text(&queue.name, 64).is_err()
                    || queue.capacity == 0
                    || queue.depth > queue.capacity
            })
            || self
                .counters
                .iter()
                .any(|counter| validate_text(&counter.name, 128).is_err())
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Bounded OpenMetrics response shared by embedded and network modes.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsResponse {
    /// Exact OpenMetrics media type.
    #[schemars(length(min = 1, max = 128))]
    pub media_type: String,
    /// Content-safe OpenMetrics text exposition.
    #[schemars(length(max = MAX_OPERATION_PAYLOAD_BYTES))]
    pub text: String,
}

impl OperationPayload for MetricsResponse {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        if self.media_type != "application/openmetrics-text; version=1.0.0; charset=utf-8"
            || self.text.len() > MAX_OPERATION_PAYLOAD_BYTES
            || self.text.contains('\0')
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

impl OperationPayload for ContextBundle {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(self)
    }
}

impl OperationPayload for SelectionManifest {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(self)
    }
}

impl OperationPayload for ContextCommit {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(self)
    }
}

impl OperationPayload for HandoffAcceptance {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(self)
    }
}

impl OperationPayload for ReplayExecution {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_protocol(self)
    }
}

impl OperationPayload for ReplayCompleteness {
    fn validate_payload(&self) -> Result<(), TypedPayloadError> {
        validate_sorted_unique(&self.available, MAX_LIST_ITEMS)?;
        validate_sorted_unique(&self.missing, MAX_LIST_ITEMS)?;
        if self
            .available
            .iter()
            .any(|kind| self.missing.binary_search(kind).is_ok())
        {
            Err(TypedPayloadError::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed operation marker binding one frozen identity to exact payload types.
pub trait TypedOperation: sealed::Sealed + Send + Sync + 'static {
    /// Stable lower-camel operation identifier.
    const OPERATION_ID: &'static str;
    /// Frozen request schema name.
    const REQUEST_SCHEMA: &'static str;
    /// Frozen response schema name.
    const RESPONSE_SCHEMA: &'static str;
    /// Frozen event schema name for the sole server stream.
    const EVENT_SCHEMA: Option<&'static str>;
    /// Exact request payload.
    type Request: OperationPayload;
    /// Exact unary response payload, or stream-open marker for a stream operation.
    type Response: OperationPayload;
    /// Exact stream event payload, or [`NoEvent`] for unary operations.
    type Event: OperationPayload;
}

/// One operation-to-payload mapping used by compatibility and completeness tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypedOperationMapping {
    /// Stable operation identity.
    pub operation_id: &'static str,
    /// Frozen request schema name.
    pub request_schema: &'static str,
    /// Frozen response schema name.
    pub response_schema: &'static str,
    /// Frozen event schema name, present only for server streaming.
    pub event_schema: Option<&'static str>,
}

/// One named self-contained JSON Schema generated from an exact Rust payload type.
#[derive(Clone, Debug)]
pub struct TypedPayloadSchema {
    /// Frozen payload schema name used by the public operation registry.
    pub name: &'static str,
    /// JSON Schema 2020-12 resource, including its referenced definitions.
    pub schema: Schema,
}

/// Request, response, and optional event schemas for one frozen operation.
#[derive(Clone, Debug)]
pub struct TypedOperationSchemas {
    /// Stable lower-camel operation identifier.
    pub operation_id: &'static str,
    /// Exact request payload schema.
    pub request: TypedPayloadSchema,
    /// Exact unary response or stream-open payload schema.
    pub response: TypedPayloadSchema,
    /// Exact stream event payload schema, present only for server streaming.
    pub event: Option<TypedPayloadSchema>,
}

#[derive(Clone, Copy)]
struct TypedOperationSchemaFactory {
    operation_id: &'static str,
    request_schema: &'static str,
    response_schema: &'static str,
    event_schema: Option<&'static str>,
    request: fn() -> Schema,
    response: fn() -> Schema,
    event: fn() -> Schema,
}

fn payload_schema<T: OperationPayload>() -> Schema {
    schemars::SchemaGenerator::default().into_root_schema_for::<T>()
}

/// Generates the authoritative exact-45 operation payload schema documents.
#[must_use]
pub fn typed_operation_schemas() -> Vec<TypedOperationSchemas> {
    TYPED_OPERATION_SCHEMA_FACTORIES
        .iter()
        .map(|factory| TypedOperationSchemas {
            operation_id: factory.operation_id,
            request: TypedPayloadSchema {
                name: factory.request_schema,
                schema: (factory.request)(),
            },
            response: TypedPayloadSchema {
                name: factory.response_schema,
                schema: (factory.response)(),
            },
            event: factory.event_schema.map(|name| TypedPayloadSchema {
                name,
                schema: (factory.event)(),
            }),
        })
        .collect()
}

macro_rules! define_typed_operations {
    ($(
        $marker:ident => ($id:literal, $request:ty, $request_schema:literal,
            $response:ty, $response_schema:literal, $event:ty, $event_schema:expr)
    ),+ $(,)?) => {
        $(
            #[doc = concat!("Sealed typed marker for `", $id, "`.")]
            #[derive(Clone, Copy, Debug, Default)]
            pub struct $marker;

            impl sealed::Sealed for $marker {}

            impl TypedOperation for $marker {
                const OPERATION_ID: &'static str = $id;
                const REQUEST_SCHEMA: &'static str = $request_schema;
                const RESPONSE_SCHEMA: &'static str = $response_schema;
                const EVENT_SCHEMA: Option<&'static str> = $event_schema;
                type Request = $request;
                type Response = $response;
                type Event = $event;
            }
        )+

        /// Complete exact-45 frozen typed payload registry.
        pub const TYPED_OPERATION_MAPPINGS: &[TypedOperationMapping] = &[
            $(TypedOperationMapping {
                operation_id: $id,
                request_schema: $request_schema,
                response_schema: $response_schema,
                event_schema: $event_schema,
            }),+
        ];

        const TYPED_OPERATION_SCHEMA_FACTORIES: &[TypedOperationSchemaFactory] = &[
            $(TypedOperationSchemaFactory {
                operation_id: $id,
                request_schema: $request_schema,
                response_schema: $response_schema,
                event_schema: $event_schema,
                request: payload_schema::<$request>,
                response: payload_schema::<$response>,
                event: payload_schema::<$event>,
            }),+
        ];
    };
}

define_typed_operations! {
    DiscoverSourcesOperation => ("discoverSources", DiscoverSourcesRequest, "DiscoverSourcesRequest", DiscoveryPlanResponse, "DiscoveryPlanResponse", NoEvent, None),
    IngestCatalogOperation => ("ingestCatalog", IngestCatalogRequest, "IngestCatalogRequest", IngestionReceiptResponse, "IngestionReceiptResponse", NoEvent, None),
    GetSourceStatusOperation => ("getSourceStatus", SourceIdRequest, "SourceIdRequest", SourceStatusResponse, "SourceStatusResponse", NoEvent, None),
    QueryCatalogOperation => ("queryCatalog", QueryCatalogRequest, "QueryCatalogRequest", CatalogQueryResponse, "CatalogQueryResponse", NoEvent, None),
    BatchAtomsOperation => ("batchAtoms", BatchAtomsRequest, "BatchAtomsRequest", AtomBatchResponse, "AtomBatchResponse", NoEvent, None),
    TombstoneAtomOperation => ("tombstoneAtom", AtomIdRequest, "AtomIdRequest", MutationReceipt, "MutationReceipt", NoEvent, None),
    CreateContextPlanOperation => ("createContextPlan", CreateContextPlanRequest, "CreateContextPlanRequest", ContextPlanResponse, "ContextPlanResponse", NoEvent, None),
    CompileContextBundleOperation => ("compileContextBundle", CompileContextBundleRequest, "CompileContextBundleRequest", ContextBundle, "ContextBundle", NoEvent, None),
    CompileContextDeltaOperation => ("compileContextDelta", CompileContextDeltaRequest, "CompileContextDeltaRequest", ContextDeltaResponse, "ContextDeltaResponse", NoEvent, None),
    GetContextBundleOperation => ("getContextBundle", BundleIdRequest, "BundleIdRequest", ContextBundle, "ContextBundle", NoEvent, None),
    GetContextBundleManifestOperation => ("getContextBundleManifest", BundleIdRequest, "BundleIdRequest", SelectionManifest, "SelectionManifest", NoEvent, None),
    ExplainContextBundleOperation => ("explainContextBundle", ExplainContextBundleRequest, "ExplainContextBundleRequest", ContextExplanationResponse, "ContextExplanationResponse", NoEvent, None),
    MaterializeContextBundleOperation => ("materializeContextBundle", MaterializeContextBundleRequest, "MaterializeContextBundleRequest", MaterializationResponse, "MaterializationResponse", NoEvent, None),
    RevalidateContextBundleOperation => ("revalidateContextBundle", BundleIdRequest, "BundleIdRequest", RevalidationResponse, "RevalidationResponse", NoEvent, None),
    CreateSpaceOperation => ("createSpace", CreateSpaceRequest, "CreateSpaceRequest", ContextCommit, "ContextCommit", NoEvent, None),
    ForkSpaceOperation => ("forkSpace", ForkSpaceRequest, "ForkSpaceRequest", SpaceForkResponse, "SpaceForkResponse", NoEvent, None),
    PublishSpaceOperation => ("publishSpace", PublishSpaceRequest, "PublishSpaceRequest", SpacePublishResponse, "SpacePublishResponse", NoEvent, None),
    GetSpaceLogOperation => ("getSpaceLog", SpaceIdRequest, "SpaceIdRequest", SpaceLogResponse, "SpaceLogResponse", NoEvent, None),
    SubscribeSpaceEventsOperation => ("subscribeSpaceEvents", SpaceIdRequest, "SpaceIdRequest", StreamOpenResponse, "StreamOpenResponse", SpaceEventPayload, Some("SpaceEventPayload")),
    CreateSpaceCheckpointOperation => ("createSpaceCheckpoint", CheckpointSpaceRequest, "CheckpointSpaceRequest", SpaceCheckpointResponse, "SpaceCheckpointResponse", NoEvent, None),
    ListSpaceConflictsOperation => ("listSpaceConflicts", SpaceIdRequest, "SpaceIdRequest", ConflictListResponse, "ConflictListResponse", NoEvent, None),
    ResolveSpaceConflictOperation => ("resolveSpaceConflict", ResolveSpaceConflictRequest, "ResolveSpaceConflictRequest", ConflictResolutionResponse, "ConflictResolutionResponse", NoEvent, None),
    CreateHandoffOperation => ("createHandoff", CreateHandoffRequest, "CreateHandoffRequest", CreateHandoffResponse, "CreateHandoffResponse", NoEvent, None),
    PreviewHandoffOperation => ("previewHandoff", HandoffIdRequest, "HandoffIdRequest", HandoffPreviewResponse, "HandoffPreviewResponse", NoEvent, None),
    AcceptHandoffOperation => ("acceptHandoff", AcceptHandoffRequest, "AcceptHandoffRequest", HandoffAcceptance, "HandoffAcceptance", NoEvent, None),
    RevokeHandoffOperation => ("revokeHandoff", RevokeHandoffRequest, "RevokeHandoffRequest", MutationReceipt, "MutationReceipt", NoEvent, None),
    RecordHandoffResultOperation => ("recordHandoffResult", RecordHandoffResultRequest, "RecordHandoffResultRequest", HandoffResultReceipt, "HandoffResultReceipt", NoEvent, None),
    MergeHandoffOperation => ("mergeHandoff", MergeHandoffRequest, "MergeHandoffRequest", HandoffMergeResponse, "HandoffMergeResponse", NoEvent, None),
    PrepareEffectOperation => ("prepareEffect", PrepareEffectRequest, "PrepareEffectRequest", EffectStatusResponse, "EffectStatusResponse", NoEvent, None),
    AuthorizeEffectOperation => ("authorizeEffect", AuthorizeEffectRequest, "AuthorizeEffectRequest", EffectStatusResponse, "EffectStatusResponse", NoEvent, None),
    DispatchEffectOperation => ("dispatchEffect", EffectIdRequest, "EffectIdRequest", EffectStatusResponse, "EffectStatusResponse", NoEvent, None),
    GetEffectStatusOperation => ("getEffectStatus", EffectIdRequest, "EffectIdRequest", EffectStatusResponse, "EffectStatusResponse", NoEvent, None),
    ReconcileEffectOperation => ("reconcileEffect", EffectIdRequest, "EffectIdRequest", EffectStatusResponse, "EffectStatusResponse", NoEvent, None),
    CompensateEffectOperation => ("compensateEffect", CompensateEffectRequest, "CompensateEffectRequest", EffectStatusResponse, "EffectStatusResponse", NoEvent, None),
    CreateReplayOperation => ("createReplay", CreateReplayRequest, "CreateReplayRequest", ReplayJobResponse, "ReplayJobResponse", NoEvent, None),
    RunObservationalReplayOperation => ("runObservationalReplay", ReplayIdRequest, "ReplayIdRequest", ReplayExecution, "ReplayExecution", NoEvent, None),
    CompareLiveReplayOperation => ("compareLiveReplay", CompareLiveReplayRequest, "CompareLiveReplayRequest", ReplayExecution, "ReplayExecution", NoEvent, None),
    GetReplayCompletenessOperation => ("getReplayCompleteness", ReplayIdRequest, "ReplayIdRequest", ReplayCompleteness, "ReplayCompleteness", NoEvent, None),
    GetLivenessOperation => ("getLiveness", EmptyRequest, "EmptyRequest", LivenessResponse, "LivenessResponse", NoEvent, None),
    GetReadinessOperation => ("getReadiness", EmptyRequest, "EmptyRequest", ReadinessResponse, "ReadinessResponse", NoEvent, None),
    GetVersionOperation => ("getVersion", EmptyRequest, "EmptyRequest", VersionResponse, "VersionResponse", NoEvent, None),
    GetCapabilitiesOperation => ("getCapabilities", EmptyRequest, "EmptyRequest", CapabilitiesResponse, "CapabilitiesResponse", NoEvent, None),
    GetConfigurationOperation => ("getConfiguration", EmptyRequest, "EmptyRequest", ConfigurationResponse, "ConfigurationResponse", NoEvent, None),
    GetDiagnosticsOperation => ("getDiagnostics", EmptyRequest, "EmptyRequest", DiagnosticsResponse, "DiagnosticsResponse", NoEvent, None),
    GetMetricsOperation => ("getMetrics", EmptyRequest, "EmptyRequest", MetricsResponse, "MetricsResponse", NoEvent, None),
}

/// Canonically encodes one semantically validated typed payload.
pub fn encode_operation_payload<T: OperationPayload>(
    payload: &T,
    maximum_bytes: usize,
) -> Result<Vec<u8>, TypedPayloadError> {
    payload.validate_payload()?;
    let json = serde_json::to_vec(payload).map_err(|_error| TypedPayloadError::InvalidPayload)?;
    let node = parse_strict_json(&json).map_err(|_error| TypedPayloadError::InvalidPayload)?;
    let encoded =
        to_deterministic_cbor(&node).map_err(|_error| TypedPayloadError::InvalidPayload)?;
    if encoded.len() > maximum_bytes {
        Err(TypedPayloadError::LimitExceeded)
    } else {
        Ok(encoded)
    }
}

/// Strictly decodes one canonical typed payload without path injection.
pub fn decode_operation_payload<T: OperationPayload>(
    encoded: &[u8],
    maximum_bytes: usize,
) -> Result<T, TypedPayloadError> {
    let node = decode_canonical_node(encoded, maximum_bytes)?;
    decode_node::<T>(&node, maximum_bytes)
}

fn decode_canonical_node(
    encoded: &[u8],
    maximum_bytes: usize,
) -> Result<CanonicalNode, TypedPayloadError> {
    if encoded.len() > maximum_bytes {
        return Err(TypedPayloadError::LimitExceeded);
    }
    if encoded.is_empty() {
        return Ok(CanonicalNode::Map(BTreeMap::new()));
    }
    from_deterministic_cbor(encoded).map_err(|_error| TypedPayloadError::InvalidPayload)
}

fn decode_node<T: OperationPayload>(
    node: &CanonicalNode,
    maximum_bytes: usize,
) -> Result<T, TypedPayloadError> {
    let normalized =
        to_normalized_json(node).map_err(|_error| TypedPayloadError::InvalidPayload)?;
    let payload: T =
        serde_json::from_slice(&normalized).map_err(|_error| TypedPayloadError::InvalidPayload)?;
    payload.validate_payload()?;
    let reencoded = encode_operation_payload(&payload, maximum_bytes)?;
    let expected =
        to_deterministic_cbor(node).map_err(|_error| TypedPayloadError::InvalidPayload)?;
    if reencoded != expected {
        return Err(TypedPayloadError::InvalidPayload);
    }
    Ok(payload)
}

/// Strictly decodes and reconciles a typed request with its frozen envelope and path bindings.
pub fn decode_typed_request<O: TypedOperation>(
    request: &RequestEnvelope,
) -> Result<O::Request, TypedPayloadError> {
    if request.operation_id().as_str() != O::OPERATION_ID {
        return Err(TypedPayloadError::WrongOperation);
    }
    let contract = operation_by_id(O::OPERATION_ID).ok_or(TypedPayloadError::WrongOperation)?;
    request
        .validate_contract(contract)
        .map_err(|_error| TypedPayloadError::InvalidPayload)?;
    let node = decode_canonical_node(request.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
    let CanonicalNode::Map(mut fields) = node else {
        return Err(TypedPayloadError::InvalidPayload);
    };
    for parameter in request.path_parameters() {
        match fields.get(parameter.name()) {
            Some(CanonicalNode::Text(value)) if value == parameter.value() => {}
            Some(_) => return Err(TypedPayloadError::PathMismatch),
            None => {
                fields.insert(
                    parameter.name().to_owned(),
                    CanonicalNode::Text(parameter.value().to_owned()),
                );
            }
        }
    }
    let merged = CanonicalNode::Map(fields);
    let payload = decode_node::<O::Request>(&merged, MAX_OPERATION_PAYLOAD_BYTES)?;
    let declared = payload.path_bindings();
    if declared.len() != request.path_parameters().len()
        || declared
            .iter()
            .zip(request.path_parameters())
            .any(|((name, value), actual)| *name != actual.name() || value != actual.value())
    {
        return Err(TypedPayloadError::PathMismatch);
    }
    Ok(payload)
}

/// Metadata retained outside operation-specific caller payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedRequestMetadata {
    dry_run: bool,
    idempotency_key: Option<String>,
    expected_revision: Option<String>,
    page_cursor: Option<String>,
    page_size: Option<u32>,
}

impl TypedRequestMetadata {
    fn from_envelope(request: &RequestEnvelope) -> Self {
        Self {
            dry_run: request.dry_run(),
            idempotency_key: request.idempotency_key().map(str::to_owned),
            expected_revision: request.expected_revision().map(str::to_owned),
            page_cursor: request.page_cursor().map(str::to_owned),
            page_size: request.page_size(),
        }
    }

    /// Returns governed preview intent without changing execution authority.
    #[must_use]
    pub const fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Returns the mutation idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    /// Returns the optimistic expected revision.
    #[must_use]
    pub fn expected_revision(&self) -> Option<&str> {
        self.expected_revision.as_deref()
    }

    /// Returns the opaque page/resume cursor.
    #[must_use]
    pub fn page_cursor(&self) -> Option<&str> {
        self.page_cursor.as_deref()
    }

    /// Returns the requested page size.
    #[must_use]
    pub const fn page_size(&self) -> Option<u32> {
        self.page_size
    }
}

/// Decoded operation request paired with transport metadata.
pub struct TypedRequest<T> {
    /// Operation-specific caller payload.
    pub payload: T,
    /// Governance-relevant envelope metadata.
    pub metadata: TypedRequestMetadata,
}

impl<T: fmt::Debug> fmt::Debug for TypedRequest<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedRequest")
            .field("payload", &self.payload)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Typed unary result with optional immutable response metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedResponse<T> {
    /// Operation-specific response payload.
    pub payload: T,
    /// Optional strong semantic ETag.
    pub semantic_etag: Option<String>,
    /// Optional opaque continuation cursor.
    pub next_page_cursor: Option<String>,
}

impl<T> TypedResponse<T> {
    /// Creates a response without optional transport metadata.
    #[must_use]
    pub const fn new(payload: T) -> Self {
        Self {
            payload,
            semantic_etag: None,
            next_page_cursor: None,
        }
    }
}

/// One typed server-stream event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedEvent<T> {
    /// Stable resumable event identity.
    pub event_id: String,
    /// Exact event payload.
    pub payload: T,
}

/// Boxed typed event stream produced by a typed stream service.
pub type TypedEventStream<T> =
    Pin<Box<dyn Stream<Item = Result<TypedEvent<T>, ApiError>> + Send + 'static>>;

/// Typed unary application boundary for one sealed operation marker.
pub trait TypedUnaryService<O: TypedOperation>: Send + Sync {
    /// Executes one decoded, semantically validated request.
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<O::Request>,
    ) -> ServiceFuture<'a, Result<TypedResponse<O::Response>, ApiError>>;
}

/// Typed server-stream application boundary for one sealed operation marker.
pub trait TypedStreamService<O: TypedOperation>: Send + Sync {
    /// Opens one decoded, bounded typed stream.
    fn subscribe_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<O::Request>,
    ) -> ServiceFuture<'a, Result<TypedEventStream<O::Event>, ApiError>>;
}

/// Erased unary handler that can only register under its marker's generated identity.
pub struct TypedUnaryAdapter<O, H> {
    handler: Arc<H>,
    errors: Arc<dyn FacadeErrorFactory>,
    operation: PhantomData<O>,
}

impl<O, H> TypedUnaryAdapter<O, H> {
    /// Wraps one typed application service with canonical envelope conversion.
    #[must_use]
    pub const fn new(handler: Arc<H>, errors: Arc<dyn FacadeErrorFactory>) -> Self {
        Self {
            handler,
            errors,
            operation: PhantomData,
        }
    }
}

impl<O, H> UnaryOperationHandler for TypedUnaryAdapter<O, H>
where
    O: TypedOperation,
    H: TypedUnaryService<O> + 'static,
{
    fn operation_id(&self) -> &'static str {
        O::OPERATION_ID
    }

    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        Box::pin(async move {
            let metadata = TypedRequestMetadata::from_envelope(&request);
            let payload = decode_typed_request::<O>(&request)
                .map_err(|failure| self.errors.public_error(failure.error_code()))?;
            let response = self
                .handler
                .call_typed(context, TypedRequest { payload, metadata })
                .await?;
            let encoded = encode_operation_payload(&response.payload, MAX_OPERATION_PAYLOAD_BYTES)
                .map_err(|_failure| {
                    self.errors
                        .public_error(cigar_protocol::ErrorCode::Internal)
                })?;
            ResponseEnvelope::new(
                O::OPERATION_ID,
                encoded,
                response.semantic_etag,
                response.next_page_cursor,
            )
            .map_err(|_error| {
                self.errors
                    .public_error(cigar_protocol::ErrorCode::Internal)
            })
        })
    }
}

impl<O, H> fmt::Debug for TypedUnaryAdapter<O, H>
where
    O: TypedOperation,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedUnaryAdapter")
            .field("operation_id", &O::OPERATION_ID)
            .finish_non_exhaustive()
    }
}

/// Erased stream handler that can only register under its marker's generated identity.
pub struct TypedStreamAdapter<O, H> {
    handler: Arc<H>,
    errors: Arc<dyn FacadeErrorFactory>,
    operation: PhantomData<O>,
}

impl<O, H> TypedStreamAdapter<O, H> {
    /// Wraps one typed stream service with canonical envelope conversion.
    #[must_use]
    pub const fn new(handler: Arc<H>, errors: Arc<dyn FacadeErrorFactory>) -> Self {
        Self {
            handler,
            errors,
            operation: PhantomData,
        }
    }
}

impl<O, H> StreamOperationHandler for TypedStreamAdapter<O, H>
where
    O: TypedOperation,
    H: TypedStreamService<O> + 'static,
{
    fn operation_id(&self) -> &'static str {
        O::OPERATION_ID
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        Box::pin(async move {
            let metadata = TypedRequestMetadata::from_envelope(&request);
            let payload = decode_typed_request::<O>(&request)
                .map_err(|failure| self.errors.public_error(failure.error_code()))?;
            let stream = self
                .handler
                .subscribe_typed(context, TypedRequest { payload, metadata })
                .await?;
            Ok(Box::pin(EncodedTypedEventStream::<O> {
                inner: stream,
                errors: Arc::clone(&self.errors),
                ended: false,
            }) as FacadeEventStream)
        })
    }
}

impl<O, H> fmt::Debug for TypedStreamAdapter<O, H>
where
    O: TypedOperation,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedStreamAdapter")
            .field("operation_id", &O::OPERATION_ID)
            .finish_non_exhaustive()
    }
}

struct EncodedTypedEventStream<O: TypedOperation> {
    inner: TypedEventStream<O::Event>,
    errors: Arc<dyn FacadeErrorFactory>,
    ended: bool,
}

impl<O: TypedOperation> Stream for EncodedTypedEventStream<O> {
    type Item = Result<EventEnvelope, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(event))) => {
                let encoded =
                    match encode_operation_payload(&event.payload, MAX_EVENT_PAYLOAD_BYTES) {
                        Ok(encoded) => encoded,
                        Err(_failure) => {
                            self.ended = true;
                            return Poll::Ready(Some(Err(self
                                .errors
                                .public_error(cigar_protocol::ErrorCode::Internal))));
                        }
                    };
                match EventEnvelope::new(O::OPERATION_ID, event.event_id, encoded) {
                    Ok(event) => Poll::Ready(Some(Ok(event))),
                    Err(_error) => {
                        self.ended = true;
                        Poll::Ready(Some(Err(self
                            .errors
                            .public_error(cigar_protocol::ErrorCode::Internal))))
                    }
                }
            }
            Poll::Ready(Some(Err(error))) => {
                self.ended = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Returns the frozen generated contract for a sealed typed marker.
#[must_use]
pub fn typed_operation_contract<O: TypedOperation>() -> Option<&'static OperationContract> {
    operation_by_id(O::OPERATION_ID)
}
