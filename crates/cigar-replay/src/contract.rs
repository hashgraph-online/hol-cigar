//! Bounded decision-archive records shared by capture and replay execution.

use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
use cigar_protocol::limits::{MAX_MATERIALIZED_BYTES, MAX_REPLAY_REFERENCES};
use cigar_protocol::{
    CandidateDisposition, ContentDigest, ContextBundle, ContextPlan, DecisionRecord,
    DependencyKind, EffectIntent, MediaType, RecordId, ReplayMode, SchemaVersion,
    SelectionManifest, UsageRecord, Validate, VerificationReceipt, VersionId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum exact bytes retained in one replay artifact.
pub const MAX_DECISION_ARTIFACT_BYTES: usize = MAX_MATERIALIZED_BYTES;
/// Maximum aggregate exact artifact bytes accepted by one capture operation.
pub const MAX_DECISION_CAPTURE_BYTES: usize = MAX_MATERIALIZED_BYTES * 4;

/// Stable content-free foundation failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayFoundationErrorCode {
    /// A record, binding, ordering, or schema invariant is invalid.
    InvalidInput,
    /// A configured collection or byte bound was exceeded.
    LimitExceeded,
    /// Exact bytes do not match their declared digest or semantic identity.
    IntegrityFailure,
    /// A requested archive or artifact is absent.
    NotFound,
    /// An immutable identity is already bound to different content.
    Collision,
    /// A lock or serialization boundary could not be used safely.
    Unavailable,
}

/// Content-free replay foundation error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplayFoundationError {
    code: ReplayFoundationErrorCode,
}

impl ReplayFoundationError {
    /// Creates one stable failure.
    #[must_use]
    pub const fn new(code: ReplayFoundationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ReplayFoundationErrorCode {
        self.code
    }
}

impl fmt::Debug for ReplayFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayFoundationError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ReplayFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "replay foundation operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for ReplayFoundationError {}

/// Exact semantic role played by one retained dependency.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRole {
    /// Observable task statement bytes.
    Task,
    /// Exact deterministic compilation plan.
    Plan,
    /// Exact selection manifest.
    Manifest,
    /// Exact semantic context bundle.
    Bundle,
    /// Provider-ready materialized bytes.
    Materialization,
    /// Exact consumer invocation envelope.
    Invocation,
    /// Exact invocation parameter bytes.
    InvocationParameters,
    /// Immutable source evidence.
    Source,
    /// Protected content blob.
    Blob,
    /// Exact policy snapshot.
    Policy,
    /// Exact index generation or watermark.
    Index,
    /// Tokenizer implementation identified by its fingerprint.
    Tokenizer,
    /// Materializer implementation identified by its fingerprint.
    Materializer,
    /// Provider adapter implementation identified by its fingerprint.
    Adapter,
    /// Consumer implementation identified by its fingerprint.
    Consumer,
    /// Runtime implementation identified by its fingerprint.
    Runtime,
    /// Tool schema used by the invocation.
    ToolSchema,
    /// Declared execution-environment component.
    Environment,
    /// Recorded consumer observation.
    ConsumerObservation,
    /// Recorded tool observation.
    ToolObservation,
    /// Recorded connector observation.
    ConnectorObservation,
    /// Recorded effect observation.
    EffectObservation,
    /// Output artifact retained by the decision.
    OutputArtifact,
    /// Asserted output claim.
    AssertedClaim,
    /// Evidence supporting an output or claim.
    Evidence,
    /// Explicit uncertainty retained by the decision.
    Uncertainty,
    /// Verification receipt retained by the decision.
    VerificationReceipt,
    /// Exact effect record retained by the decision.
    Effect,
}

/// Exact content-addressed dependency declared by a decision archive.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDependency {
    /// Protocol completeness category.
    pub kind: DependencyKind,
    /// Exact role within the decision.
    pub role: DependencyRole,
    /// SHA-256 multihash of the retained exact bytes.
    pub content_digest: ContentDigest,
    /// Semantic identity for a source or content-derived protocol record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_id: Option<VersionId>,
    /// Immutable record identity when the dependency is record-addressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<RecordId>,
    /// Component fingerprint, or index-generation fingerprint for an index dependency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<ContentDigest>,
    /// Replay modes for which absence makes execution incomplete.
    pub required_modes: BTreeSet<ReplayMode>,
}

impl DecisionDependency {
    /// Validates the role/category and identity requirements.
    pub fn validate(&self) -> Result<(), ReplayFoundationError> {
        if self.required_modes.is_empty()
            || !role_matches_kind(self.role, self.kind)
            || minimum_modes(self.role)
                .iter()
                .any(|mode| !self.required_modes.contains(mode))
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        let semantic_required = matches!(
            self.role,
            DependencyRole::Source
                | DependencyRole::Manifest
                | DependencyRole::Bundle
                | DependencyRole::OutputArtifact
                | DependencyRole::VerificationReceipt
        );
        let record_required = matches!(self.role, DependencyRole::Plan | DependencyRole::Effect);
        let fingerprint_required = matches!(
            self.role,
            DependencyRole::Tokenizer
                | DependencyRole::Materializer
                | DependencyRole::Adapter
                | DependencyRole::Consumer
                | DependencyRole::Runtime
                | DependencyRole::ToolSchema
                | DependencyRole::Environment
        );
        if semantic_required != self.semantic_id.is_some()
            || record_required != self.record_id.is_some()
            || (fingerprint_required && self.fingerprint.as_ref() != Some(&self.content_digest))
            || (self.role == DependencyRole::Index && self.fingerprint.is_none())
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        Ok(())
    }
}

fn minimum_modes(role: DependencyRole) -> &'static [ReplayMode] {
    const ALL: &[ReplayMode] = &[
        ReplayMode::EvidenceReproduction,
        ReplayMode::InvocationReproduction,
        ReplayMode::Observational,
        ReplayMode::LiveComparison,
    ];
    const INVOCATION: &[ReplayMode] = &[
        ReplayMode::InvocationReproduction,
        ReplayMode::Observational,
        ReplayMode::LiveComparison,
    ];
    const EVIDENCE_AND_COMPARISON: &[ReplayMode] = &[
        ReplayMode::EvidenceReproduction,
        ReplayMode::Observational,
        ReplayMode::LiveComparison,
    ];
    const OBSERVATION: &[ReplayMode] = &[ReplayMode::Observational, ReplayMode::LiveComparison];
    match role {
        DependencyRole::Task
        | DependencyRole::Plan
        | DependencyRole::Manifest
        | DependencyRole::Bundle
        | DependencyRole::Materialization => ALL,
        DependencyRole::Invocation
        | DependencyRole::InvocationParameters
        | DependencyRole::Tokenizer
        | DependencyRole::Materializer
        | DependencyRole::Adapter
        | DependencyRole::Consumer
        | DependencyRole::Runtime
        | DependencyRole::ToolSchema
        | DependencyRole::Environment => INVOCATION,
        DependencyRole::Source
        | DependencyRole::Policy
        | DependencyRole::Index
        | DependencyRole::OutputArtifact
        | DependencyRole::AssertedClaim
        | DependencyRole::Evidence
        | DependencyRole::Uncertainty
        | DependencyRole::VerificationReceipt
        | DependencyRole::Effect => EVIDENCE_AND_COMPARISON,
        DependencyRole::ConsumerObservation
        | DependencyRole::ToolObservation
        | DependencyRole::ConnectorObservation
        | DependencyRole::EffectObservation => OBSERVATION,
        DependencyRole::Blob => &[],
    }
}

fn role_matches_kind(role: DependencyRole, kind: DependencyKind) -> bool {
    match role {
        DependencyRole::Manifest => kind == DependencyKind::Manifest,
        DependencyRole::Bundle => kind == DependencyKind::Bundle,
        DependencyRole::Source => kind == DependencyKind::Source,
        DependencyRole::Policy => kind == DependencyKind::Policy,
        DependencyRole::Index => kind == DependencyKind::Index,
        DependencyRole::Tokenizer => kind == DependencyKind::Tokenizer,
        DependencyRole::Materializer | DependencyRole::Adapter => kind == DependencyKind::Adapter,
        DependencyRole::Consumer => kind == DependencyKind::Consumer,
        DependencyRole::Runtime | DependencyRole::Environment => {
            kind == DependencyKind::Environment
        }
        DependencyRole::ToolSchema => kind == DependencyKind::ToolSchema,
        DependencyRole::Task
        | DependencyRole::Plan
        | DependencyRole::Materialization
        | DependencyRole::Invocation
        | DependencyRole::InvocationParameters
        | DependencyRole::Blob
        | DependencyRole::ConsumerObservation
        | DependencyRole::ToolObservation
        | DependencyRole::ConnectorObservation
        | DependencyRole::EffectObservation
        | DependencyRole::OutputArtifact
        | DependencyRole::AssertedClaim
        | DependencyRole::Evidence
        | DependencyRole::Uncertainty
        | DependencyRole::VerificationReceipt
        | DependencyRole::Effect => kind == DependencyKind::Blob,
    }
}

/// Observable exact consumer invocation without hidden reasoning.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationEnvelope {
    /// Must be `cigar.invocation-envelope.v1`.
    pub schema_version: SchemaVersion,
    /// Digest of exact final consumer input bytes.
    pub input_digest: ContentDigest,
    /// Digest of exact materialized context bytes included in the invocation.
    pub materialization_digest: ContentDigest,
    /// Runtime implementation fingerprint.
    pub runtime_fingerprint: ContentDigest,
    /// Consumer implementation fingerprint.
    pub consumer_fingerprint: ContentDigest,
    /// Provider adapter implementation fingerprint.
    pub adapter_fingerprint: ContentDigest,
    /// Digest of exact declared parameter bytes.
    pub parameters_digest: ContentDigest,
    /// Sorted exact tool-schema fingerprints.
    pub tool_schema_digests: Vec<ContentDigest>,
    /// Sorted exact environment-component fingerprints.
    pub environment_digests: Vec<ContentDigest>,
    /// Sorted effect identities emitted by this decision.
    pub effect_ids: Vec<RecordId>,
    /// Exact observed usage bound into the decision.
    pub usage: UsageRecord,
}

impl fmt::Debug for InvocationEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationEnvelope")
            .field("schema_version", &self.schema_version)
            .field("input_digest", &self.input_digest)
            .field("materialization_digest", &self.materialization_digest)
            .field("runtime_fingerprint", &self.runtime_fingerprint)
            .field("consumer_fingerprint", &self.consumer_fingerprint)
            .field("adapter_fingerprint", &self.adapter_fingerprint)
            .field("tool_schema_count", &self.tool_schema_digests.len())
            .field("environment_count", &self.environment_digests.len())
            .field("effect_count", &self.effect_ids.len())
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

impl InvocationEnvelope {
    /// Validates schema and ordered bounded reference sets.
    pub fn validate(&self) -> Result<(), ReplayFoundationError> {
        if self
            .schema_version
            .require_v1("cigar.invocation-envelope")
            .is_err()
            || !bounded_sorted_unique(&self.tool_schema_digests)
            || !bounded_sorted_unique(&self.environment_digests)
            || !bounded_sorted_unique(&self.effect_ids)
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        Ok(())
    }
}

/// Closed observable provider boundary represented in a recorded transcript.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Consumer or model response.
    Consumer,
    /// Tool response.
    Tool,
    /// Connector response.
    Connector,
    /// Effect-kernel observation or receipt.
    Effect,
}

impl ObservationKind {
    /// Returns the dependency role used for retained response bytes.
    #[must_use]
    pub const fn dependency_role(self) -> DependencyRole {
        match self {
            Self::Consumer => DependencyRole::ConsumerObservation,
            Self::Tool => DependencyRole::ToolObservation,
            Self::Connector => DependencyRole::ConnectorObservation,
            Self::Effect => DependencyRole::EffectObservation,
        }
    }
}

/// One ordered request/response observation used without invoking its provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedObservation {
    /// Contiguous one-based observation ordinal.
    pub ordinal: u64,
    /// Boundary that produced the observation.
    pub kind: ObservationKind,
    /// Digest of the exact normalized request.
    pub request_digest: ContentDigest,
    /// Digest of exact retained response bytes.
    pub response_digest: ContentDigest,
    /// Exact implementation fingerprint that produced the response.
    pub provider_fingerprint: ContentDigest,
    /// Optional effect, attempt, or tool-call record identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<RecordId>,
}

/// Bounded dependency manifest sealed into a decision archive root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionArchiveManifest {
    /// Must be `cigar.decision-archive-manifest.v1`.
    pub schema_version: SchemaVersion,
    /// Sorted unique exact dependencies.
    pub dependencies: Vec<DecisionDependency>,
    /// Exact invocation description.
    pub invocation: InvocationEnvelope,
    /// Contiguous ordered observations.
    pub observations: Vec<RecordedObservation>,
}

impl DecisionArchiveManifest {
    /// Validates deterministic ordering, bounds, and exact transcript references.
    pub fn validate(&self) -> Result<(), ReplayFoundationError> {
        if self
            .schema_version
            .require_v1("cigar.decision-archive-manifest")
            .is_err()
            || self.dependencies.is_empty()
            || self.dependencies.len() > MAX_REPLAY_REFERENCES
            || !strictly_sorted_unique(&self.dependencies)
            || self.observations.len() > MAX_REPLAY_REFERENCES
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        self.invocation.validate()?;
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        let mut role_digests = BTreeSet::new();
        let mut singletons = BTreeSet::new();
        for dependency in &self.dependencies {
            if !role_digests.insert((dependency.role, dependency.content_digest.clone()))
                || (singleton_role(dependency.role) && !singletons.insert(dependency.role))
            {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::InvalidInput,
                ));
            }
        }
        let observation_dependencies: BTreeSet<_> = self
            .dependencies
            .iter()
            .filter_map(|dependency| {
                role_observation_kind(dependency.role).and_then(|kind| {
                    dependency.fingerprint.as_ref().map(|fingerprint| {
                        (kind, dependency.content_digest.clone(), fingerprint.clone())
                    })
                })
            })
            .collect();
        let mut declared_observations = BTreeSet::new();
        for (index, observation) in self.observations.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    ReplayFoundationError::new(ReplayFoundationErrorCode::LimitExceeded)
                })?;
            let identity = (
                observation.kind,
                observation.response_digest.clone(),
                observation.provider_fingerprint.clone(),
            );
            if observation.ordinal != expected || !observation_dependencies.contains(&identity) {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::InvalidInput,
                ));
            }
            declared_observations.insert(identity);
        }
        if observation_dependencies != declared_observations {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        Ok(())
    }
}

fn singleton_role(role: DependencyRole) -> bool {
    matches!(
        role,
        DependencyRole::Task
            | DependencyRole::Plan
            | DependencyRole::Manifest
            | DependencyRole::Bundle
            | DependencyRole::Materialization
            | DependencyRole::Invocation
            | DependencyRole::InvocationParameters
            | DependencyRole::Tokenizer
            | DependencyRole::Materializer
            | DependencyRole::Adapter
            | DependencyRole::Consumer
            | DependencyRole::Runtime
            | DependencyRole::Policy
            | DependencyRole::Index
    )
}

fn role_observation_kind(role: DependencyRole) -> Option<ObservationKind> {
    match role {
        DependencyRole::ConsumerObservation => Some(ObservationKind::Consumer),
        DependencyRole::ToolObservation => Some(ObservationKind::Tool),
        DependencyRole::ConnectorObservation => Some(ObservationKind::Connector),
        DependencyRole::EffectObservation => Some(ObservationKind::Effect),
        _ => None,
    }
}

/// Content-addressed decision root and its exact replay dependency manifest.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionArchive {
    /// Observable protocol decision record.
    pub decision: DecisionRecord,
    /// Exact dependency and observation manifest.
    pub manifest: DecisionArchiveManifest,
}

impl DecisionArchive {
    /// Validates protocol fields and the self-ID-excluding content-addressed root.
    pub fn validate(&self) -> Result<(), ReplayFoundationError> {
        self.decision.validate().map_err(|_error| {
            ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput)
        })?;
        self.manifest.validate()?;
        validate_archive_bindings(&self.decision, &self.manifest)?;
        if crate::digest::archive_version_id(self)? != self.decision.decision_id {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::IntegrityFailure,
            ));
        }
        Ok(())
    }
}

fn validate_archive_bindings(
    decision: &DecisionRecord,
    manifest: &DecisionArchiveManifest,
) -> Result<(), ReplayFoundationError> {
    let dependencies = &manifest.dependencies;
    let one = |role| -> Result<&DecisionDependency, ReplayFoundationError> {
        let mut found = dependencies
            .iter()
            .filter(|dependency| dependency.role == role);
        let value = found
            .next()
            .ok_or_else(|| ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput))?;
        if found.next().is_some() {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        Ok(value)
    };
    if one(DependencyRole::Task)?.content_digest != decision.task_digest
        || one(DependencyRole::Plan)?.content_digest != decision.plan_digest
        || one(DependencyRole::Plan)?.record_id.as_ref() != Some(&decision.plan_id)
        || one(DependencyRole::Bundle)?.semantic_id.as_ref() != Some(&decision.bundle_id)
        || one(DependencyRole::Materialization)?.content_digest != decision.materialization_digest
        || one(DependencyRole::Invocation)?.content_digest != manifest.invocation.input_digest
        || one(DependencyRole::InvocationParameters)?.content_digest
            != manifest.invocation.parameters_digest
        || one(DependencyRole::Runtime)?.fingerprint.as_ref() != Some(&decision.runtime_fingerprint)
        || one(DependencyRole::Consumer)?.fingerprint.as_ref()
            != Some(&decision.consumer_fingerprint)
        || one(DependencyRole::Adapter)?.fingerprint.as_ref()
            != Some(&manifest.invocation.adapter_fingerprint)
        || manifest.invocation.materialization_digest != decision.materialization_digest
        || manifest.invocation.runtime_fingerprint != decision.runtime_fingerprint
        || manifest.invocation.consumer_fingerprint != decision.consumer_fingerprint
        || manifest.invocation.effect_ids != decision.effects
        || manifest.invocation.usage != decision.usage
    {
        return Err(ReplayFoundationError::new(
            ReplayFoundationErrorCode::InvalidInput,
        ));
    }
    // These component identities have no direct protocol field on DecisionRecord, but their
    // singleton exact references are required for invocation and materialization reproduction.
    one(DependencyRole::Manifest)?;
    one(DependencyRole::Tokenizer)?;
    one(DependencyRole::Materializer)?;
    one(DependencyRole::Policy)?;
    one(DependencyRole::Index)?;

    let semantic_ids = |role| {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .filter_map(|dependency| dependency.semantic_id.clone())
            .collect();
        values.sort();
        values
    };
    let content_digests = |role| {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .map(|dependency| dependency.content_digest.clone())
            .collect();
        values.sort();
        values
    };
    let record_ids = |role| {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .filter_map(|dependency| dependency.record_id.clone())
            .collect();
        values.sort();
        values
    };
    let fingerprints = |role| {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .filter_map(|dependency| dependency.fingerprint.clone())
            .collect();
        values.sort();
        values
    };
    if semantic_ids(DependencyRole::OutputArtifact) != decision.output_artifacts
        || content_digests(DependencyRole::AssertedClaim) != decision.asserted_claims
        || content_digests(DependencyRole::Evidence) != decision.evidence
        || content_digests(DependencyRole::Uncertainty) != decision.uncertainty
        || semantic_ids(DependencyRole::VerificationReceipt) != decision.verification_receipts
        || record_ids(DependencyRole::Effect) != decision.effects
        || fingerprints(DependencyRole::ToolSchema) != manifest.invocation.tool_schema_digests
        || fingerprints(DependencyRole::Environment) != manifest.invocation.environment_digests
    {
        return Err(ReplayFoundationError::new(
            ReplayFoundationErrorCode::InvalidInput,
        ));
    }
    Ok(())
}

impl fmt::Debug for DecisionArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionArchive")
            .field("decision", &self.decision)
            .field("dependency_count", &self.manifest.dependencies.len())
            .field("observation_count", &self.manifest.observations.len())
            .finish_non_exhaustive()
    }
}

/// Exact protected artifact bytes addressed by their raw content digest.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionArtifact {
    /// Must be `cigar.decision-artifact.v1`.
    pub schema_version: SchemaVersion,
    /// Exact SHA-256 multihash of `bytes`.
    pub content_digest: ContentDigest,
    /// Declared protected content media type.
    pub media_type: MediaType,
    /// Exact retained bytes.
    pub(crate) bytes: Vec<u8>,
}

impl DecisionArtifact {
    /// Creates and hashes one bounded exact artifact.
    pub fn new(media_type: MediaType, bytes: Vec<u8>) -> Result<Self, ReplayFoundationError> {
        if bytes.len() > MAX_DECISION_ARTIFACT_BYTES {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::LimitExceeded,
            ));
        }
        let content_digest = crate::digest::raw_content_digest(&bytes)?;
        Ok(Self {
            schema_version: SchemaVersion::new("cigar.decision-artifact", 1).map_err(|_error| {
                ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput)
            })?,
            content_digest,
            media_type,
            bytes,
        })
    }

    /// Returns exact protected bytes to an authorized replay caller.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Validates schema, byte bounds, and exact digest binding.
    pub fn validate(&self) -> Result<(), ReplayFoundationError> {
        if self
            .schema_version
            .require_v1("cigar.decision-artifact")
            .is_err()
            || self.bytes.len() > MAX_DECISION_ARTIFACT_BYTES
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        if crate::digest::raw_content_digest(&self.bytes)? != self.content_digest {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::IntegrityFailure,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for DecisionArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionArtifact")
            .field("schema_version", &self.schema_version)
            .field("content_digest", &self.content_digest)
            .field("media_type", &self.media_type)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// One sealed archive plus exact artifacts captured in the same operation.
#[derive(Clone, Eq, PartialEq)]
pub struct DecisionCapture {
    /// Content-addressed root.
    pub archive: DecisionArchive,
    /// Sorted unique exact artifacts available at capture time.
    pub artifacts: Vec<DecisionArtifact>,
}

impl DecisionCapture {
    /// Validates archive integrity and every supplied artifact binding.
    pub fn validate(&self) -> Result<(), ReplayFoundationError> {
        self.archive.validate()?;
        if self.artifacts.len() > MAX_REPLAY_REFERENCES
            || !strictly_sorted_unique_by(&self.artifacts, |artifact| &artifact.content_digest)
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
        let mut aggregate = 0_usize;
        for artifact in &self.artifacts {
            artifact.validate()?;
            aggregate = aggregate.checked_add(artifact.bytes.len()).ok_or_else(|| {
                ReplayFoundationError::new(ReplayFoundationErrorCode::LimitExceeded)
            })?;
            if aggregate > MAX_DECISION_CAPTURE_BYTES {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::LimitExceeded,
                ));
            }
            if !self
                .archive
                .manifest
                .dependencies
                .iter()
                .any(|dependency| dependency.content_digest == artifact.content_digest)
            {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::InvalidInput,
                ));
            }
        }
        if self.archive.manifest.dependencies.iter().any(|dependency| {
            !self
                .artifacts
                .iter()
                .any(|artifact| artifact.content_digest == dependency.content_digest)
        }) {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::IntegrityFailure,
            ));
        }
        validate_typed_artifacts(&self.archive, &self.artifacts)?;
        Ok(())
    }
}

fn validate_typed_artifacts(
    archive: &DecisionArchive,
    artifacts: &[DecisionArtifact],
) -> Result<(), ReplayFoundationError> {
    let artifact = |role| -> Result<&DecisionArtifact, ReplayFoundationError> {
        let dependency = archive
            .manifest
            .dependencies
            .iter()
            .find(|dependency| dependency.role == role)
            .ok_or_else(|| ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput))?;
        artifacts
            .binary_search_by(|candidate| candidate.content_digest.cmp(&dependency.content_digest))
            .ok()
            .and_then(|index| artifacts.get(index))
            .ok_or_else(|| ReplayFoundationError::new(ReplayFoundationErrorCode::IntegrityFailure))
    };
    for dependency in archive.manifest.dependencies.iter().filter(|dependency| {
        matches!(
            dependency.role,
            DependencyRole::Task
                | DependencyRole::Materialization
                | DependencyRole::Invocation
                | DependencyRole::Source
                | DependencyRole::Policy
                | DependencyRole::Index
                | DependencyRole::Tokenizer
                | DependencyRole::Materializer
                | DependencyRole::Adapter
                | DependencyRole::Consumer
                | DependencyRole::Runtime
                | DependencyRole::ToolSchema
                | DependencyRole::Environment
        )
    }) {
        let exact = artifacts
            .binary_search_by(|candidate| candidate.content_digest.cmp(&dependency.content_digest))
            .ok()
            .and_then(|index| artifacts.get(index))
            .ok_or_else(integrity_foundation)?;
        if exact.bytes.is_empty() {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::InvalidInput,
            ));
        }
    }

    let plan: ContextPlan = canonical_typed(artifact(DependencyRole::Plan)?)?;
    plan.validate().map_err(|_error| invalid_foundation())?;
    let manifest: SelectionManifest = canonical_typed(artifact(DependencyRole::Manifest)?)?;
    manifest.validate().map_err(|_error| invalid_foundation())?;
    let bundle: ContextBundle = canonical_typed(artifact(DependencyRole::Bundle)?)?;
    bundle.validate().map_err(|_error| invalid_foundation())?;
    let manifest_dependency = archive
        .manifest
        .dependencies
        .iter()
        .find(|dependency| dependency.role == DependencyRole::Manifest)
        .ok_or_else(invalid_foundation)?;
    let bundle_dependency = archive
        .manifest
        .dependencies
        .iter()
        .find(|dependency| dependency.role == DependencyRole::Bundle)
        .ok_or_else(invalid_foundation)?;
    if plan.plan_id != archive.decision.plan_id
        || plan.contract_digest != manifest.contract_digest
        || plan.contract_digest != bundle.contract_digest
        || manifest_dependency.semantic_id.as_ref() != Some(&manifest.manifest_id)
        || bundle_dependency.semantic_id.as_ref() != Some(&bundle.bundle_id)
        || bundle.bundle_id != archive.decision.bundle_id
        || bundle.manifest_digest.as_str() != manifest.manifest_id.as_str()
        || semantic_multihash_v1(SemanticEnvelopeProfile::Manifest, &manifest)
            .map_err(|_error| integrity_foundation())?
            != manifest.manifest_id.as_str()
        || semantic_multihash_v1(SemanticEnvelopeProfile::Bundle, &bundle)
            .map_err(|_error| integrity_foundation())?
            != bundle.bundle_id.as_str()
    {
        return Err(integrity_foundation());
    }

    let selected_sources: BTreeSet<_> = manifest
        .entries
        .iter()
        .filter(|entry| matches!(&entry.disposition, CandidateDisposition::Selected { .. }))
        .map(|entry| entry.version_id.clone())
        .collect();
    let bundle_sources: BTreeSet<_> = bundle
        .blocks
        .iter()
        .flat_map(|block| block.provenance.iter().cloned())
        .collect();
    let archived_sources: BTreeSet<_> = archive
        .manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.role == DependencyRole::Source)
        .filter_map(|dependency| dependency.semantic_id.clone())
        .collect();
    let index = archive
        .manifest
        .dependencies
        .iter()
        .find(|dependency| dependency.role == DependencyRole::Index)
        .ok_or_else(invalid_foundation)?;
    if selected_sources != bundle_sources
        || bundle_sources != archived_sources
        || index.fingerprint.as_ref() != Some(&plan.catalog_watermark)
    {
        return Err(integrity_foundation());
    }

    for dependency in archive
        .manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.role == DependencyRole::OutputArtifact)
    {
        if dependency.semantic_id.as_ref().map(VersionId::as_str)
            != Some(dependency.content_digest.as_str())
        {
            return Err(integrity_foundation());
        }
    }

    for dependency in archive
        .manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.role == DependencyRole::Effect)
    {
        let effect_artifact = artifacts
            .binary_search_by(|candidate| candidate.content_digest.cmp(&dependency.content_digest))
            .ok()
            .and_then(|index| artifacts.get(index))
            .ok_or_else(integrity_foundation)?;
        let intent: EffectIntent = canonical_typed(effect_artifact)?;
        intent.validate().map_err(|_error| invalid_foundation())?;
        if dependency.record_id.as_ref() != Some(&intent.effect_id)
            || intent.bundle_id != archive.decision.bundle_id
        {
            return Err(integrity_foundation());
        }
    }

    for dependency in archive
        .manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.role == DependencyRole::VerificationReceipt)
    {
        let receipt_artifact = artifacts
            .binary_search_by(|candidate| candidate.content_digest.cmp(&dependency.content_digest))
            .ok()
            .and_then(|index| artifacts.get(index))
            .ok_or_else(integrity_foundation)?;
        let receipt: VerificationReceipt = canonical_typed(receipt_artifact)?;
        receipt.validate().map_err(|_error| invalid_foundation())?;
        if dependency.semantic_id.as_ref() != Some(&receipt.receipt_id)
            || semantic_multihash_v1(SemanticEnvelopeProfile::Receipt, &receipt)
                .map_err(|_error| integrity_foundation())?
                != receipt.receipt_id.as_str()
        {
            return Err(integrity_foundation());
        }
    }
    Ok(())
}

fn canonical_typed<T>(artifact: &DecisionArtifact) -> Result<T, ReplayFoundationError>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice(&artifact.bytes).map_err(|_error| invalid_foundation())?;
    if crate::digest::canonical_record_bytes(&value)? != artifact.bytes {
        return Err(integrity_foundation());
    }
    Ok(value)
}

fn invalid_foundation() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput)
}

fn integrity_foundation() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::IntegrityFailure)
}

impl fmt::Debug for DecisionCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionCapture")
            .field("archive", &self.archive)
            .field("artifact_count", &self.artifacts.len())
            .field(
                "artifact_bytes",
                &self
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.bytes.len())
                    .sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

/// Reason one exact dependency cannot currently be reproduced.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingDependencyReason {
    /// No retained artifact exists for the exact digest.
    Missing,
    /// Retained bytes fail their exact content digest.
    DigestMismatch,
    /// Retained semantic record does not match its declared semantic identity.
    SemanticMismatch,
    /// The exact component exists but this runtime cannot reproduce it.
    Unsupported,
}

/// Internal detailed missing-dependency row; public protocol output remains category-only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MissingDependencyRow {
    /// Missing dependency category.
    pub kind: DependencyKind,
    /// Exact missing role.
    pub role: DependencyRole,
    /// Exact requested content digest.
    pub content_digest: ContentDigest,
    /// Replay mode that required the dependency.
    pub required_mode: ReplayMode,
    /// Stable reason exact reproduction is unavailable.
    pub reason: MissingDependencyReason,
}

fn bounded_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REPLAY_REFERENCES && strictly_sorted_unique(values)
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| {
        window
            .first()
            .zip(window.get(1))
            .is_some_and(|(first, second)| first < second)
    })
}

fn strictly_sorted_unique_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|window| {
        window
            .first()
            .zip(window.get(1))
            .is_some_and(|(first, second)| key(first) < key(second))
    })
}

#[cfg(test)]
mod tests {
    use super::{DecisionArtifact, MAX_DECISION_ARTIFACT_BYTES, ReplayFoundationErrorCode};
    use cigar_protocol::MediaType;

    #[test]
    fn artifact_is_bounded_and_debug_redacts_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = DecisionArtifact::new(
            MediaType::new("application/octet-stream")?,
            b"protected replay bytes".to_vec(),
        )?;
        artifact.validate()?;
        let rendered = format!("{artifact:?}");
        assert!(rendered.contains("byte_count"));
        assert!(!rendered.contains("protected replay bytes"));

        let empty = DecisionArtifact::new(MediaType::new("application/octet-stream")?, Vec::new())?;
        empty.validate()?;
        assert!(empty.bytes().is_empty());

        let result = DecisionArtifact::new(
            MediaType::new("application/octet-stream")?,
            vec![0; MAX_DECISION_ARTIFACT_BYTES + 1],
        );
        let Err(error) = result else {
            return Err("oversized artifact unexpectedly passed".into());
        };
        assert_eq!(error.code(), ReplayFoundationErrorCode::LimitExceeded);
        Ok(())
    }
}
