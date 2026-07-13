//! Observable decision capture and strict cross-record sealing.

use crate::contract::{
    DecisionArchive, DecisionArchiveManifest, DecisionArtifact, DecisionCapture,
    DecisionDependency, DependencyRole, InvocationEnvelope, ObservationKind, RecordedObservation,
    ReplayFoundationError, ReplayFoundationErrorCode,
};
use crate::digest::{archive_version_id, canonical_record_bytes, raw_content_digest};
use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
use cigar_protocol::{
    ContentDigest, ContextBundle, ContextPlan, DecisionRecord, DependencyKind, MaterializedContext,
    MediaType, RecordId, ReplayMode, SchemaVersion, SelectionManifest, Validate,
    VerificationReceipt, VersionId,
};
use std::collections::BTreeSet;
use std::fmt;

/// Exact invocation bytes paired with their observable metadata envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct InvocationCapture {
    /// Observable invocation metadata.
    pub envelope: InvocationEnvelope,
    input_bytes: Vec<u8>,
    parameter_bytes: Vec<u8>,
}

impl InvocationCapture {
    /// Creates one exact invocation capture. Final input must be non-empty.
    pub fn new(
        envelope: InvocationEnvelope,
        input_bytes: Vec<u8>,
        parameter_bytes: Vec<u8>,
    ) -> Result<Self, ReplayFoundationError> {
        if input_bytes.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            envelope,
            input_bytes,
            parameter_bytes,
        })
    }
}

impl fmt::Debug for InvocationCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationCapture")
            .field("envelope", &self.envelope)
            .field("input_bytes", &self.input_bytes.len())
            .field("parameter_bytes", &self.parameter_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Exact recorded response paired with its request and provider metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservationCapture {
    /// Ordered observable transcript metadata.
    pub observation: RecordedObservation,
    response_bytes: Vec<u8>,
}

impl ObservationCapture {
    /// Creates one response capture. Empty exact responses remain representable.
    #[must_use]
    pub fn new(observation: RecordedObservation, response_bytes: Vec<u8>) -> Self {
        Self {
            observation,
            response_bytes,
        }
    }
}

impl fmt::Debug for ObservationCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservationCapture")
            .field("observation", &self.observation)
            .field("response_bytes", &self.response_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Caller-supplied exact dependency and its retained bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct DependencyCapture {
    /// Exact role, identities, fingerprint, and mode requirements.
    pub dependency: DecisionDependency,
    /// Exact protected artifact.
    pub artifact: DecisionArtifact,
}

impl DependencyCapture {
    /// Validates and pairs one dependency with bytes having its exact digest.
    pub fn new(
        dependency: DecisionDependency,
        artifact: DecisionArtifact,
    ) -> Result<Self, ReplayFoundationError> {
        dependency.validate()?;
        artifact.validate()?;
        if dependency.content_digest != artifact.content_digest
            || (is_component_role(dependency.role)
                && dependency.fingerprint.as_ref() != Some(&artifact.content_digest))
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::IntegrityFailure,
            ));
        }
        Ok(Self {
            dependency,
            artifact,
        })
    }
}

impl fmt::Debug for DependencyCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DependencyCapture")
            .field("dependency", &self.dependency)
            .field("artifact", &self.artifact)
            .finish()
    }
}

/// Builder that seals one observable decision and exact replay archive.
pub struct DecisionCaptureBuilder {
    decision: DecisionRecord,
    task_bytes: Vec<u8>,
    plan: ContextPlan,
    manifest: SelectionManifest,
    bundle: ContextBundle,
    materialization: MaterializedContext,
    invocation: InvocationCapture,
    observations: Vec<ObservationCapture>,
    verification_receipts: Vec<VerificationReceipt>,
    dependencies: Vec<DependencyCapture>,
}

impl fmt::Debug for DecisionCaptureBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionCaptureBuilder")
            .field("decision", &self.decision)
            .field("task_bytes", &self.task_bytes.len())
            .field("plan_id", &self.plan.plan_id)
            .field("manifest_id", &self.manifest.manifest_id)
            .field("bundle_id", &self.bundle.bundle_id)
            .field("materialization_bytes", &self.materialization.bytes.len())
            .field("invocation", &self.invocation)
            .field("observation_count", &self.observations.len())
            .field("verification_count", &self.verification_receipts.len())
            .field("additional_dependency_count", &self.dependencies.len())
            .finish_non_exhaustive()
    }
}

impl DecisionCaptureBuilder {
    /// Starts a capture with every required observable compilation and invocation record.
    #[must_use]
    pub fn new(
        decision: DecisionRecord,
        task_bytes: Vec<u8>,
        plan: ContextPlan,
        manifest: SelectionManifest,
        bundle: ContextBundle,
        materialization: MaterializedContext,
        invocation: InvocationCapture,
    ) -> Self {
        Self {
            decision,
            task_bytes,
            plan,
            manifest,
            bundle,
            materialization,
            invocation,
            observations: Vec::new(),
            verification_receipts: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// Replaces the ordered recorded-observation transcript.
    #[must_use]
    pub fn with_observations(mut self, observations: Vec<ObservationCapture>) -> Self {
        self.observations = observations;
        self
    }

    /// Replaces exact verification receipts retained by the decision.
    #[must_use]
    pub fn with_verification_receipts(
        mut self,
        verification_receipts: Vec<VerificationReceipt>,
    ) -> Self {
        self.verification_receipts = verification_receipts;
        self
    }

    /// Adds one exact source, component, output, claim, evidence, uncertainty, or effect record.
    #[must_use]
    pub fn with_dependency(mut self, dependency: DependencyCapture) -> Self {
        self.dependencies.push(dependency);
        self
    }

    /// Validates all cross-record bindings and derives the content-addressed decision root.
    pub fn seal(self) -> Result<DecisionCapture, ReplayFoundationError> {
        self.validate_protocol_records()?;
        self.validate_compilation_bindings()?;
        self.invocation.envelope.validate()?;
        self.validate_invocation_bindings()?;
        self.validate_observations()?;
        self.validate_verification_receipts()?;

        let all_modes = modes(&[
            ReplayMode::EvidenceReproduction,
            ReplayMode::InvocationReproduction,
            ReplayMode::Observational,
            ReplayMode::LiveComparison,
        ]);
        let invocation_modes = modes(&[
            ReplayMode::InvocationReproduction,
            ReplayMode::Observational,
            ReplayMode::LiveComparison,
        ]);
        let observation_modes = modes(&[ReplayMode::Observational, ReplayMode::LiveComparison]);
        let observation_records: Vec<_> = self
            .observations
            .iter()
            .map(|capture| capture.observation.clone())
            .collect();
        let tokenizer_fingerprint = self.materialization.tokenizer_fingerprint.clone();
        let materializer_fingerprint = self.materialization.materializer_fingerprint.clone();

        let mut artifacts = Vec::new();
        let mut dependencies = Vec::new();
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            MediaType::new("text/plain").map_err(|_error| invalid())?,
            self.task_bytes,
            DependencyKind::Blob,
            DependencyRole::Task,
            None,
            None,
            None,
            all_modes.clone(),
        )?;

        let plan_bytes = canonical_record_bytes(&self.plan)?;
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            json_media_type()?,
            plan_bytes,
            DependencyKind::Blob,
            DependencyRole::Plan,
            None,
            Some(self.plan.plan_id.clone()),
            None,
            all_modes.clone(),
        )?;
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            json_media_type()?,
            canonical_record_bytes(&self.manifest)?,
            DependencyKind::Manifest,
            DependencyRole::Manifest,
            Some(self.manifest.manifest_id.clone()),
            None,
            None,
            all_modes.clone(),
        )?;
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            json_media_type()?,
            canonical_record_bytes(&self.bundle)?,
            DependencyKind::Bundle,
            DependencyRole::Bundle,
            Some(self.bundle.bundle_id.clone()),
            None,
            None,
            all_modes.clone(),
        )?;
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            self.materialization.media_type.clone(),
            self.materialization.bytes,
            DependencyKind::Blob,
            DependencyRole::Materialization,
            None,
            None,
            None,
            all_modes,
        )?;
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            octet_stream_media_type()?,
            self.invocation.input_bytes,
            DependencyKind::Blob,
            DependencyRole::Invocation,
            None,
            None,
            None,
            invocation_modes.clone(),
        )?;
        add_artifact_dependency(
            &mut artifacts,
            &mut dependencies,
            octet_stream_media_type()?,
            self.invocation.parameter_bytes,
            DependencyKind::Blob,
            DependencyRole::InvocationParameters,
            None,
            None,
            None,
            invocation_modes,
        )?;

        for capture in self.observations {
            let fingerprint = capture.observation.provider_fingerprint.clone();
            let expected = capture.observation.response_digest.clone();
            let role = capture.observation.kind.dependency_role();
            let artifact =
                DecisionArtifact::new(octet_stream_media_type()?, capture.response_bytes)?;
            if artifact.content_digest != expected {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::IntegrityFailure,
                ));
            }
            dependencies.push(DecisionDependency {
                kind: DependencyKind::Blob,
                role,
                content_digest: artifact.content_digest.clone(),
                semantic_id: None,
                record_id: None,
                fingerprint: Some(fingerprint),
                required_modes: observation_modes.clone(),
            });
            artifacts.push(artifact);
        }

        for receipt in self.verification_receipts {
            let semantic_id = receipt.receipt_id.clone();
            add_artifact_dependency(
                &mut artifacts,
                &mut dependencies,
                json_media_type()?,
                canonical_record_bytes(&receipt)?,
                DependencyKind::Blob,
                DependencyRole::VerificationReceipt,
                Some(semantic_id),
                None,
                None,
                modes(&[
                    ReplayMode::EvidenceReproduction,
                    ReplayMode::Observational,
                    ReplayMode::LiveComparison,
                ]),
            )?;
        }

        for supplied in self.dependencies {
            supplied.dependency.validate()?;
            supplied.artifact.validate()?;
            if supplied.dependency.content_digest != supplied.artifact.content_digest {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::IntegrityFailure,
                ));
            }
            dependencies.push(supplied.dependency);
            artifacts.push(supplied.artifact);
        }

        dependencies.sort();
        dependencies.dedup();
        artifacts.sort_by(|left, right| left.content_digest.cmp(&right.content_digest));
        deduplicate_artifacts(&mut artifacts)?;
        validate_decision_reference_bindings(&dependencies, &self.decision)?;
        validate_component_bindings(
            &dependencies,
            &self.decision,
            &tokenizer_fingerprint,
            &materializer_fingerprint,
            &self.invocation.envelope,
        )?;

        let manifest = DecisionArchiveManifest {
            schema_version: SchemaVersion::new("cigar.decision-archive-manifest", 1)
                .map_err(|_error| invalid())?,
            dependencies,
            invocation: self.invocation.envelope,
            observations: observation_records,
        };
        let mut archive = DecisionArchive {
            decision: self.decision,
            manifest,
        };
        archive.decision.decision_id = archive_version_id(&archive)?;
        let capture = DecisionCapture { archive, artifacts };
        capture.validate()?;
        Ok(capture)
    }

    fn validate_protocol_records(&self) -> Result<(), ReplayFoundationError> {
        self.decision.validate().map_err(|_error| invalid())?;
        self.plan.validate().map_err(|_error| invalid())?;
        self.manifest.validate().map_err(|_error| invalid())?;
        self.bundle.validate().map_err(|_error| invalid())?;
        self.materialization.validate().map_err(|_error| invalid())
    }

    fn validate_compilation_bindings(&self) -> Result<(), ReplayFoundationError> {
        if self.task_bytes.is_empty()
            || raw_content_digest(&self.task_bytes)? != self.decision.task_digest
            || self.plan.plan_id != self.decision.plan_id
            || raw_content_digest(&canonical_record_bytes(&self.plan)?)?
                != self.decision.plan_digest
            || self.bundle.bundle_id != self.decision.bundle_id
            || raw_content_digest(&self.materialization.bytes)?
                != self.decision.materialization_digest
            || self.plan.contract_digest != self.manifest.contract_digest
            || self.plan.contract_digest != self.bundle.contract_digest
            || self.materialization.bundle_id != self.bundle.bundle_id
        {
            return Err(invalid());
        }
        let expected_manifest =
            semantic_multihash_v1(SemanticEnvelopeProfile::Manifest, &self.manifest)
                .map_err(|_error| integrity())?;
        let expected_bundle = semantic_multihash_v1(SemanticEnvelopeProfile::Bundle, &self.bundle)
            .map_err(|_error| integrity())?;
        if expected_manifest != self.manifest.manifest_id.as_str()
            || expected_bundle != self.bundle.bundle_id.as_str()
            || self.bundle.manifest_digest.as_str() != self.manifest.manifest_id.as_str()
        {
            return Err(integrity());
        }
        Ok(())
    }

    fn validate_invocation_bindings(&self) -> Result<(), ReplayFoundationError> {
        if self.invocation.input_bytes.is_empty()
            || raw_content_digest(&self.invocation.input_bytes)?
                != self.invocation.envelope.input_digest
            || raw_content_digest(&self.invocation.parameter_bytes)?
                != self.invocation.envelope.parameters_digest
            || self.invocation.envelope.materialization_digest
                != self.decision.materialization_digest
            || self.invocation.envelope.runtime_fingerprint != self.decision.runtime_fingerprint
            || self.invocation.envelope.consumer_fingerprint != self.decision.consumer_fingerprint
            || self.invocation.envelope.effect_ids != self.decision.effects
            || self.invocation.envelope.usage != self.decision.usage
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_observations(&self) -> Result<(), ReplayFoundationError> {
        if self.observations.len() > cigar_protocol::limits::MAX_REPLAY_REFERENCES {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::LimitExceeded,
            ));
        }
        for (index, capture) in self.observations.iter().enumerate() {
            let ordinal = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    ReplayFoundationError::new(ReplayFoundationErrorCode::LimitExceeded)
                })?;
            if capture.observation.ordinal != ordinal
                || raw_content_digest(&capture.response_bytes)?
                    != capture.observation.response_digest
                || (capture.observation.kind == ObservationKind::Effect
                    && capture
                        .observation
                        .subject_id
                        .as_ref()
                        .is_none_or(|subject| {
                            self.decision.effects.binary_search(subject).is_err()
                        }))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn validate_verification_receipts(&self) -> Result<(), ReplayFoundationError> {
        if self.verification_receipts.len() > cigar_protocol::limits::MAX_REPLAY_REFERENCES {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::LimitExceeded,
            ));
        }
        let mut identities = Vec::with_capacity(self.verification_receipts.len());
        for receipt in &self.verification_receipts {
            receipt.validate().map_err(|_error| invalid())?;
            let expected = semantic_multihash_v1(SemanticEnvelopeProfile::Receipt, receipt)
                .map_err(|_error| integrity())?;
            if expected != receipt.receipt_id.as_str() {
                return Err(integrity());
            }
            identities.push(receipt.receipt_id.clone());
        }
        identities.sort();
        if identities != self.decision.verification_receipts
            || identities
                .windows(2)
                .any(|window| window.first() == window.get(1))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn add_artifact_dependency(
    artifacts: &mut Vec<DecisionArtifact>,
    dependencies: &mut Vec<DecisionDependency>,
    media_type: MediaType,
    bytes: Vec<u8>,
    kind: DependencyKind,
    role: DependencyRole,
    semantic_id: Option<VersionId>,
    record_id: Option<RecordId>,
    fingerprint: Option<ContentDigest>,
    required_modes: BTreeSet<ReplayMode>,
) -> Result<(), ReplayFoundationError> {
    let artifact = DecisionArtifact::new(media_type, bytes)?;
    dependencies.push(DecisionDependency {
        kind,
        role,
        content_digest: artifact.content_digest.clone(),
        semantic_id,
        record_id,
        fingerprint,
        required_modes,
    });
    artifacts.push(artifact);
    Ok(())
}

fn deduplicate_artifacts(
    artifacts: &mut Vec<DecisionArtifact>,
) -> Result<(), ReplayFoundationError> {
    let mut index = 1_usize;
    while index < artifacts.len() {
        let previous = artifacts.get(index - 1).ok_or_else(invalid)?;
        let current = artifacts.get(index).ok_or_else(invalid)?;
        if previous.content_digest == current.content_digest {
            if previous != current {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::Collision,
                ));
            }
            artifacts.remove(index);
        } else {
            index = index.checked_add(1).ok_or_else(|| {
                ReplayFoundationError::new(ReplayFoundationErrorCode::LimitExceeded)
            })?;
        }
    }
    Ok(())
}

fn validate_component_bindings(
    dependencies: &[DecisionDependency],
    decision: &DecisionRecord,
    tokenizer_fingerprint: &ContentDigest,
    materializer_fingerprint: &ContentDigest,
    invocation: &InvocationEnvelope,
) -> Result<(), ReplayFoundationError> {
    require_one_fingerprint(
        dependencies,
        DependencyRole::Runtime,
        &decision.runtime_fingerprint,
    )?;
    require_one_fingerprint(
        dependencies,
        DependencyRole::Consumer,
        &decision.consumer_fingerprint,
    )?;
    require_one_fingerprint(
        dependencies,
        DependencyRole::Adapter,
        &invocation.adapter_fingerprint,
    )?;
    require_one_fingerprint(
        dependencies,
        DependencyRole::Tokenizer,
        tokenizer_fingerprint,
    )?;
    require_one_fingerprint(
        dependencies,
        DependencyRole::Materializer,
        materializer_fingerprint,
    )?;
    let fingerprints = |role| -> Vec<ContentDigest> {
        dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .filter_map(|dependency| dependency.fingerprint.clone())
            .collect()
    };
    if fingerprints(DependencyRole::ToolSchema) != invocation.tool_schema_digests
        || fingerprints(DependencyRole::Environment) != invocation.environment_digests
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_decision_reference_bindings(
    dependencies: &[DecisionDependency],
    decision: &DecisionRecord,
) -> Result<(), ReplayFoundationError> {
    let semantic = |role| -> Vec<VersionId> {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .filter_map(|dependency| dependency.semantic_id.clone())
            .collect();
        values.sort();
        values
    };
    let digests = |role| -> Vec<ContentDigest> {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .map(|dependency| dependency.content_digest.clone())
            .collect();
        values.sort();
        values
    };
    let records = |role| -> Vec<RecordId> {
        let mut values: Vec<_> = dependencies
            .iter()
            .filter(|dependency| dependency.role == role)
            .filter_map(|dependency| dependency.record_id.clone())
            .collect();
        values.sort();
        values
    };
    if semantic(DependencyRole::OutputArtifact) != decision.output_artifacts
        || digests(DependencyRole::AssertedClaim) != decision.asserted_claims
        || digests(DependencyRole::Evidence) != decision.evidence
        || digests(DependencyRole::Uncertainty) != decision.uncertainty
        || semantic(DependencyRole::VerificationReceipt) != decision.verification_receipts
        || records(DependencyRole::Effect) != decision.effects
    {
        return Err(invalid());
    }
    Ok(())
}

fn require_one_fingerprint(
    dependencies: &[DecisionDependency],
    role: DependencyRole,
    expected: &ContentDigest,
) -> Result<(), ReplayFoundationError> {
    let found: Vec<_> = dependencies
        .iter()
        .filter(|dependency| dependency.role == role)
        .filter_map(|dependency| dependency.fingerprint.as_ref())
        .collect();
    if found.as_slice() != [expected] {
        return Err(invalid());
    }
    Ok(())
}

fn is_component_role(role: DependencyRole) -> bool {
    matches!(
        role,
        DependencyRole::Tokenizer
            | DependencyRole::Materializer
            | DependencyRole::Adapter
            | DependencyRole::Consumer
            | DependencyRole::Runtime
            | DependencyRole::ToolSchema
            | DependencyRole::Environment
    )
}

fn modes(values: &[ReplayMode]) -> BTreeSet<ReplayMode> {
    values.iter().copied().collect()
}

fn json_media_type() -> Result<MediaType, ReplayFoundationError> {
    MediaType::new("application/json").map_err(|_error| invalid())
}

fn octet_stream_media_type() -> Result<MediaType, ReplayFoundationError> {
    MediaType::new("application/octet-stream").map_err(|_error| invalid())
}

fn invalid() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput)
}

fn integrity() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::IntegrityFailure)
}

#[cfg(test)]
mod tests {
    use super::{DecisionCaptureBuilder, DependencyCapture, InvocationCapture, modes};
    use crate::archive::{InMemoryReplayArchive, ReplayArchive};
    use crate::contract::{
        DecisionArtifact, DecisionDependency, DependencyRole, InvocationEnvelope,
        ReplayFoundationErrorCode,
    };
    use crate::digest::{archive_version_id, canonical_record_bytes, raw_content_digest};
    use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
    use cigar_protocol::{
        ContentDigest, ContextBundle, ContextPlan, DecisionOutcome, DecisionRecord, DependencyKind,
        ExtensionMap, LaneKind, MaterializedContext, MediaType, PlanLane, ReplayMode,
        SchemaVersion, SelectionManifest, UsageRecord, UtcTimestamp, VersionId,
    };

    fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn content(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn component(
        role: DependencyRole,
        kind: DependencyKind,
        bytes: &[u8],
    ) -> Result<DependencyCapture, Box<dyn std::error::Error>> {
        let artifact =
            DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes.to_vec())?;
        Ok(DependencyCapture::new(
            DecisionDependency {
                kind,
                role,
                content_digest: artifact.content_digest.clone(),
                semantic_id: None,
                record_id: None,
                fingerprint: Some(artifact.content_digest.clone()),
                required_modes: modes(&[
                    ReplayMode::EvidenceReproduction,
                    ReplayMode::InvocationReproduction,
                    ReplayMode::Observational,
                    ReplayMode::LiveComparison,
                ]),
            },
            artifact,
        )?)
    }

    fn evidence_dependency(
        role: DependencyRole,
        kind: DependencyKind,
        bytes: &[u8],
        fingerprint: Option<ContentDigest>,
    ) -> Result<DependencyCapture, Box<dyn std::error::Error>> {
        let artifact =
            DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes.to_vec())?;
        Ok(DependencyCapture::new(
            DecisionDependency {
                kind,
                role,
                content_digest: artifact.content_digest.clone(),
                semantic_id: None,
                record_id: None,
                fingerprint,
                required_modes: modes(&[
                    ReplayMode::EvidenceReproduction,
                    ReplayMode::Observational,
                    ReplayMode::LiveComparison,
                ]),
            },
            artifact,
        )?)
    }

    fn fixture_builder(
        valid_task: bool,
        include_runtime: bool,
    ) -> Result<DecisionCaptureBuilder, Box<dyn std::error::Error>> {
        let task_bytes = if valid_task {
            b"observable task".to_vec()
        } else {
            b"modified task".to_vec()
        };
        let expected_task_digest = raw_content_digest(b"observable task")?;
        let contract_digest = content('a')?;
        let plan = ContextPlan {
            schema_version: SchemaVersion::new("cigar.context-plan", 1)?,
            plan_id: cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?,
            contract_digest: contract_digest.clone(),
            catalog_watermark: content('b')?,
            total_input_tokens: 1,
            lanes: vec![PlanLane {
                kind: LaneKind::Evidence,
                budget_tokens: 1,
                candidate_versions: Vec::new(),
            }],
            dispositions: Vec::new(),
            extensions: ExtensionMap::default(),
        };
        let placeholder = version('0')?;
        let mut manifest = SelectionManifest {
            schema_version: SchemaVersion::new("cigar.selection-manifest", 1)?,
            manifest_id: placeholder.clone(),
            contract_digest: contract_digest.clone(),
            entries: Vec::new(),
            extensions: ExtensionMap::default(),
        };
        manifest.manifest_id = VersionId::new(semantic_multihash_v1(
            SemanticEnvelopeProfile::Manifest,
            &manifest,
        )?)?;
        let mut bundle = ContextBundle {
            schema_version: SchemaVersion::new("cigar.context-bundle", 1)?,
            bundle_id: placeholder.clone(),
            contract_digest,
            manifest_digest: ContentDigest::new(manifest.manifest_id.as_str())?,
            blocks: Vec::new(),
            total_tokens: 0,
            extensions: ExtensionMap::default(),
        };
        bundle.bundle_id = VersionId::new(semantic_multihash_v1(
            SemanticEnvelopeProfile::Bundle,
            &bundle,
        )?)?;

        let runtime = raw_content_digest(b"runtime implementation")?;
        let consumer = raw_content_digest(b"consumer implementation")?;
        let adapter = raw_content_digest(b"adapter implementation")?;
        let tokenizer = raw_content_digest(b"tokenizer implementation")?;
        let materializer = raw_content_digest(b"materializer implementation")?;
        let materialized_bytes = b"provider-ready context".to_vec();
        let materialization_digest = raw_content_digest(&materialized_bytes)?;
        let materialization = MaterializedContext {
            schema_version: SchemaVersion::new("cigar.materialized-context", 1)?,
            bundle_id: bundle.bundle_id.clone(),
            media_type: MediaType::new("text/plain")?,
            bytes: materialized_bytes,
            token_count: 1,
            tokenizer_fingerprint: tokenizer,
            materializer_fingerprint: materializer,
        };
        let usage = UsageRecord {
            input_tokens: 1,
            output_tokens: 1,
            cached_input_tokens: 0,
            cost_micros: 0,
        };
        let input_bytes = b"exact invocation input".to_vec();
        let parameter_bytes = b"{}".to_vec();
        let invocation = InvocationCapture::new(
            InvocationEnvelope {
                schema_version: SchemaVersion::new("cigar.invocation-envelope", 1)?,
                input_digest: raw_content_digest(&input_bytes)?,
                materialization_digest: materialization_digest.clone(),
                runtime_fingerprint: runtime.clone(),
                consumer_fingerprint: consumer.clone(),
                adapter_fingerprint: adapter.clone(),
                parameters_digest: raw_content_digest(&parameter_bytes)?,
                tool_schema_digests: Vec::new(),
                environment_digests: Vec::new(),
                effect_ids: Vec::new(),
                usage,
            },
            input_bytes,
            parameter_bytes,
        )?;
        let decision = DecisionRecord {
            schema_version: SchemaVersion::new("cigar.decision-record", 1)?,
            decision_id: placeholder,
            task_digest: expected_task_digest,
            plan_id: plan.plan_id.clone(),
            plan_digest: raw_content_digest(&canonical_record_bytes(&plan)?)?,
            bundle_id: bundle.bundle_id.clone(),
            materialization_digest,
            runtime_fingerprint: runtime,
            consumer_fingerprint: consumer,
            output_artifacts: Vec::new(),
            asserted_claims: Vec::new(),
            evidence: Vec::new(),
            uncertainty: Vec::new(),
            verification_receipts: Vec::new(),
            effects: Vec::new(),
            usage,
            started_at: UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")?,
            completed_at: UtcTimestamp::parse_rfc3339("2026-07-11T12:00:01Z")?,
            outcome: DecisionOutcome::Succeeded,
            extensions: ExtensionMap::default(),
        };
        let mut builder = DecisionCaptureBuilder::new(
            decision,
            task_bytes,
            plan,
            manifest,
            bundle,
            materialization,
            invocation,
        )
        .with_dependency(component(
            DependencyRole::Consumer,
            DependencyKind::Consumer,
            b"consumer implementation",
        )?)
        .with_dependency(component(
            DependencyRole::Adapter,
            DependencyKind::Adapter,
            b"adapter implementation",
        )?)
        .with_dependency(component(
            DependencyRole::Tokenizer,
            DependencyKind::Tokenizer,
            b"tokenizer implementation",
        )?)
        .with_dependency(component(
            DependencyRole::Materializer,
            DependencyKind::Adapter,
            b"materializer implementation",
        )?)
        .with_dependency(evidence_dependency(
            DependencyRole::Policy,
            DependencyKind::Policy,
            b"policy snapshot",
            None,
        )?)
        .with_dependency(evidence_dependency(
            DependencyRole::Index,
            DependencyKind::Index,
            b"index generation",
            Some(content('b')?),
        )?);
        if include_runtime {
            builder = builder.with_dependency(component(
                DependencyRole::Runtime,
                DependencyKind::Environment,
                b"runtime implementation",
            )?);
        }
        Ok(builder)
    }

    #[test]
    fn capture_cross_binds_and_stores_exact_observable_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let capture = fixture_builder(true, true)?.seal()?;
        capture.validate()?;
        let decision_id = capture.archive.decision.decision_id.clone();
        assert_eq!(archive_version_id(&capture.archive)?, decision_id);

        let mut alternate_self_id = capture.archive.clone();
        alternate_self_id.decision.decision_id = version('f')?;
        assert_eq!(archive_version_id(&alternate_self_id)?, decision_id);

        let encoded = serde_json::to_string(&capture.archive)?;
        assert!(!encoded.contains("reasoning"));
        assert!(!format!("{capture:?}").contains("observable task"));

        let archive = InMemoryReplayArchive::default();
        archive.put_capture(&capture)?;
        archive.put_capture(&capture)?;
        assert_eq!(
            archive.get_decision(&decision_id)?.as_ref(),
            Some(&capture.archive)
        );
        for artifact in &capture.artifacts {
            assert_eq!(
                archive.get_artifact(&artifact.content_digest)?.as_ref(),
                Some(artifact)
            );
        }
        Ok(())
    }

    #[test]
    fn capture_rejects_modified_task_and_missing_component()
    -> Result<(), Box<dyn std::error::Error>> {
        let modified = fixture_builder(false, true)?.seal();
        let Err(error) = modified else {
            return Err("modified task unexpectedly sealed".into());
        };
        assert_eq!(error.code(), ReplayFoundationErrorCode::InvalidInput);

        let missing = fixture_builder(true, false)?.seal();
        let Err(error) = missing else {
            return Err("missing runtime unexpectedly sealed".into());
        };
        assert_eq!(error.code(), ReplayFoundationErrorCode::InvalidInput);
        Ok(())
    }
}
