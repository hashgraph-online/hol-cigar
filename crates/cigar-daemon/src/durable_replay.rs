//! Restart-safe replay archives and one-use reservations over the service repository.

use cigar_canon::parse_strict_json;
use cigar_protocol::{ContentDigest, MediaType, RecordId, VersionId};
use cigar_replay::{
    DecisionArchive, DecisionArtifact, DecisionCapture, MAX_DECISION_ARTIFACT_BYTES, ReplayArchive,
    ReplayError, ReplayErrorCode, ReplayFoundationError, ReplayFoundationErrorCode,
    ReplayReservationLedger,
};
use cigar_store::{
    CancellationToken, MAX_SERVICE_RECORD_BYTES, ServiceBatch, ServiceError, ServiceErrorCode,
    ServiceExpectedVersion, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite,
    ServiceRepository, ServiceResponse,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

const DECISION_NAMESPACE: &str = "replay.decision.v1";
const ARTIFACT_METADATA_NAMESPACE: &str = "replay.artifact-metadata.v1";
const ARTIFACT_CHUNK_NAMESPACE: &str = "replay.artifact-chunk.v1";
const EXECUTION_NAMESPACE: &str = "replay.execution.v1";
const LIVE_NONCE_NAMESPACE: &str = "replay.live-nonce.v1";
const LIVE_DIGEST_NAMESPACE: &str = "replay.live-digest.v1";
const ARTIFACT_METADATA_SCHEMA: &str = "cigar.durable-replay-artifact.v1";
const RESERVATION_MARKER: &[u8] = b"cigar.replay-reservation.v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactMetadata {
    schema_version: String,
    content_digest: ContentDigest,
    media_type: MediaType,
    byte_count: u64,
    chunk_count: u32,
}

impl ArtifactMetadata {
    fn from_artifact(artifact: &DecisionArtifact) -> Result<Self, ReplayFoundationError> {
        let byte_count = u64::try_from(artifact.bytes().len()).map_err(|_error| limit())?;
        let chunk_count = chunk_count(artifact.bytes().len())?;
        Ok(Self {
            schema_version: ARTIFACT_METADATA_SCHEMA.to_owned(),
            content_digest: artifact.content_digest.clone(),
            media_type: artifact.media_type.clone(),
            byte_count,
            chunk_count,
        })
    }

    fn validate_for(&self, requested: &ContentDigest) -> Result<usize, ReplayFoundationError> {
        let byte_count = usize::try_from(self.byte_count).map_err(|_error| integrity())?;
        if self.schema_version != ARTIFACT_METADATA_SCHEMA
            || &self.content_digest != requested
            || byte_count > MAX_DECISION_ARTIFACT_BYTES
            || self.chunk_count != chunk_count(byte_count)?
        {
            return Err(integrity());
        }
        Ok(byte_count)
    }
}

/// Durable immutable replay archive with chunked artifacts and root-last publication.
pub struct DurableReplayArchive {
    repository: Arc<dyn ServiceRepository>,
    tenant_id: RecordId,
    cancellation: CancellationToken,
}

impl DurableReplayArchive {
    /// Creates a tenant-scoped archive backed by one durable service repository.
    #[must_use]
    pub fn new(repository: Arc<dyn ServiceRepository>, tenant_id: RecordId) -> Self {
        Self {
            repository,
            tenant_id,
            cancellation: CancellationToken::default(),
        }
    }

    /// Creates a tenant-scoped archive linked to one request lifetime.
    #[must_use]
    pub fn new_with_cancellation(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            repository,
            tenant_id,
            cancellation,
        }
    }

    fn put_artifact(&self, artifact: &DecisionArtifact) -> Result<(), ReplayFoundationError> {
        artifact.validate()?;
        for (index, chunk) in artifact
            .bytes()
            .chunks(MAX_SERVICE_RECORD_BYTES)
            .enumerate()
        {
            self.ensure_exact(
                ARTIFACT_CHUNK_NAMESPACE,
                &artifact_chunk_key(&artifact.content_digest, index)?,
                chunk.to_vec(),
            )?;
        }
        let metadata = ArtifactMetadata::from_artifact(artifact)?;
        self.ensure_exact(
            ARTIFACT_METADATA_NAMESPACE,
            artifact.content_digest.as_str(),
            encode_json(&metadata)?,
        )
    }

    fn ensure_exact(
        &self,
        namespace: &str,
        key: &str,
        bytes: Vec<u8>,
    ) -> Result<(), ReplayFoundationError> {
        if let Some(existing) = self.get_record(namespace, key)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err(collision())
            };
        }
        let write = ServiceRecordWrite::new(
            namespace,
            key,
            ServiceExpectedVersion::Absent,
            bytes.clone(),
        )
        .map_err(map_foundation_error)?;
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_foundation_error)?;
        let batch = ServiceBatch::new(self.tenant_id.clone(), vec![write], response)
            .map_err(map_foundation_error)?;
        match self.repository.service_commit(batch, &self.cancellation) {
            Ok(_receipt) => Ok(()),
            Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                match self.get_record(namespace, key)? {
                    Some(existing) if existing == bytes => Ok(()),
                    Some(_) => Err(collision()),
                    None => Err(unavailable()),
                }
            }
            Err(error) => Err(map_foundation_error(error)),
        }
    }

    fn get_record(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, ReplayFoundationError> {
        let locator = ServiceRecordLocator::new(self.tenant_id.clone(), namespace, key)
            .map_err(map_foundation_error)?;
        self.repository
            .service_get(&locator, ServiceRecordSelection::Latest, &self.cancellation)
            .map(|record| record.map(|record| record.bytes().to_vec()))
            .map_err(map_foundation_error)
    }
}

impl fmt::Debug for DurableReplayArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableReplayArchive")
            .field("repository", &"[INJECTED]")
            .field("tenant_scope", &"[BOUND]")
            .finish()
    }
}

impl ReplayArchive for DurableReplayArchive {
    fn put_capture(&self, capture: &DecisionCapture) -> Result<(), ReplayFoundationError> {
        capture.validate()?;
        for artifact in &capture.artifacts {
            self.put_artifact(artifact)?;
        }
        let decision_id = &capture.archive.decision.decision_id;
        self.ensure_exact(
            DECISION_NAMESPACE,
            decision_id.as_str(),
            encode_json(&capture.archive)?,
        )
    }

    fn get_decision(
        &self,
        decision_id: &VersionId,
    ) -> Result<Option<DecisionArchive>, ReplayFoundationError> {
        let Some(bytes) = self.get_record(DECISION_NAMESPACE, decision_id.as_str())? else {
            return Ok(None);
        };
        let archive: DecisionArchive = decode_json(&bytes)?;
        archive.validate().map_err(|_error| integrity())?;
        if &archive.decision.decision_id != decision_id {
            return Err(integrity());
        }
        Ok(Some(archive))
    }

    fn get_artifact(
        &self,
        content_digest: &ContentDigest,
    ) -> Result<Option<DecisionArtifact>, ReplayFoundationError> {
        let Some(metadata_bytes) =
            self.get_record(ARTIFACT_METADATA_NAMESPACE, content_digest.as_str())?
        else {
            return Ok(None);
        };
        let metadata: ArtifactMetadata = decode_json(&metadata_bytes)?;
        let byte_count = metadata.validate_for(content_digest)?;
        let capacity = byte_count;
        let mut bytes = Vec::with_capacity(capacity);
        for index in 0..usize::try_from(metadata.chunk_count).map_err(|_error| integrity())? {
            let key = artifact_chunk_key(content_digest, index)?;
            let chunk = self
                .get_record(ARTIFACT_CHUNK_NAMESPACE, &key)?
                .ok_or_else(integrity)?;
            let remaining = byte_count.checked_sub(bytes.len()).ok_or_else(integrity)?;
            let expected = remaining.min(MAX_SERVICE_RECORD_BYTES);
            if chunk.len() != expected {
                return Err(integrity());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != byte_count {
            return Err(integrity());
        }
        let artifact =
            DecisionArtifact::new(metadata.media_type, bytes).map_err(|_error| integrity())?;
        if &artifact.content_digest != content_digest {
            return Err(integrity());
        }
        Ok(Some(artifact))
    }
}

/// Durable atomic replay execution and live-authorization reservation ledger.
pub struct DurableReplayReservationLedger {
    repository: Arc<dyn ServiceRepository>,
    tenant_id: RecordId,
    cancellation: CancellationToken,
}

impl DurableReplayReservationLedger {
    /// Creates a tenant-scoped one-use reservation ledger.
    #[must_use]
    pub fn new(repository: Arc<dyn ServiceRepository>, tenant_id: RecordId) -> Self {
        Self {
            repository,
            tenant_id,
            cancellation: CancellationToken::default(),
        }
    }

    /// Creates a tenant-scoped ledger linked to one request lifetime.
    #[must_use]
    pub fn new_with_cancellation(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            repository,
            tenant_id,
            cancellation,
        }
    }

    fn reserve(&self, writes: Vec<ServiceRecordWrite>) -> Result<bool, ReplayError> {
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_replay_error)?;
        let batch = ServiceBatch::new(self.tenant_id.clone(), writes, response)
            .map_err(map_replay_error)?;
        match self.repository.service_commit(batch, &self.cancellation) {
            Ok(_receipt) => Ok(true),
            Err(error) if error.code() == ServiceErrorCode::RevisionConflict => Ok(false),
            Err(error) => Err(map_replay_error(error)),
        }
    }

    fn marker(namespace: &str, key: &str) -> Result<ServiceRecordWrite, ReplayError> {
        ServiceRecordWrite::new(
            namespace,
            key,
            ServiceExpectedVersion::Absent,
            RESERVATION_MARKER.to_vec(),
        )
        .map_err(map_replay_error)
    }
}

impl fmt::Debug for DurableReplayReservationLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableReplayReservationLedger")
            .field("repository", &"[INJECTED]")
            .field("tenant_scope", &"[BOUND]")
            .finish()
    }
}

impl ReplayReservationLedger for DurableReplayReservationLedger {
    fn reserve_execution(&self, execution_id: &RecordId) -> Result<bool, ReplayError> {
        self.reserve(vec![Self::marker(
            EXECUTION_NAMESPACE,
            execution_id.as_str(),
        )?])
    }

    fn reserve_live_authorization(
        &self,
        nonce: &RecordId,
        digest: &ContentDigest,
    ) -> Result<bool, ReplayError> {
        self.reserve(vec![
            Self::marker(LIVE_NONCE_NAMESPACE, nonce.as_str())?,
            Self::marker(LIVE_DIGEST_NAMESPACE, digest.as_str())?,
        ])
    }
}

fn chunk_count(byte_count: usize) -> Result<u32, ReplayFoundationError> {
    let count = if byte_count == 0 {
        0
    } else {
        byte_count
            .checked_sub(1)
            .and_then(|value| value.checked_div(MAX_SERVICE_RECORD_BYTES))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(limit)?
    };
    u32::try_from(count).map_err(|_error| limit())
}

fn artifact_chunk_key(
    content_digest: &ContentDigest,
    index: usize,
) -> Result<String, ReplayFoundationError> {
    let index = u32::try_from(index).map_err(|_error| limit())?;
    Ok(format!("{}.{index:08}", content_digest.as_str()))
}

fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ReplayFoundationError> {
    serde_json::to_vec(value).map_err(|_error| unavailable())
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ReplayFoundationError> {
    parse_strict_json(bytes).map_err(|_error| integrity())?;
    serde_json::from_slice(bytes).map_err(|_error| integrity())
}

fn map_foundation_error(error: ServiceError) -> ReplayFoundationError {
    match error.code() {
        ServiceErrorCode::LimitExceeded => limit(),
        _ => unavailable(),
    }
}

fn map_replay_error(_error: ServiceError) -> ReplayError {
    ReplayError::new(ReplayErrorCode::Unavailable)
}

fn limit() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::LimitExceeded)
}

fn integrity() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::IntegrityFailure)
}

fn collision() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::Collision)
}

fn unavailable() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::Unavailable)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{DurableReplayArchive, DurableReplayReservationLedger};
    use cigar_canon::{
        SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1, to_normalized_json,
    };
    use cigar_protocol::{
        ContentDigest, ContextBundle, ContextPlan, DecisionOutcome, DecisionRecord, DependencyKind,
        ExtensionMap, LaneKind, MaterializedContext, MediaType, PlanLane, RecordId, ReplayMode,
        SchemaVersion, SelectionManifest, UsageRecord, UtcTimestamp, VersionId,
    };
    use cigar_replay::{
        DecisionArtifact, DecisionCapture, DecisionCaptureBuilder, DecisionDependency,
        DependencyCapture, DependencyRole, InvocationCapture, InvocationEnvelope, ReplayArchive,
        ReplayFoundationErrorCode, ReplayReservationLedger,
    };
    use cigar_store::{InMemoryStore, MAX_SERVICE_RECORD_BYTES, ServiceRepository, SqliteStore};
    use serde::Serialize;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fmt::Write as _;
    use std::sync::Arc;

    fn tenant() -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?)
    }

    fn record(last: char) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f789{last}"
        ))?)
    }

    fn digest(last: char) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            last.to_string().repeat(64)
        ))?)
    }

    fn raw_digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
        let mut encoded = String::from("1220");
        for byte in Sha256::digest(bytes) {
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(ContentDigest::new(encoded)?)
    }

    fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
        let json = serde_json::to_vec(value)?;
        Ok(to_normalized_json(&parse_strict_json(&json)?)?)
    }

    fn modes(values: &[ReplayMode]) -> BTreeSet<ReplayMode> {
        values.iter().copied().collect()
    }

    fn component(
        role: DependencyRole,
        kind: DependencyKind,
        bytes: &[u8],
    ) -> Result<DependencyCapture, Box<dyn Error>> {
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

    fn evidence(
        role: DependencyRole,
        kind: DependencyKind,
        bytes: &[u8],
        fingerprint: Option<ContentDigest>,
    ) -> Result<DependencyCapture, Box<dyn Error>> {
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

    pub(crate) fn capture_fixture() -> Result<DecisionCapture, Box<dyn Error>> {
        let task_bytes = b"durable replay task".to_vec();
        let contract_digest = digest('a')?;
        let catalog_watermark = digest('b')?;
        let plan = ContextPlan {
            schema_version: SchemaVersion::new("cigar.context-plan", 1)?,
            plan_id: record('5')?,
            contract_digest: contract_digest.clone(),
            catalog_watermark: catalog_watermark.clone(),
            total_input_tokens: 1,
            lanes: vec![PlanLane {
                kind: LaneKind::Evidence,
                budget_tokens: 1,
                candidate_versions: Vec::new(),
            }],
            dispositions: Vec::new(),
            extensions: ExtensionMap::default(),
        };
        let placeholder = VersionId::new(digest('0')?.as_str())?;
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

        let runtime = raw_digest(b"runtime implementation")?;
        let consumer = raw_digest(b"consumer implementation")?;
        let adapter = raw_digest(b"adapter implementation")?;
        let tokenizer = raw_digest(b"tokenizer implementation")?;
        let materializer = raw_digest(b"materializer implementation")?;
        let materialized_bytes = b"provider-ready context".to_vec();
        let materialization_digest = raw_digest(&materialized_bytes)?;
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
        let invocation_bytes = b"exact durable invocation".to_vec();
        let parameter_bytes = b"{}".to_vec();
        let invocation = InvocationCapture::new(
            InvocationEnvelope {
                schema_version: SchemaVersion::new("cigar.invocation-envelope", 1)?,
                input_digest: raw_digest(&invocation_bytes)?,
                materialization_digest: materialization_digest.clone(),
                runtime_fingerprint: runtime.clone(),
                consumer_fingerprint: consumer.clone(),
                adapter_fingerprint: adapter,
                parameters_digest: raw_digest(&parameter_bytes)?,
                tool_schema_digests: Vec::new(),
                environment_digests: Vec::new(),
                effect_ids: Vec::new(),
                usage,
            },
            invocation_bytes,
            parameter_bytes,
        )?;
        let decision = DecisionRecord {
            schema_version: SchemaVersion::new("cigar.decision-record", 1)?,
            decision_id: placeholder,
            task_digest: raw_digest(&task_bytes)?,
            plan_id: plan.plan_id.clone(),
            plan_digest: raw_digest(&canonical_json(&plan)?)?,
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
        let builder = DecisionCaptureBuilder::new(
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
        .with_dependency(component(
            DependencyRole::Runtime,
            DependencyKind::Environment,
            b"runtime implementation",
        )?)
        .with_dependency(evidence(
            DependencyRole::Policy,
            DependencyKind::Policy,
            b"policy snapshot",
            None,
        )?)
        .with_dependency(evidence(
            DependencyRole::Index,
            DependencyKind::Index,
            b"index generation",
            Some(catalog_watermark),
        )?);
        Ok(builder.seal()?)
    }

    #[test]
    fn artifact_chunks_and_empty_bytes_round_trip_exactly() -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let archive = DurableReplayArchive::new(repository, tenant()?);
        let empty = DecisionArtifact::new(MediaType::new("application/octet-stream")?, Vec::new())?;
        archive.put_artifact(&empty)?;
        assert_eq!(archive.get_artifact(&empty.content_digest)?, Some(empty));

        let bytes = vec![0xa5; MAX_SERVICE_RECORD_BYTES + 17];
        let chunked = DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes)?;
        archive.put_artifact(&chunked)?;
        assert_eq!(
            archive.get_artifact(&chunked.content_digest)?,
            Some(chunked)
        );
        Ok(())
    }

    #[test]
    fn absent_replay_records_never_fall_back() -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let archive = DurableReplayArchive::new(repository, tenant()?);
        assert!(
            archive
                .get_decision(&VersionId::new(digest('a')?.as_str())?)?
                .is_none()
        );
        assert!(archive.get_artifact(&digest('b')?)?.is_none());
        Ok(())
    }

    #[test]
    fn reservations_are_atomic_and_have_one_concurrent_winner() -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let ledger = Arc::new(DurableReplayReservationLedger::new(repository, tenant()?));
        let execution = record('1')?;
        let mut workers = Vec::new();
        for _index in 0..12 {
            let ledger = Arc::clone(&ledger);
            let execution = execution.clone();
            workers.push(std::thread::spawn(move || {
                ledger.reserve_execution(&execution)
            }));
        }
        let mut winners = 0_u8;
        for worker in workers {
            if worker
                .join()
                .map_err(|_panic| "reservation worker panicked")??
            {
                winners = winners.checked_add(1).ok_or("winner count overflow")?;
            }
        }
        assert_eq!(winners, 1);

        let nonce = record('2')?;
        let alternate_nonce = record('3')?;
        let authorization = digest('c')?;
        let alternate_authorization = digest('d')?;
        assert!(ledger.reserve_live_authorization(&nonce, &authorization)?);
        assert!(!ledger.reserve_live_authorization(&nonce, &alternate_authorization)?);
        assert!(!ledger.reserve_live_authorization(&alternate_nonce, &authorization)?);
        assert!(ledger.reserve_live_authorization(&alternate_nonce, &alternate_authorization)?);
        Ok(())
    }

    #[test]
    fn sqlite_restart_preserves_artifacts_and_reservations() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("durable-replay.sqlite3");
        let tenant_id = tenant()?;
        let execution = record('4')?;
        let artifact = DecisionArtifact::new(MediaType::new("text/plain")?, b"restart".to_vec())?;
        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let archive = DurableReplayArchive::new(Arc::clone(&repository), tenant_id.clone());
            archive.put_artifact(&artifact)?;
            let ledger = DurableReplayReservationLedger::new(repository, tenant_id.clone());
            assert!(ledger.reserve_execution(&execution)?);
        }
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let archive = DurableReplayArchive::new(Arc::clone(&repository), tenant_id.clone());
        assert_eq!(
            archive.get_artifact(&artifact.content_digest)?,
            Some(artifact)
        );
        let ledger = DurableReplayReservationLedger::new(repository, tenant_id);
        assert!(!ledger.reserve_execution(&execution)?);
        Ok(())
    }

    #[test]
    fn decision_root_is_published_last_and_full_capture_survives_restart()
    -> Result<(), Box<dyn Error>> {
        let capture = capture_fixture()?;
        let decision_id = capture.archive.decision.decision_id.clone();
        let store = Arc::new(InMemoryStore::default());
        let repository: Arc<dyn ServiceRepository> = store.clone();
        let archive = DurableReplayArchive::new(repository, tenant()?);
        for artifact in &capture.artifacts {
            archive.put_artifact(artifact)?;
        }
        store.fail_next_commit();
        let failure = archive
            .put_capture(&capture)
            .err()
            .ok_or("injected root publication did not fail")?;
        assert_eq!(failure.code(), ReplayFoundationErrorCode::Unavailable);
        assert!(archive.get_decision(&decision_id)?.is_none());
        archive.put_capture(&capture)?;
        assert_eq!(
            archive.get_decision(&decision_id)?,
            Some(capture.archive.clone())
        );

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("capture-restart.sqlite3");
        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            DurableReplayArchive::new(repository, tenant()?).put_capture(&capture)?;
        }
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let reopened = DurableReplayArchive::new(repository, tenant()?);
        assert_eq!(reopened.get_decision(&decision_id)?, Some(capture.archive));
        for artifact in capture.artifacts {
            assert_eq!(
                reopened.get_artifact(&artifact.content_digest)?,
                Some(artifact)
            );
        }
        Ok(())
    }
}
