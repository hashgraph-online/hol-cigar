//! Root-last durable publication for bounded service snapshots.

use cigar_canon::parse_strict_json;
use cigar_crypto::{KeyProvider, KeyRef};
use cigar_protocol::{
    ContentDigest, ContextCommit, ContextSpaceId, CoordinationEvent, ExpectedRevision,
    HandoffAcceptance, HandoffCapsule, Overlay, RecordId, UtcTimestamp, VersionId,
};
use cigar_space::{
    AcceptHandoffRequest, AcceptanceInspection, AcceptedHandoffContext, AcquireLeaseRequest,
    ConflictResolutionReceipt, ContextSpaceService, CreateHandoffRequest, CreateSpaceRequest,
    EventCursor, EventPage, FencedLease, FocusBranch, HandoffCreationPreview, HandoffError,
    HandoffMergeMaterial, HandoffResultReceipt, HandoffRevocation, HandoffService,
    LeaseMutationRequest, ProjectContribution, ProjectLink, ProjectLinkPreview, ProposedMutation,
    PublishOutcome, PublishRequest, RecipientBundleReceipt, RecordHandoffResultRequest,
    ResolveConflictRequest, ResultMergeMapping, ResultMergeReceipt, RevokeHandoffRequest,
    SpaceError, SpaceView, StoredMergeConflict, merge_child_result,
};
use cigar_store::{
    CancellationToken, MAX_SERVICE_RECORD_BYTES, ServiceBatch, ServiceError, ServiceErrorCode,
    ServiceExpectedVersion, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite,
    ServiceRepository, ServiceResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};

const ROOT_NAMESPACE: &str = "cigar.daemon.snapshot-root.v1";
const CHUNK_NAMESPACE: &str = "cigar.daemon.snapshot-chunk.v1";
const MANIFEST_SCHEMA: &str = "cigar.durable-snapshot-manifest.v1";
const ROOT_ENVELOPE_SCHEMA: &str = "cigar.durable-snapshot-root.v1";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"CIGAR-DURABLE-SNAPSHOT-ROOT\0v1\0";
pub(crate) const SNAPSHOT_ROOT_SIGNATURE_PURPOSE: &str = "cigar.durable-snapshot-root.v1";
pub(crate) const SNAPSHOT_ROOT_SIGNER: &str = "cigard.snapshot-root";
const CHUNK_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_SNAPSHOT_CHUNKS: usize = 64;
const MAX_SNAPSHOT_BYTES: usize = CHUNK_BYTES * MAX_SNAPSHOT_CHUNKS;
const SPACE_SNAPSHOT_KIND: &str = "context-space";
const HANDOFF_SNAPSHOT_KIND: &str = "handoff";

/// Stable content-free durable snapshot failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableSnapshotErrorCode {
    /// A manifest, chunk, digest, or restored snapshot was inconsistent.
    InvalidSnapshot,
    /// A configured snapshot or repository bound was exceeded.
    LimitExceeded,
    /// Another writer advanced the exact snapshot root first.
    RevisionConflict,
    /// Cooperative cancellation was observed before publication.
    Cancelled,
    /// A test failpoint aborted before atomic root publication.
    InjectedAbort,
    /// The durable repository could not safely complete the operation.
    Unavailable,
}

/// Content-free error returned by root-last snapshot persistence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DurableSnapshotError {
    code: DurableSnapshotErrorCode,
}

impl DurableSnapshotError {
    pub(crate) const fn new(code: DurableSnapshotErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable content-free category.
    #[must_use]
    pub const fn code(self) -> DurableSnapshotErrorCode {
        self.code
    }
}

impl fmt::Debug for DurableSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableSnapshotError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for DurableSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "durable snapshot operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for DurableSnapshotError {}

impl From<ServiceError> for DurableSnapshotError {
    fn from(error: ServiceError) -> Self {
        let code = match error.code() {
            ServiceErrorCode::RevisionConflict => DurableSnapshotErrorCode::RevisionConflict,
            ServiceErrorCode::LimitExceeded => DurableSnapshotErrorCode::LimitExceeded,
            ServiceErrorCode::Cancelled => DurableSnapshotErrorCode::Cancelled,
            ServiceErrorCode::InjectedAbort => DurableSnapshotErrorCode::InjectedAbort,
            ServiceErrorCode::InvalidInput
            | ServiceErrorCode::NotFound
            | ServiceErrorCode::IdempotencyConflict
            | ServiceErrorCode::CursorScopeMismatch => DurableSnapshotErrorCode::InvalidSnapshot,
            ServiceErrorCode::Unavailable => DurableSnapshotErrorCode::Unavailable,
        };
        Self::new(code)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotChunk {
    digest: ContentDigest,
    byte_count: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifest {
    schema_version: String,
    snapshot_kind: String,
    generation: u64,
    byte_count: usize,
    content_digest: ContentDigest,
    chunks: Vec<SnapshotChunk>,
}

/// Keyed authentication retained beside one durable snapshot manifest.
///
/// The signed payload binds the exact tenant, snapshot kind, generation, and canonical manifest.
/// Keeping this record independent of repository checksums prevents a storage actor from
/// coherently replacing both chunks and their root manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRootAuthentication {
    /// Exact signing key selected by the trusted tenant authority.
    pub key_ref: KeyRef,
    /// Unix nanoseconds at which the root was signed.
    pub signed_at: i128,
    /// Ed25519 signature over the domain-separated root payload digest.
    pub signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRootEnvelope {
    schema_version: String,
    manifest: SnapshotManifest,
    authentication: SnapshotRootAuthentication,
}

/// Trusted tenant authority used to sign and verify durable snapshot roots.
pub trait DurableSnapshotAuthenticator: Send + Sync {
    /// Signs one already domain-separated root payload digest.
    fn sign_snapshot_root(
        &self,
        tenant_id: &RecordId,
        payload_digest: [u8; 32],
    ) -> Result<SnapshotRootAuthentication, DurableSnapshotError>;

    /// Verifies one root against current tenant and key revocation authority.
    fn verify_snapshot_root(
        &self,
        tenant_id: &RecordId,
        payload_digest: &[u8; 32],
        authentication: &SnapshotRootAuthentication,
    ) -> Result<(), DurableSnapshotError>;
}

#[cfg(test)]
#[derive(Default)]
struct TestSnapshotAuthenticator;

#[cfg(test)]
impl TestSnapshotAuthenticator {
    fn signature(payload_digest: &[u8; 32]) -> Vec<u8> {
        const TEST_KEY: &[u8] = b"cigar-test-only-snapshot-root-key";
        let mut left = Sha256::new();
        left.update(TEST_KEY);
        left.update(payload_digest);
        let mut right = Sha256::new();
        right.update(payload_digest);
        right.update(TEST_KEY);
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&left.finalize());
        signature.extend_from_slice(&right.finalize());
        signature
    }
}

#[cfg(test)]
impl DurableSnapshotAuthenticator for TestSnapshotAuthenticator {
    fn sign_snapshot_root(
        &self,
        _tenant_id: &RecordId,
        payload_digest: [u8; 32],
    ) -> Result<SnapshotRootAuthentication, DurableSnapshotError> {
        Ok(SnapshotRootAuthentication {
            key_ref: KeyRef::new("test-snapshot-root").map_err(|_error| {
                DurableSnapshotError::new(DurableSnapshotErrorCode::Unavailable)
            })?,
            signed_at: 1,
            signature: Self::signature(&payload_digest),
        })
    }

    fn verify_snapshot_root(
        &self,
        _tenant_id: &RecordId,
        payload_digest: &[u8; 32],
        authentication: &SnapshotRootAuthentication,
    ) -> Result<(), DurableSnapshotError> {
        if authentication.key_ref.as_str() == "test-snapshot-root"
            && authentication.signed_at == 1
            && authentication.signature == Self::signature(payload_digest)
        {
            Ok(())
        } else {
            Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ))
        }
    }
}

#[cfg(test)]
pub(crate) fn test_snapshot_authenticator() -> Arc<dyn DurableSnapshotAuthenticator> {
    Arc::new(TestSnapshotAuthenticator)
}

/// One loaded exact snapshot and its CAS root version.
pub(crate) struct LoadedSnapshot {
    pub(crate) version: u64,
    pub(crate) bytes: Option<Vec<u8>>,
}

/// Repository-scoped root-last snapshot persistence.
pub(crate) struct DurableSnapshotStore {
    repository: Arc<dyn ServiceRepository>,
    authenticator: Arc<dyn DurableSnapshotAuthenticator>,
    tenant_id: RecordId,
    snapshot_kind: &'static str,
}

impl DurableSnapshotStore {
    pub(crate) fn new_authenticated(
        repository: Arc<dyn ServiceRepository>,
        authenticator: Arc<dyn DurableSnapshotAuthenticator>,
        tenant_id: RecordId,
        snapshot_kind: &'static str,
    ) -> Self {
        Self {
            repository,
            authenticator,
            tenant_id,
            snapshot_kind,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        snapshot_kind: &'static str,
    ) -> Self {
        Self::new_authenticated(
            repository,
            test_snapshot_authenticator(),
            tenant_id,
            snapshot_kind,
        )
    }

    pub(crate) fn load(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<LoadedSnapshot, DurableSnapshotError> {
        let root = self.repository.service_get(
            &self.root_locator()?,
            ServiceRecordSelection::Latest,
            cancellation,
        )?;
        let Some(root) = root else {
            return Ok(LoadedSnapshot {
                version: 0,
                bytes: None,
            });
        };
        parse_strict_json(root.bytes()).map_err(|_error| {
            DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot)
        })?;
        let envelope: SnapshotRootEnvelope =
            serde_json::from_slice(root.bytes()).map_err(|_error| {
                DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot)
            })?;
        if envelope.schema_version != ROOT_ENVELOPE_SCHEMA {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        let manifest = envelope.manifest;
        self.validate_manifest(&manifest, root.version())?;
        let payload_digest = root_payload_digest(&self.tenant_id, &manifest)?;
        self.authenticator.verify_snapshot_root(
            &self.tenant_id,
            &payload_digest,
            &envelope.authentication,
        )?;

        let mut bytes = Vec::with_capacity(manifest.byte_count);
        for expected in &manifest.chunks {
            let locator = ServiceRecordLocator::new(
                self.tenant_id.clone(),
                CHUNK_NAMESPACE,
                expected.digest.as_str(),
            )?;
            let record = self
                .repository
                .service_get(&locator, ServiceRecordSelection::Latest, cancellation)?
                .ok_or_else(|| {
                    DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot)
                })?;
            if record.bytes().len() != expected.byte_count
                || exact_digest(record.bytes())? != expected.digest
            {
                return Err(DurableSnapshotError::new(
                    DurableSnapshotErrorCode::InvalidSnapshot,
                ));
            }
            bytes.extend_from_slice(record.bytes());
        }
        if bytes.len() != manifest.byte_count || exact_digest(&bytes)? != manifest.content_digest {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        Ok(LoadedSnapshot {
            version: root.version(),
            bytes: Some(bytes),
        })
    }

    pub(crate) fn publish(
        &self,
        expected_version: u64,
        bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<u64, DurableSnapshotError> {
        if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::LimitExceeded,
            ));
        }
        let generation = expected_version
            .checked_add(1)
            .ok_or_else(|| DurableSnapshotError::new(DurableSnapshotErrorCode::LimitExceeded))?;
        let mut chunks = Vec::new();
        for chunk in bytes.chunks(CHUNK_BYTES) {
            let digest = exact_digest(chunk)?;
            self.ensure_chunk(&digest, chunk, cancellation)?;
            chunks.push(SnapshotChunk {
                digest,
                byte_count: chunk.len(),
            });
        }
        if chunks.is_empty() || chunks.len() > MAX_SNAPSHOT_CHUNKS {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::LimitExceeded,
            ));
        }
        let manifest = SnapshotManifest {
            schema_version: MANIFEST_SCHEMA.to_owned(),
            snapshot_kind: self.snapshot_kind.to_owned(),
            generation,
            byte_count: bytes.len(),
            content_digest: exact_digest(bytes)?,
            chunks,
        };
        let payload_digest = root_payload_digest(&self.tenant_id, &manifest)?;
        let authentication = self
            .authenticator
            .sign_snapshot_root(&self.tenant_id, payload_digest)?;
        if authentication.signature.len() != 64 {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        let root_bytes = serde_json::to_vec(&SnapshotRootEnvelope {
            schema_version: ROOT_ENVELOPE_SCHEMA.to_owned(),
            manifest,
            authentication,
        })
        .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))?;
        if root_bytes.is_empty() || root_bytes.len() > MAX_SERVICE_RECORD_BYTES {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::LimitExceeded,
            ));
        }
        let expected = if expected_version == 0 {
            ServiceExpectedVersion::Absent
        } else {
            ServiceExpectedVersion::Version(expected_version)
        };
        let write =
            ServiceRecordWrite::new(ROOT_NAMESPACE, self.snapshot_kind, expected, root_bytes)?;
        let batch = ServiceBatch::new(self.tenant_id.clone(), vec![write], empty_response()?)?;
        let receipt = self.repository.service_commit(batch, cancellation)?;
        let published = receipt
            .records
            .first()
            .ok_or_else(|| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))?;
        if published.namespace != ROOT_NAMESPACE
            || published.key != self.snapshot_kind
            || published.version != generation
        {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        Ok(generation)
    }

    fn ensure_chunk(
        &self,
        digest: &ContentDigest,
        bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), DurableSnapshotError> {
        let locator =
            ServiceRecordLocator::new(self.tenant_id.clone(), CHUNK_NAMESPACE, digest.as_str())?;
        if let Some(record) =
            self.repository
                .service_get(&locator, ServiceRecordSelection::Latest, cancellation)?
        {
            return verify_chunk(&record, digest, bytes);
        }
        let write = ServiceRecordWrite::new(
            CHUNK_NAMESPACE,
            digest.as_str(),
            ServiceExpectedVersion::Absent,
            bytes.to_vec(),
        )?;
        let batch = ServiceBatch::new(self.tenant_id.clone(), vec![write], empty_response()?)?;
        match self.repository.service_commit(batch, cancellation) {
            Ok(_receipt) => Ok(()),
            Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                let record = self
                    .repository
                    .service_get(&locator, ServiceRecordSelection::Latest, cancellation)?
                    .ok_or_else(|| {
                        DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot)
                    })?;
                verify_chunk(&record, digest, bytes)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn validate_manifest(
        &self,
        manifest: &SnapshotManifest,
        root_version: u64,
    ) -> Result<(), DurableSnapshotError> {
        let counted = manifest
            .chunks
            .iter()
            .try_fold(0_usize, |total, chunk| total.checked_add(chunk.byte_count))
            .ok_or_else(|| DurableSnapshotError::new(DurableSnapshotErrorCode::LimitExceeded))?;
        if manifest.schema_version != MANIFEST_SCHEMA
            || manifest.snapshot_kind != self.snapshot_kind
            || manifest.generation != root_version
            || manifest.byte_count == 0
            || manifest.byte_count > MAX_SNAPSHOT_BYTES
            || manifest.chunks.is_empty()
            || manifest.chunks.len() > MAX_SNAPSHOT_CHUNKS
            || counted != manifest.byte_count
            || manifest
                .chunks
                .iter()
                .any(|chunk| chunk.byte_count == 0 || chunk.byte_count > CHUNK_BYTES)
        {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        Ok(())
    }

    fn root_locator(&self) -> Result<ServiceRecordLocator, DurableSnapshotError> {
        ServiceRecordLocator::new(self.tenant_id.clone(), ROOT_NAMESPACE, self.snapshot_kind)
            .map_err(Into::into)
    }
}

fn verify_chunk(
    record: &cigar_store::ServiceRecord,
    digest: &ContentDigest,
    bytes: &[u8],
) -> Result<(), DurableSnapshotError> {
    if record.digest() != digest
        || record.bytes() != bytes
        || exact_digest(record.bytes())? != *digest
    {
        Err(DurableSnapshotError::new(
            DurableSnapshotErrorCode::InvalidSnapshot,
        ))
    } else {
        Ok(())
    }
}

fn empty_response() -> Result<ServiceResponse, DurableSnapshotError> {
    ServiceResponse::new(204, "application/octet-stream", Vec::new()).map_err(Into::into)
}

fn exact_digest(bytes: &[u8]) -> Result<ContentDigest, DurableSnapshotError> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| {
            DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot)
        })?;
    }
    ContentDigest::new(encoded)
        .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))
}

fn root_payload_digest(
    tenant_id: &RecordId,
    manifest: &SnapshotManifest,
) -> Result<[u8; 32], DurableSnapshotError> {
    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))?;
    let tenant = tenant_id.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(ROOT_SIGNATURE_DOMAIN);
    hasher.update(
        u64::try_from(tenant.len())
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hasher.update(tenant);
    hasher.update(
        u64::try_from(manifest_bytes.len())
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hasher.update(&manifest_bytes);
    Ok(hasher.finalize().into())
}

/// Stable content-free failure categories for durable space and handoff services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableStateErrorCode {
    /// The context-space domain operation failed before publication.
    Space(SpaceError),
    /// The handoff domain operation failed before publication.
    Handoff(HandoffError),
    /// Snapshot persistence, reconciliation, or restoration failed.
    Snapshot(DurableSnapshotErrorCode),
}

/// Content-free error returned by a durable space or handoff service.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DurableStateError {
    code: DurableStateErrorCode,
}

impl DurableStateError {
    const fn new(code: DurableStateErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable content-free category.
    #[must_use]
    pub const fn code(self) -> DurableStateErrorCode {
        self.code
    }

    /// Creates a content-free dependency-unavailable failure for bounded service providers.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self::new(DurableStateErrorCode::Snapshot(
            DurableSnapshotErrorCode::Unavailable,
        ))
    }
}

impl fmt::Debug for DurableStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableStateError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for DurableStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "durable service operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for DurableStateError {}

impl From<DurableSnapshotError> for DurableStateError {
    fn from(error: DurableSnapshotError) -> Self {
        Self::new(DurableStateErrorCode::Snapshot(error.code()))
    }
}

impl From<SpaceError> for DurableStateError {
    fn from(error: SpaceError) -> Self {
        Self::new(DurableStateErrorCode::Space(error))
    }
}

impl From<HandoffError> for DurableStateError {
    fn from(error: HandoffError) -> Self {
        Self::new(DurableStateErrorCode::Handoff(error))
    }
}

struct SpaceSnapshotState {
    service: ContextSpaceService,
    generation: u64,
    healthy: bool,
}

/// Transactional context-space service whose complete state is published root-last.
///
/// Every mutation is serialized, validated, and persisted with a root CAS before its result is
/// returned. Failed domain operations and failed publications restore the last durable snapshot.
/// A repository error that cannot be reconciled poisons the instance so stale state is never read.
pub struct DurableContextSpaceService {
    store: DurableSnapshotStore,
    state: Mutex<SpaceSnapshotState>,
}

impl DurableContextSpaceService {
    /// Opens the latest tenant-scoped state, or an empty service when no root exists.
    pub fn open_authenticated(
        repository: Arc<dyn ServiceRepository>,
        authenticator: Arc<dyn DurableSnapshotAuthenticator>,
        tenant_id: RecordId,
        cancellation: &CancellationToken,
    ) -> Result<Self, DurableStateError> {
        let store = DurableSnapshotStore::new_authenticated(
            repository,
            authenticator,
            tenant_id,
            SPACE_SNAPSHOT_KIND,
        );
        let loaded = store.load(cancellation)?;
        let service = match loaded.bytes {
            Some(bytes) => {
                ContextSpaceService::from_snapshot(&bytes).map_err(|_error| invalid_state())?
            }
            None if loaded.version == 0 => ContextSpaceService::new(),
            None => return Err(invalid_state()),
        };
        Ok(Self {
            store,
            state: Mutex::new(SpaceSnapshotState {
                service,
                generation: loaded.version,
                healthy: true,
            }),
        })
    }

    #[cfg(test)]
    fn open(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        cancellation: &CancellationToken,
    ) -> Result<Self, DurableStateError> {
        Self::open_authenticated(
            repository,
            test_snapshot_authenticator(),
            tenant_id,
            cancellation,
        )
    }

    /// Returns the latest reconciled root generation.
    pub fn generation(&self) -> Result<u64, DurableStateError> {
        let state = self.state.lock().map_err(|_error| unavailable_state())?;
        ensure_healthy(state.healthy)?;
        Ok(state.generation)
    }

    /// Resolves the immutable active-project binding for an existing space.
    pub fn active_project_id(
        &self,
        space_id: &ContextSpaceId,
    ) -> Result<RecordId, DurableStateError> {
        self.read(|service| service.active_project_id(space_id).map_err(Into::into))
    }

    /// Runs a domain operation against an isolated exact clone without publishing mutations.
    pub fn simulate<T>(
        &self,
        operation: impl FnOnce(&ContextSpaceService) -> Result<T, SpaceError>,
    ) -> Result<T, DurableStateError> {
        self.read(|service| {
            let snapshot = service.export_snapshot().map_err(DurableStateError::from)?;
            let isolated =
                ContextSpaceService::from_snapshot(&snapshot).map_err(DurableStateError::from)?;
            operation(&isolated).map_err(Into::into)
        })
    }

    /// Creates and durably publishes a new context space.
    pub fn create_space(
        &self,
        request: CreateSpaceRequest,
        cancellation: &CancellationToken,
    ) -> Result<ContextCommit, DurableStateError> {
        self.transact(cancellation, move |service| {
            service.create_space(request).map_err(Into::into)
        })
    }

    /// Returns the current immutable head from reconciled durable state.
    pub fn head(&self, space_id: &ContextSpaceId) -> Result<ContextCommit, DurableStateError> {
        self.read(|service| service.head(space_id).map_err(Into::into))
    }

    /// Returns the complete immutable commit log from reconciled durable state.
    pub fn log(&self, space_id: &ContextSpaceId) -> Result<Vec<ContextCommit>, DurableStateError> {
        self.read(|service| service.log(space_id).map_err(Into::into))
    }

    /// Creates and durably publishes an empty private overlay.
    pub fn create_overlay(
        &self,
        overlay: Overlay,
        cancellation: &CancellationToken,
    ) -> Result<(), DurableStateError> {
        self.transact(cancellation, move |service| {
            service.create_overlay(overlay).map_err(Into::into)
        })
    }

    /// Creates and durably publishes an overlay against an exact head revision.
    pub fn create_overlay_at_revision(
        &self,
        overlay: Overlay,
        expected_head: ExpectedRevision,
        cancellation: &CancellationToken,
    ) -> Result<(), DurableStateError> {
        self.transact(cancellation, move |service| {
            service
                .create_overlay_at_revision(overlay, expected_head)
                .map_err(Into::into)
        })
    }

    /// Adds or replaces one private proposal and durably publishes the result.
    pub fn propose(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        actor_id: &RecordId,
        proposal: ProposedMutation,
        cancellation: &CancellationToken,
    ) -> Result<(), DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .propose(space_id, overlay_id, actor_id, proposal)
                .map_err(Into::into)
        })
    }

    /// Returns a base or owner-private overlay view from reconciled durable state.
    pub fn view(
        &self,
        space_id: &ContextSpaceId,
        actor_id: &RecordId,
        overlay_id: Option<&RecordId>,
    ) -> Result<SpaceView, DurableStateError> {
        self.read(|service| {
            service
                .view(space_id, actor_id, overlay_id)
                .map_err(Into::into)
        })
    }

    /// Discards one owner-private overlay and durably publishes the removal.
    pub fn discard_overlay(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        actor_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<(), DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .discard_overlay(space_id, overlay_id, actor_id)
                .map_err(Into::into)
        })
    }

    /// Performs an optimistic merge and durably publishes any resulting state transition.
    pub fn publish(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        request: PublishRequest,
        cancellation: &CancellationToken,
    ) -> Result<PublishOutcome, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .publish(space_id, overlay_id, request)
                .map_err(Into::into)
        })
    }

    /// Lists durable unresolved conflicts visible to one exact overlay owner.
    pub fn list_conflicts(
        &self,
        space_id: &ContextSpaceId,
        actor_id: &RecordId,
    ) -> Result<Vec<StoredMergeConflict>, DurableStateError> {
        self.read(|service| {
            service
                .list_conflicts(space_id, actor_id)
                .map_err(Into::into)
        })
    }

    /// Resolves and durably publishes one private-overlay conflict decision.
    pub fn resolve_conflict(
        &self,
        space_id: &ContextSpaceId,
        conflict_id: &RecordId,
        request: ResolveConflictRequest,
        cancellation: &CancellationToken,
    ) -> Result<ConflictResolutionReceipt, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .resolve_conflict(space_id, conflict_id, request)
                .map_err(Into::into)
        })
    }

    /// Resolves one conflict and publishes its overlay in one durable snapshot transaction.
    pub fn resolve_conflict_and_publish(
        &self,
        space_id: &ContextSpaceId,
        conflict_id: &RecordId,
        resolve: ResolveConflictRequest,
        publish: PublishRequest,
        cancellation: &CancellationToken,
    ) -> Result<(ConflictResolutionReceipt, PublishOutcome), DurableStateError> {
        self.transact(cancellation, |service| {
            let receipt = service.resolve_conflict(space_id, conflict_id, resolve)?;
            let outcome = service.publish(space_id, &receipt.overlay_id, publish)?;
            Ok((receipt, outcome))
        })
    }

    /// Polls a bounded project-scoped event page from reconciled durable state.
    pub fn poll_events(
        &self,
        space_id: &ContextSpaceId,
        authorized_projects: &BTreeSet<RecordId>,
        after: EventCursor,
        limit: usize,
    ) -> Result<EventPage, DurableStateError> {
        self.read(|service| {
            service
                .poll_events(space_id, authorized_projects, after, limit)
                .map_err(Into::into)
        })
    }

    /// Resolves one disclosure-visible event identity to its durable resume cursor.
    pub fn event_cursor_for_id(
        &self,
        space_id: &ContextSpaceId,
        authorized_projects: &BTreeSet<RecordId>,
        event_id: &RecordId,
    ) -> Result<EventCursor, DurableStateError> {
        self.read(|service| {
            service
                .event_cursor_for_id(space_id, authorized_projects, event_id)
                .map_err(Into::into)
        })
    }

    /// Appends a resource-neutral commit and durably publishes its ordered events.
    pub fn append_events(
        &self,
        space_id: &ContextSpaceId,
        project_id: RecordId,
        request: PublishRequest,
        events: Vec<CoordinationEvent>,
        cancellation: &CancellationToken,
    ) -> Result<ContextCommit, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .append_events(space_id, project_id, request, events)
                .map_err(Into::into)
        })
    }

    /// Acquires and durably publishes a fenced advisory lease.
    pub fn acquire_lease(
        &self,
        space_id: &ContextSpaceId,
        request: AcquireLeaseRequest,
        cancellation: &CancellationToken,
    ) -> Result<FencedLease, DurableStateError> {
        self.transact(cancellation, |service| {
            service.acquire_lease(space_id, request).map_err(Into::into)
        })
    }

    /// Renews and durably publishes a current fenced lease.
    pub fn renew_lease(
        &self,
        space_id: &ContextSpaceId,
        resource_id: &VersionId,
        request: LeaseMutationRequest,
        cancellation: &CancellationToken,
    ) -> Result<FencedLease, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .renew_lease(space_id, resource_id, request)
                .map_err(Into::into)
        })
    }

    /// Releases and durably publishes a current fenced lease.
    pub fn release_lease(
        &self,
        space_id: &ContextSpaceId,
        resource_id: &VersionId,
        request: LeaseMutationRequest,
        cancellation: &CancellationToken,
    ) -> Result<FencedLease, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .release_lease(space_id, resource_id, request)
                .map_err(Into::into)
        })
    }

    /// Verifies a current holder and fence from reconciled durable state.
    pub fn verify_fence(
        &self,
        space_id: &ContextSpaceId,
        resource_id: &VersionId,
        holder_id: &RecordId,
        fencing_token: u64,
        now: &UtcTimestamp,
    ) -> Result<(), DurableStateError> {
        self.read(|service| {
            service
                .verify_fence(space_id, resource_id, holder_id, fencing_token, now)
                .map_err(Into::into)
        })
    }

    /// Forks and durably publishes a resumable focus branch.
    pub fn fork_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: RecordId,
        label: impl Into<String>,
        offline: bool,
        cancellation: &CancellationToken,
    ) -> Result<FocusBranch, DurableStateError> {
        let label = label.into();
        self.transact(cancellation, |service| {
            service
                .fork_focus(space_id, branch_id, label, offline)
                .map_err(Into::into)
        })
    }

    /// Forks and durably publishes a focus branch against an exact head revision.
    pub fn fork_focus_at_revision(
        &self,
        space_id: &ContextSpaceId,
        branch_id: RecordId,
        label: impl Into<String>,
        offline: bool,
        expected_head: ExpectedRevision,
        cancellation: &CancellationToken,
    ) -> Result<FocusBranch, DurableStateError> {
        let label = label.into();
        self.transact(cancellation, |service| {
            service
                .fork_focus_at_revision(space_id, branch_id, label, offline, expected_head)
                .map_err(Into::into)
        })
    }

    /// Checkpoints and durably publishes a focus branch at the current head.
    pub fn checkpoint_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<FocusBranch, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .checkpoint_focus(space_id, branch_id)
                .map_err(Into::into)
        })
    }

    /// Checkpoints and durably publishes a focus branch against an exact head revision.
    pub fn checkpoint_focus_at_revision(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
        expected_head: ExpectedRevision,
        cancellation: &CancellationToken,
    ) -> Result<FocusBranch, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .checkpoint_focus_at_revision(space_id, branch_id, expected_head)
                .map_err(Into::into)
        })
    }

    /// Switches and durably publishes the active focus branch.
    pub fn switch_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<FocusBranch, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .switch_focus(space_id, branch_id)
                .map_err(Into::into)
        })
    }

    /// Marks an offline branch resumed and durably publishes that transition.
    pub fn resume_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<FocusBranch, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .resume_focus(space_id, branch_id)
                .map_err(Into::into)
        })
    }

    /// Creates and durably publishes a disclosure-authorized directional project link.
    pub fn link_project(
        &self,
        space_id: &ContextSpaceId,
        link: ProjectLink,
        can_disclose: impl Fn(&RecordId) -> bool,
        cancellation: &CancellationToken,
    ) -> Result<ProjectLinkPreview, DurableStateError> {
        self.transact(cancellation, |service| {
            service
                .link_project(space_id, link, can_disclose)
                .map_err(Into::into)
        })
    }

    /// Returns a currently disclosure-authorized project-link preview.
    pub fn project_link_preview(
        &self,
        space_id: &ContextSpaceId,
        from_project_id: &RecordId,
        to_project_id: &RecordId,
        can_disclose: impl Fn(&RecordId) -> bool,
    ) -> Result<ProjectLinkPreview, DurableStateError> {
        self.read(|service| {
            service
                .project_link_preview(space_id, from_project_id, to_project_id, can_disclose)
                .map_err(Into::into)
        })
    }

    /// Applies directional project contribution caps from reconciled durable state.
    pub fn cap_project_contributions(
        &self,
        space_id: &ContextSpaceId,
        active_project_id: &RecordId,
        authorized_projects: &BTreeSet<RecordId>,
        candidates: Vec<ProjectContribution>,
    ) -> Result<Vec<ProjectContribution>, DurableStateError> {
        self.read(|service| {
            service
                .cap_project_contributions(
                    space_id,
                    active_project_id,
                    authorized_projects,
                    candidates,
                )
                .map_err(Into::into)
        })
    }

    /// Validates a child delta and durably publishes all accepted overlay proposals atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn merge_child_result(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        parent_id: &RecordId,
        capsule: &HandoffCapsule,
        acceptance: &HandoffAcceptance,
        delta: &cigar_protocol::HandoffDelta,
        expected_base_commit_id: &VersionId,
        mappings: &[ResultMergeMapping],
        currently_authorized: impl Fn(&VersionId) -> bool,
        cancellation: &CancellationToken,
    ) -> Result<ResultMergeReceipt, DurableStateError> {
        self.transact(cancellation, |service| {
            merge_child_result(
                service,
                space_id,
                overlay_id,
                parent_id,
                capsule,
                acceptance,
                delta,
                expected_base_commit_id,
                mappings,
                currently_authorized,
            )
            .map_err(Into::into)
        })
    }

    /// Atomically proposes one retained child result and explicitly publishes its parent overlay.
    ///
    /// A conflict outcome and its stable durable identities are committed in the same root-last
    /// snapshot as the child proposals, so a process failure cannot strand a partially merged
    /// overlay between proposal and publication.
    #[allow(clippy::too_many_arguments)]
    pub fn merge_child_result_and_publish(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        parent_id: &RecordId,
        capsule: &HandoffCapsule,
        acceptance: &HandoffAcceptance,
        delta: &cigar_protocol::HandoffDelta,
        expected_base_commit_id: &VersionId,
        mappings: &[ResultMergeMapping],
        currently_authorized: impl Fn(&VersionId) -> bool,
        publish: PublishRequest,
        cancellation: &CancellationToken,
    ) -> Result<(ResultMergeReceipt, PublishOutcome, Vec<RecordId>), DurableStateError> {
        self.transact(cancellation, |service| {
            let receipt = merge_child_result(
                service,
                space_id,
                overlay_id,
                parent_id,
                capsule,
                acceptance,
                delta,
                expected_base_commit_id,
                mappings,
                currently_authorized,
            )?;
            let outcome = service.publish(space_id, overlay_id, publish)?;
            let conflict_ids = if matches!(outcome, PublishOutcome::Conflicted(_)) {
                service
                    .list_conflicts(space_id, parent_id)?
                    .into_iter()
                    .filter(|conflict| &conflict.overlay_id == overlay_id)
                    .map(|conflict| conflict.conflict_id)
                    .collect()
            } else {
                Vec::new()
            };
            Ok((receipt, outcome, conflict_ids))
        })
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&ContextSpaceService) -> Result<T, DurableStateError>,
    ) -> Result<T, DurableStateError> {
        let state = self.state.lock().map_err(|_error| unavailable_state())?;
        ensure_healthy(state.healthy)?;
        operation(&state.service)
    }

    fn transact<T>(
        &self,
        cancellation: &CancellationToken,
        operation: impl FnOnce(&ContextSpaceService) -> Result<T, DurableStateError>,
    ) -> Result<T, DurableStateError> {
        let mut state = self.state.lock().map_err(|_error| unavailable_state())?;
        ensure_healthy(state.healthy)?;
        let prior = match state.service.export_snapshot() {
            Ok(bytes) => bytes,
            Err(_error) => {
                state.healthy = false;
                return Err(invalid_state());
            }
        };
        let result = match operation(&state.service) {
            Ok(result) => result,
            Err(error) => {
                restore_space(&mut state, &prior)?;
                return Err(error);
            }
        };
        let attempted = match state.service.export_snapshot() {
            Ok(bytes) => bytes,
            Err(_error) => {
                restore_space(&mut state, &prior)?;
                return Err(invalid_state());
            }
        };
        if attempted == prior {
            return Ok(result);
        }
        let expected = state.generation;
        match self.store.publish(expected, &attempted, cancellation) {
            Ok(generation) => {
                state.generation = generation;
                Ok(result)
            }
            Err(error) => match self.store.load(&CancellationToken::default()) {
                Ok(loaded)
                    if loaded.version == expected.saturating_add(1)
                        && loaded.bytes.as_deref() == Some(attempted.as_slice()) =>
                {
                    state.generation = loaded.version;
                    Ok(result)
                }
                Ok(loaded) => match install_space(&mut state, loaded) {
                    Ok(()) => Err(error.into()),
                    Err(restore_error) => Err(restore_error),
                },
                Err(_recovery_error) => {
                    let _restore_result = restore_space(&mut state, &prior);
                    state.healthy = false;
                    Err(unavailable_state())
                }
            },
        }
    }
}

impl fmt::Debug for DurableContextSpaceService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableContextSpaceService")
            .field("repository", &"[INJECTED]")
            .field("tenant_scope", &"[BOUND]")
            .finish_non_exhaustive()
    }
}

struct HandoffSnapshotState {
    service: HandoffService,
    generation: u64,
    healthy: bool,
}

/// Transactional signed-handoff service with durable capsules, receipts, and replay guards.
pub struct DurableHandoffService {
    store: DurableSnapshotStore,
    provider: Arc<dyn KeyProvider>,
    state: Mutex<HandoffSnapshotState>,
}

impl DurableHandoffService {
    /// Opens the latest tenant-scoped handoff state around a scoped signing provider.
    pub fn open_authenticated(
        repository: Arc<dyn ServiceRepository>,
        authenticator: Arc<dyn DurableSnapshotAuthenticator>,
        tenant_id: RecordId,
        provider: Arc<dyn KeyProvider>,
        cancellation: &CancellationToken,
    ) -> Result<Self, DurableStateError> {
        let store = DurableSnapshotStore::new_authenticated(
            repository,
            authenticator,
            tenant_id,
            HANDOFF_SNAPSHOT_KIND,
        );
        let loaded = store.load(cancellation)?;
        let service = match loaded.bytes {
            Some(bytes) => HandoffService::from_snapshot(provider.clone(), &bytes)
                .map_err(|_error| invalid_state())?,
            None if loaded.version == 0 => HandoffService::new(provider.clone()),
            None => return Err(invalid_state()),
        };
        Ok(Self {
            store,
            provider,
            state: Mutex::new(HandoffSnapshotState {
                service,
                generation: loaded.version,
                healthy: true,
            }),
        })
    }

    #[cfg(test)]
    fn open(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        provider: Arc<dyn KeyProvider>,
        cancellation: &CancellationToken,
    ) -> Result<Self, DurableStateError> {
        Self::open_authenticated(
            repository,
            test_snapshot_authenticator(),
            tenant_id,
            provider,
            cancellation,
        )
    }

    /// Returns the latest reconciled root generation.
    pub fn generation(&self) -> Result<u64, DurableStateError> {
        let state = self.state.lock().map_err(|_error| unavailable_state())?;
        ensure_healthy(state.healthy)?;
        Ok(state.generation)
    }

    /// Runs a handoff operation against an isolated exact clone without publishing mutations.
    pub fn simulate<T>(
        &self,
        operation: impl FnOnce(&HandoffService) -> Result<T, HandoffError>,
    ) -> Result<T, DurableStateError> {
        let provider = self.provider.clone();
        self.read(|service| {
            let snapshot = service.export_snapshot().map_err(DurableStateError::from)?;
            let isolated = HandoffService::from_snapshot(provider, &snapshot)
                .map_err(DurableStateError::from)?;
            operation(&isolated).map_err(Into::into)
        })
    }

    /// Computes the exact attenuation preview without consuming durable state.
    pub fn preview_creation(
        &self,
        request: &CreateHandoffRequest,
    ) -> Result<HandoffCreationPreview, DurableStateError> {
        self.read(|service| service.preview_creation(request).map_err(Into::into))
    }

    /// Signs and durably publishes one unique handoff capsule.
    pub fn create(
        &self,
        request: CreateHandoffRequest,
        cancellation: &CancellationToken,
    ) -> Result<(HandoffCapsule, HandoffCreationPreview), DurableStateError> {
        self.transact(cancellation, move |service| {
            service.create(request).map_err(Into::into)
        })
    }

    /// Returns a persisted capsule only to its issuer or resolved recipient.
    pub fn persisted_capsule(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<HandoffCapsule, DurableStateError> {
        self.read(|service| {
            service
                .persisted_capsule(handoff_id, actor_id, actor_roles)
                .map_err(Into::into)
        })
    }

    /// Returns the exact retained creation preview to a visible actor.
    pub fn persisted_preview(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<HandoffCreationPreview, DurableStateError> {
        self.read(|service| {
            service
                .persisted_preview(handoff_id, actor_id, actor_roles)
                .map_err(Into::into)
        })
    }

    /// Returns the latest persisted per-capsule revision to a visible actor.
    pub fn handoff_revision(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<u64, DurableStateError> {
        self.read(|service| {
            service
                .handoff_revision(handoff_id, actor_id, actor_roles)
                .map_err(Into::into)
        })
    }

    /// Revokes one handoff and durably publishes its stable record and event.
    pub fn revoke(
        &self,
        request: RevokeHandoffRequest,
        cancellation: &CancellationToken,
    ) -> Result<HandoffRevocation, DurableStateError> {
        self.transact(cancellation, move |service| {
            service.revoke(request).map_err(Into::into)
        })
    }

    /// Returns an authoritative persisted revocation to a visible actor.
    pub fn persisted_revocation(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<Option<HandoffRevocation>, DurableStateError> {
        self.read(|service| {
            service
                .persisted_revocation(handoff_id, actor_id, actor_roles)
                .map_err(Into::into)
        })
    }

    /// Reauthorizes a capsule without consuming its durable replay guard.
    pub fn inspect_acceptance(
        &self,
        request: &AcceptHandoffRequest,
        authorize_reference: impl Fn(&VersionId) -> bool,
    ) -> Result<AcceptanceInspection, DurableStateError> {
        self.read(|service| {
            service
                .inspect_acceptance(request, authorize_reference)
                .map_err(Into::into)
        })
    }

    /// Accepts once and atomically publishes its receipt, topics, and replay guard.
    pub fn accept(
        &self,
        request: AcceptHandoffRequest,
        authorize_reference: impl Fn(&VersionId) -> bool,
        compile_recipient_bundle: impl FnOnce(
            &AcceptedHandoffContext,
        ) -> Result<RecipientBundleReceipt, HandoffError>,
        cancellation: &CancellationToken,
    ) -> Result<HandoffAcceptance, DurableStateError> {
        self.transact(cancellation, move |service| {
            service
                .accept(request, authorize_reference, compile_recipient_bundle)
                .map_err(Into::into)
        })
    }

    /// Returns one persisted acceptance only to its authenticated recipient.
    pub fn persisted_acceptance(
        &self,
        acceptance_id: &RecordId,
        recipient_id: &RecordId,
    ) -> Result<HandoffAcceptance, DurableStateError> {
        self.read(|service| {
            service
                .persisted_acceptance(acceptance_id, recipient_id)
                .map_err(Into::into)
        })
    }

    /// Resolves the newest durable acceptance matching an exact producer and result base.
    pub fn acceptance_for_result(
        &self,
        handoff_id: &RecordId,
        recipient_id: &RecordId,
        base_commit_id: &VersionId,
    ) -> Result<HandoffAcceptance, DurableStateError> {
        self.read(|service| {
            service
                .acceptance_for_result(handoff_id, recipient_id, base_commit_id)
                .map_err(Into::into)
        })
    }

    /// Returns the exact signed topics retained with one durable acceptance.
    pub fn subscription_topics(
        &self,
        acceptance_id: &RecordId,
    ) -> Result<Vec<cigar_protocol::CoordinationTopic>, DurableStateError> {
        self.read(|service| {
            service
                .subscription_topics(acceptance_id)
                .map_err(Into::into)
        })
    }

    /// Validates and durably publishes one immutable child result and proposal event.
    pub fn record_result(
        &self,
        request: RecordHandoffResultRequest,
        cancellation: &CancellationToken,
    ) -> Result<HandoffResultReceipt, DurableStateError> {
        self.transact(cancellation, move |service| {
            service.record_result(request).map_err(Into::into)
        })
    }

    /// Returns one durable child result to its producer or capsule issuer.
    pub fn persisted_result(
        &self,
        delta_id: &RecordId,
        actor_id: &RecordId,
    ) -> Result<HandoffResultReceipt, DurableStateError> {
        self.read(|service| {
            service
                .persisted_result(delta_id, actor_id)
                .map_err(Into::into)
        })
    }

    /// Returns the durable child results visible to an issuer or exact producer.
    pub fn persisted_results(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
    ) -> Result<Vec<HandoffResultReceipt>, DurableStateError> {
        self.read(|service| {
            service
                .persisted_results(handoff_id, actor_id)
                .map_err(Into::into)
        })
    }

    /// Returns complete retained result material only after signature and revocation checks.
    pub fn verified_merge_material(
        &self,
        delta_id: &RecordId,
        issuer_id: &RecordId,
        tenant: &str,
        revoked_principals: &BTreeSet<RecordId>,
        revoked_key_ids: &BTreeSet<String>,
    ) -> Result<HandoffMergeMaterial, DurableStateError> {
        self.read(|service| {
            service
                .verified_merge_material(
                    delta_id,
                    issuer_id,
                    tenant,
                    revoked_principals,
                    revoked_key_ids,
                )
                .map_err(Into::into)
        })
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&HandoffService) -> Result<T, DurableStateError>,
    ) -> Result<T, DurableStateError> {
        let state = self.state.lock().map_err(|_error| unavailable_state())?;
        ensure_healthy(state.healthy)?;
        operation(&state.service)
    }

    fn transact<T>(
        &self,
        cancellation: &CancellationToken,
        operation: impl FnOnce(&HandoffService) -> Result<T, DurableStateError>,
    ) -> Result<T, DurableStateError> {
        let mut state = self.state.lock().map_err(|_error| unavailable_state())?;
        ensure_healthy(state.healthy)?;
        let prior = match state.service.export_snapshot() {
            Ok(bytes) => bytes,
            Err(_error) => {
                state.healthy = false;
                return Err(unavailable_state());
            }
        };
        let result = match operation(&state.service) {
            Ok(result) => result,
            Err(error) => {
                restore_handoff(&mut state, &self.provider, &prior)?;
                return Err(error);
            }
        };
        let attempted = match state.service.export_snapshot() {
            Ok(bytes) => bytes,
            Err(_error) => {
                restore_handoff(&mut state, &self.provider, &prior)?;
                return Err(invalid_state());
            }
        };
        if attempted == prior {
            return Ok(result);
        }
        let expected = state.generation;
        match self.store.publish(expected, &attempted, cancellation) {
            Ok(generation) => {
                state.generation = generation;
                Ok(result)
            }
            Err(error) => match self.store.load(&CancellationToken::default()) {
                Ok(loaded)
                    if loaded.version == expected.saturating_add(1)
                        && loaded.bytes.as_deref() == Some(attempted.as_slice()) =>
                {
                    state.generation = loaded.version;
                    Ok(result)
                }
                Ok(loaded) => match install_handoff(&mut state, &self.provider, loaded) {
                    Ok(()) => Err(error.into()),
                    Err(restore_error) => Err(restore_error),
                },
                Err(_recovery_error) => {
                    let _restore_result = restore_handoff(&mut state, &self.provider, &prior);
                    state.healthy = false;
                    Err(unavailable_state())
                }
            },
        }
    }
}

impl fmt::Debug for DurableHandoffService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableHandoffService")
            .field("repository", &"[INJECTED]")
            .field("provider", &"[INJECTED]")
            .field("tenant_scope", &"[BOUND]")
            .finish_non_exhaustive()
    }
}

fn install_space(
    state: &mut SpaceSnapshotState,
    loaded: LoadedSnapshot,
) -> Result<(), DurableStateError> {
    state.healthy = false;
    let service = match loaded.bytes {
        Some(bytes) => {
            ContextSpaceService::from_snapshot(&bytes).map_err(|_error| invalid_state())?
        }
        None if loaded.version == 0 => ContextSpaceService::new(),
        None => return Err(invalid_state()),
    };
    state.service = service;
    state.generation = loaded.version;
    state.healthy = true;
    Ok(())
}

fn restore_space(state: &mut SpaceSnapshotState, bytes: &[u8]) -> Result<(), DurableStateError> {
    state.healthy = false;
    state.service = ContextSpaceService::from_snapshot(bytes).map_err(|_error| invalid_state())?;
    state.healthy = true;
    Ok(())
}

fn install_handoff(
    state: &mut HandoffSnapshotState,
    provider: &Arc<dyn KeyProvider>,
    loaded: LoadedSnapshot,
) -> Result<(), DurableStateError> {
    state.healthy = false;
    let service = match loaded.bytes {
        Some(bytes) => HandoffService::from_snapshot(provider.clone(), &bytes)
            .map_err(|_error| invalid_state())?,
        None if loaded.version == 0 => HandoffService::new(provider.clone()),
        None => return Err(invalid_state()),
    };
    state.service = service;
    state.generation = loaded.version;
    state.healthy = true;
    Ok(())
}

fn restore_handoff(
    state: &mut HandoffSnapshotState,
    provider: &Arc<dyn KeyProvider>,
    bytes: &[u8],
) -> Result<(), DurableStateError> {
    state.healthy = false;
    state.service =
        HandoffService::from_snapshot(provider.clone(), bytes).map_err(|_error| invalid_state())?;
    state.healthy = true;
    Ok(())
}

fn ensure_healthy(healthy: bool) -> Result<(), DurableStateError> {
    if healthy {
        Ok(())
    } else {
        Err(unavailable_state())
    }
}

const fn invalid_state() -> DurableStateError {
    DurableStateError::new(DurableStateErrorCode::Snapshot(
        DurableSnapshotErrorCode::InvalidSnapshot,
    ))
}

const fn unavailable_state() -> DurableStateError {
    DurableStateError::new(DurableStateErrorCode::Snapshot(
        DurableSnapshotErrorCode::Unavailable,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, MemoryKeyProvider,
    };
    use cigar_policy::EffectiveCapabilities;
    use cigar_protocol::{
        Budget, Capability, CoordinationEventKind, CoordinationTopic, ExtensionMap, HandoffDelta,
        HandoffReferences, LaneKind, LeaseKind, RecipientSelector, ResultClaim, SchemaVersion,
    };
    use cigar_space::SpaceHierarchy;
    use cigar_store::{InMemoryStore, SqliteFailpoint, SqliteStore};
    use std::collections::BTreeMap;
    use std::sync::Barrier;
    use std::thread;
    use tempfile::tempdir;

    fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn space_id(value: u64) -> Result<ContextSpaceId, Box<dyn std::error::Error>> {
        Ok(ContextSpaceId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
        let hash = Sha256::digest(value.to_be_bytes());
        let mut encoded = String::from("1220");
        for byte in hash {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(VersionId::new(encoded)?)
    }

    fn content(value: u64) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(version(value)?.as_str())?)
    }

    fn time(second: u8) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
        Ok(UtcTimestamp::parse_rfc3339(&format!(
            "2026-07-11T12:00:{second:02}Z"
        ))?)
    }

    fn create_space_request(id: u64) -> Result<CreateSpaceRequest, Box<dyn std::error::Error>> {
        Ok(CreateSpaceRequest {
            space_id: space_id(id)?,
            hierarchy: SpaceHierarchy {
                tenant_id: record(10)?,
                workspace_id: record(11)?,
                active_project_id: record(12)?,
                branch_id: record(13)?,
                task_id: record(14)?,
                session_id: record(15)?,
            },
            author_id: record(16)?,
            purpose: format!("durable space {id}"),
            policy_snapshot_digest: content(17)?,
            committed_at: time(1)?,
            event_id: record(id.saturating_add(1_000))?,
        })
    }

    fn signing_provider() -> Result<(Arc<MemoryKeyProvider>, KeyRef), Box<dyn std::error::Error>> {
        let provider = Arc::new(MemoryKeyProvider::default());
        let metadata = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: time(0)?.unix_nanos(),
            activated_at: time(0)?.unix_nanos(),
        })?;
        Ok((provider, metadata.key_ref))
    }

    fn effective(
        subject_id: RecordId,
        grant_id: RecordId,
        capabilities: BTreeSet<Capability>,
        project_ids: BTreeSet<RecordId>,
    ) -> Result<EffectiveCapabilities, Box<dyn std::error::Error>> {
        Ok(EffectiveCapabilities {
            tenant: "tenant-a".to_owned(),
            subject_id,
            grant_id,
            capabilities,
            project_ids,
            processors: BTreeSet::from(["local".to_owned()]),
            expires_at: time(50)?,
        })
    }

    fn handoff_creation(
        key_ref: KeyRef,
        handoff_number: u64,
    ) -> Result<CreateHandoffRequest, Box<dyn std::error::Error>> {
        let issuer = record(100)?;
        let recipient = record(101)?;
        let project = record(102)?;
        Ok(CreateHandoffRequest {
            handoff_id: record(handoff_number)?,
            issuer_effective: effective(
                issuer,
                record(103)?,
                BTreeSet::from([Capability::CreateHandoff, Capability::ReadContext]),
                BTreeSet::from([project.clone()]),
            )?,
            recipient: RecipientSelector::Principal(recipient),
            task: "Verify the durable handoff".to_owned(),
            acceptance_criteria: vec!["Attach typed evidence".to_owned()],
            requested_projects: BTreeSet::from([project.clone()]),
            requested_capabilities: BTreeSet::from([Capability::ReadContext]),
            policy_allowed_projects: BTreeSet::from([project]),
            policy_allowed_capabilities: BTreeSet::from([Capability::ReadContext]),
            budget: Budget {
                total_input_tokens: 100,
                output_reserve_tokens: 20,
                lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 100)]),
            },
            topics: BTreeSet::from([
                CoordinationTopic::AtomInvalidation,
                CoordinationTopic::PolicySnapshot,
            ]),
            references: HandoffReferences {
                sources: vec![version(104)?],
                states: vec![version(105)?],
                decisions: Vec::new(),
                artifacts: Vec::new(),
                uncertainties: Vec::new(),
                effects: Vec::new(),
            },
            bundle_id: version(106)?,
            audience: "durable-test".to_owned(),
            created_at: time(10)?,
            expires_at: time(40)?,
            nonce: format!("nonce-{handoff_number}").into_bytes(),
            reusable: false,
            issuer_key_ref: key_ref,
        })
    }

    fn acceptance_request(
        capsule: HandoffCapsule,
        acceptance_number: u64,
    ) -> Result<AcceptHandoffRequest, Box<dyn std::error::Error>> {
        let recipient = record(101)?;
        let project = record(102)?;
        Ok(AcceptHandoffRequest {
            capsule,
            expected_revision: ExpectedRevision(1),
            acceptance_id: record(acceptance_number)?,
            recipient_id: recipient.clone(),
            recipient_roles: BTreeSet::new(),
            expected_audience: "durable-test".to_owned(),
            tenant: "tenant-a".to_owned(),
            now: time(20)?,
            recipient_effective: effective(
                recipient,
                record(107)?,
                BTreeSet::from([Capability::ReadContext]),
                BTreeSet::from([project]),
            )?,
            policy_allowed_capabilities: BTreeSet::from([Capability::ReadContext]),
            policy_digest: content(108)?,
            revoked_principals: BTreeSet::new(),
            revoked_key_ids: BTreeSet::new(),
            target_allowed: true,
            accepted_at: time(20)?,
        })
    }

    fn recipient_bundle_receipt(
        capsule: &HandoffCapsule,
        bundle_number: u64,
    ) -> Result<RecipientBundleReceipt, HandoffError> {
        let bundle_id = version(bundle_number).map_err(|_error| HandoffError::Unavailable)?;
        let digest = ContentDigest::new(bundle_id.as_str().to_owned())
            .map_err(|_error| HandoffError::Unavailable)?;
        Ok(RecipientBundleReceipt {
            bundle_id,
            source_bundle_id: capsule.bundle_id.clone(),
            target_plan_id: record(bundle_number.saturating_add(10_000))
                .map_err(|_error| HandoffError::Unavailable)?,
            target_plan_revision: 1,
            target_plan_digest: digest.clone(),
            derivation_digest: digest,
        })
    }

    fn handoff_delta(
        capsule: &HandoffCapsule,
        acceptance: &HandoffAcceptance,
        delta_number: u64,
    ) -> Result<HandoffDelta, Box<dyn std::error::Error>> {
        Ok(HandoffDelta {
            schema_version: SchemaVersion::new("cigar.handoff-delta", 1)?,
            delta_id: record(delta_number)?,
            handoff_id: capsule.handoff_id.clone(),
            base_commit_id: acceptance.bundle_id.clone(),
            producer_id: acceptance.recipient_id.clone(),
            claims: vec![ResultClaim {
                claim: "Durable delegated result".to_owned(),
                evidence: vec![version(delta_number.saturating_add(1))?],
            }],
            decisions: Vec::new(),
            artifacts: vec![version(delta_number.saturating_add(2))?],
            source_changes: Vec::new(),
            verifier_receipts: Vec::new(),
            unresolved_questions: Vec::new(),
            blockers: Vec::new(),
            effect_references: Vec::new(),
            requested_followup_capabilities: Vec::new(),
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn sqlite_restart_retains_space_commit_and_failed_publication_rolls_back()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("space.sqlite3");
        let tenant = record(1)?;
        let first = create_space_request(200)?;
        let second = create_space_request(201)?;
        let store = Arc::new(SqliteStore::open(&path)?);
        let service = DurableContextSpaceService::open(
            store.clone(),
            tenant.clone(),
            &CancellationToken::default(),
        )?;
        let first_commit = service.create_space(first.clone(), &CancellationToken::default())?;
        assert_eq!(service.generation()?, 1);

        store.fail_next_commit();
        let failed = service.create_space(second.clone(), &CancellationToken::default());
        assert_eq!(
            failed.map_err(|error| error.code()),
            Err(DurableStateErrorCode::Snapshot(
                DurableSnapshotErrorCode::InjectedAbort
            ))
        );
        assert_eq!(
            service.head(&second.space_id).map_err(|error| error.code()),
            Err(DurableStateErrorCode::Space(SpaceError::NotFound))
        );
        assert_eq!(service.head(&first.space_id)?, first_commit);
        drop(service);
        drop(store);

        let reopened_store = Arc::new(SqliteStore::open(&path)?);
        let reopened = DurableContextSpaceService::open(
            reopened_store,
            tenant,
            &CancellationToken::default(),
        )?;
        assert_eq!(reopened.generation()?, 1);
        assert_eq!(reopened.head(&first.space_id)?, first_commit);
        assert_eq!(
            reopened
                .head(&second.space_id)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Space(SpaceError::NotFound))
        );
        reopened.create_space(second.clone(), &CancellationToken::default())?;
        assert_eq!(reopened.generation()?, 2);
        assert_eq!(reopened.head(&second.space_id)?.sequence, 1);
        Ok(())
    }

    #[test]
    fn sqlite_restart_retains_scoped_event_resume_and_monotonic_lease_fences()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("space-coordination.sqlite3");
        let tenant = record(20)?;
        let request = create_space_request(260)?;
        let space_id = request.space_id.clone();
        let visible_project = request.hierarchy.active_project_id.clone();
        let hidden_project = record(261)?;
        let holder = request.author_id.clone();
        let replacement_holder = record(262)?;
        let resource = version(263)?;

        let store = Arc::new(SqliteStore::open(&path)?);
        let service = DurableContextSpaceService::open(
            store.clone(),
            tenant.clone(),
            &CancellationToken::default(),
        )?;
        let genesis = service.create_space(request, &CancellationToken::default())?;
        service.append_events(
            &space_id,
            hidden_project.clone(),
            PublishRequest {
                expected_head: ExpectedRevision(1),
                actor_id: holder.clone(),
                purpose: "hidden project checkpoint".to_owned(),
                policy_snapshot_digest: content(264)?,
                committed_at: time(2)?,
                event_id: record(264)?,
            },
            vec![CoordinationEvent {
                event_id: record(265)?,
                kind: CoordinationEventKind::TaskCheckpointed,
                payload_digest: content(265)?,
            }],
            &CancellationToken::default(),
        )?;
        service.append_events(
            &space_id,
            visible_project.clone(),
            PublishRequest {
                expected_head: ExpectedRevision(2),
                actor_id: holder.clone(),
                purpose: "visible project checkpoint".to_owned(),
                policy_snapshot_digest: content(266)?,
                committed_at: time(3)?,
                event_id: record(266)?,
            },
            vec![CoordinationEvent {
                event_id: record(267)?,
                kind: CoordinationEventKind::TaskCheckpointed,
                payload_digest: content(267)?,
            }],
            &CancellationToken::default(),
        )?;

        let visible = BTreeSet::from([visible_project.clone()]);
        let first_page = service.poll_events(&space_id, &visible, EventCursor(0), 1)?;
        assert_eq!(first_page.events.len(), 1);
        assert_eq!(
            first_page.events.first().map(|event| &event.event.event_id),
            genesis.events.first().map(|event| &event.event_id)
        );
        assert_eq!(first_page.resume_cursor, EventCursor(2));
        assert!(first_page.has_more);
        let resumed = service.poll_events(&space_id, &visible, first_page.resume_cursor, 1)?;
        assert_eq!(resumed.events.len(), 1);
        assert_eq!(
            resumed.events.first().map(|event| &event.event.event_id),
            Some(&record(267)?)
        );
        assert_eq!(resumed.resume_cursor, EventCursor(3));
        assert!(!resumed.has_more);
        assert_eq!(
            service
                .event_cursor_for_id(&space_id, &visible, &record(265)?)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Space(SpaceError::NotFound))
        );

        let first_lease = service.acquire_lease(
            &space_id,
            AcquireLeaseRequest {
                lease_id: record(268)?,
                resource_id: resource.clone(),
                holder_id: holder.clone(),
                kind: LeaseKind::Publication,
                acquired_at: time(10)?,
                expires_at: time(20)?,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(first_lease.fencing_token, 1);
        drop(service);
        drop(store);

        let reopened_store = Arc::new(SqliteStore::open(&path)?);
        let reopened = DurableContextSpaceService::open(
            reopened_store.clone(),
            tenant.clone(),
            &CancellationToken::default(),
        )?;
        assert!(
            reopened
                .verify_fence(&space_id, &resource, &holder, 1, &time(19)?)
                .is_ok()
        );
        assert_eq!(
            reopened
                .verify_fence(&space_id, &resource, &holder, 1, &time(20)?)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Space(SpaceError::Conflict))
        );
        let second_lease = reopened.acquire_lease(
            &space_id,
            AcquireLeaseRequest {
                lease_id: record(269)?,
                resource_id: resource.clone(),
                holder_id: replacement_holder.clone(),
                kind: LeaseKind::Publication,
                acquired_at: time(20)?,
                expires_at: time(30)?,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(second_lease.fencing_token, 2);
        assert_eq!(
            reopened
                .verify_fence(&space_id, &resource, &holder, 1, &time(21)?)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Space(SpaceError::Conflict))
        );
        drop(reopened);
        drop(reopened_store);

        let restarted = DurableContextSpaceService::open(
            Arc::new(SqliteStore::open(&path)?),
            tenant,
            &CancellationToken::default(),
        )?;
        assert!(
            restarted
                .verify_fence(&space_id, &resource, &replacement_holder, 2, &time(21)?,)
                .is_ok()
        );
        assert_eq!(
            restarted.poll_events(&space_id, &visible, first_page.resume_cursor, 1)?,
            resumed
        );
        Ok(())
    }

    #[test]
    fn concurrent_stale_space_writers_publish_exactly_one_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = Arc::new(InMemoryStore::default());
        let tenant = record(2)?;
        let left_request = create_space_request(210)?;
        let right_request = create_space_request(211)?;
        let left_id = left_request.space_id.clone();
        let right_id = right_request.space_id.clone();
        let left = DurableContextSpaceService::open(
            repository.clone(),
            tenant.clone(),
            &CancellationToken::default(),
        )?;
        let right = DurableContextSpaceService::open(
            repository.clone(),
            tenant.clone(),
            &CancellationToken::default(),
        )?;
        let barrier = Arc::new(Barrier::new(2));
        let left_barrier = barrier.clone();
        let left_thread = thread::spawn(move || {
            left_barrier.wait();
            left.create_space(left_request, &CancellationToken::default())
        });
        let right_thread = thread::spawn(move || {
            barrier.wait();
            right.create_space(right_request, &CancellationToken::default())
        });
        let left_result = left_thread
            .join()
            .map_err(|_panic| "left writer panicked")?;
        let right_result = right_thread
            .join()
            .map_err(|_panic| "right writer panicked")?;
        assert_eq!(
            usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
            1
        );
        let loser = if let Err(error) = left_result {
            error
        } else if let Err(error) = right_result {
            error
        } else {
            return Err("expected one root CAS loser".into());
        };
        assert_eq!(
            loser.code(),
            DurableStateErrorCode::Snapshot(DurableSnapshotErrorCode::RevisionConflict)
        );

        let restored =
            DurableContextSpaceService::open(repository, tenant, &CancellationToken::default())?;
        assert_eq!(restored.generation()?, 1);
        let visible = usize::from(restored.head(&left_id).is_ok())
            + usize::from(restored.head(&right_id).is_ok());
        assert_eq!(visible, 1);
        Ok(())
    }

    #[test]
    fn chunks_are_root_last_and_post_commit_error_is_reconciled()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("root-last.sqlite3");
        let tenant = record(3)?;
        let request = create_space_request(220)?;
        let expected = ContextSpaceService::new();
        expected.create_space(request.clone())?;
        let attempted = expected.export_snapshot()?;
        let store = Arc::new(SqliteStore::open(&path)?);

        let seed = DurableSnapshotStore::new(store.clone(), tenant.clone(), "snapshot-seed");
        seed.publish(0, &attempted, &CancellationToken::default())?;
        let service = DurableContextSpaceService::open(
            store.clone(),
            tenant.clone(),
            &CancellationToken::default(),
        )?;
        store.inject_failpoint(SqliteFailpoint::BeforeRevisionAnchor)?;
        let committed = service.create_space(request.clone(), &CancellationToken::default())?;
        assert_eq!(committed.sequence, 1);
        assert_eq!(service.generation()?, 1);
        assert_eq!(service.head(&request.space_id)?, committed);
        drop(service);
        drop(store);

        let reopened = DurableContextSpaceService::open(
            Arc::new(SqliteStore::open(&path)?),
            tenant,
            &CancellationToken::default(),
        )?;
        assert_eq!(reopened.generation()?, 1);
        assert_eq!(reopened.head(&request.space_id)?, committed);
        Ok(())
    }

    #[test]
    fn missing_chunk_and_semantically_tampered_snapshot_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = Arc::new(InMemoryStore::default());
        let tenant = record(4)?;
        let missing = b"missing snapshot chunk";
        let digest = exact_digest(missing)?;
        let manifest = SnapshotManifest {
            schema_version: MANIFEST_SCHEMA.to_owned(),
            snapshot_kind: SPACE_SNAPSHOT_KIND.to_owned(),
            generation: 1,
            byte_count: missing.len(),
            content_digest: digest.clone(),
            chunks: vec![SnapshotChunk {
                digest,
                byte_count: missing.len(),
            }],
        };
        let write = ServiceRecordWrite::new(
            ROOT_NAMESPACE,
            SPACE_SNAPSHOT_KIND,
            ServiceExpectedVersion::Absent,
            serde_json::to_vec(&manifest)?,
        )?;
        repository.service_commit(
            ServiceBatch::new(tenant.clone(), vec![write], empty_response()?)?,
            &CancellationToken::default(),
        )?;
        let missing_result =
            DurableContextSpaceService::open(repository, tenant, &CancellationToken::default());
        let Err(missing_error) = missing_result else {
            return Err("missing chunk snapshot unexpectedly opened".into());
        };
        assert_eq!(
            missing_error.code(),
            DurableStateErrorCode::Snapshot(DurableSnapshotErrorCode::InvalidSnapshot)
        );

        let semantic_repository = Arc::new(InMemoryStore::default());
        let semantic_tenant = record(5)?;
        let store = DurableSnapshotStore::new(
            semantic_repository.clone(),
            semantic_tenant.clone(),
            SPACE_SNAPSHOT_KIND,
        );
        store.publish(
            0,
            br#"{"schema_version":"cigar.context-space-snapshot.v1","spaces":{"forged":{}}}"#,
            &CancellationToken::default(),
        )?;
        let semantic_result = DurableContextSpaceService::open(
            semantic_repository,
            semantic_tenant,
            &CancellationToken::default(),
        );
        let Err(semantic_error) = semantic_result else {
            return Err("semantic tamper unexpectedly opened".into());
        };
        assert_eq!(
            semantic_error.code(),
            DurableStateErrorCode::Snapshot(DurableSnapshotErrorCode::InvalidSnapshot)
        );
        Ok(())
    }

    #[test]
    fn coherently_rewritten_root_and_chunks_fail_signature_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = Arc::new(InMemoryStore::default());
        let tenant = record(6)?;
        let authentic = ContextSpaceService::new();
        authentic.create_space(create_space_request(230)?)?;
        let authentic_bytes = authentic.export_snapshot()?;
        let store =
            DurableSnapshotStore::new(repository.clone(), tenant.clone(), SPACE_SNAPSHOT_KIND);
        store.publish(0, &authentic_bytes, &CancellationToken::default())?;

        let forged = ContextSpaceService::new();
        forged.create_space(create_space_request(231)?)?;
        let forged_bytes = forged.export_snapshot()?;
        let forged_digest = exact_digest(&forged_bytes)?;
        let forged_chunk = ServiceRecordWrite::new(
            CHUNK_NAMESPACE,
            forged_digest.as_str(),
            ServiceExpectedVersion::Absent,
            forged_bytes.clone(),
        )?;
        repository.service_commit(
            ServiceBatch::new(tenant.clone(), vec![forged_chunk], empty_response()?)?,
            &CancellationToken::default(),
        )?;

        let root = repository
            .service_get(
                &ServiceRecordLocator::new(tenant.clone(), ROOT_NAMESPACE, SPACE_SNAPSHOT_KIND)?,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )?
            .ok_or("published snapshot root missing")?;
        let mut envelope: SnapshotRootEnvelope = serde_json::from_slice(root.bytes())?;
        envelope.manifest.generation = 2;
        envelope.manifest.byte_count = forged_bytes.len();
        envelope.manifest.content_digest = forged_digest.clone();
        envelope.manifest.chunks = vec![SnapshotChunk {
            digest: forged_digest,
            byte_count: forged_bytes.len(),
        }];
        let forged_root = ServiceRecordWrite::new(
            ROOT_NAMESPACE,
            SPACE_SNAPSHOT_KIND,
            ServiceExpectedVersion::Version(1),
            serde_json::to_vec(&envelope)?,
        )?;
        repository.service_commit(
            ServiceBatch::new(tenant.clone(), vec![forged_root], empty_response()?)?,
            &CancellationToken::default(),
        )?;

        let reopened =
            DurableContextSpaceService::open(repository, tenant, &CancellationToken::default());
        let Err(error) = reopened else {
            return Err("coherently rewritten snapshot unexpectedly authenticated".into());
        };
        assert_eq!(
            error.code(),
            DurableStateErrorCode::Snapshot(DurableSnapshotErrorCode::InvalidSnapshot)
        );
        Ok(())
    }

    #[test]
    fn handoff_receipt_replay_guard_rollback_and_sqlite_restart_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("handoff.sqlite3");
        let tenant = record(6)?;
        let (provider, key_ref) = signing_provider()?;
        let store = Arc::new(SqliteStore::open(&path)?);
        let service = DurableHandoffService::open(
            store.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let (capsule, _preview) = service.create(
            handoff_creation(key_ref, 300)?,
            &CancellationToken::default(),
        )?;
        let request = acceptance_request(capsule.clone(), 301)?;
        let bundle = version(302)?;
        let bundle_receipt = recipient_bundle_receipt(&capsule, 302)?;

        store.fail_next_commit();
        let failed = service.accept(
            request.clone(),
            |_reference| true,
            |_context| Ok(bundle_receipt.clone()),
            &CancellationToken::default(),
        );
        assert_eq!(
            failed.map_err(|error| error.code()),
            Err(DurableStateErrorCode::Snapshot(
                DurableSnapshotErrorCode::InjectedAbort
            ))
        );
        assert!(
            service
                .inspect_acceptance(&request, |_reference| true)
                .is_ok()
        );

        let acceptance = service.accept(
            request.clone(),
            |_reference| true,
            |_context| Ok(bundle_receipt.clone()),
            &CancellationToken::default(),
        )?;
        assert_eq!(acceptance.bundle_id, bundle);
        assert_eq!(service.generation()?, 2);
        assert_eq!(
            service
                .inspect_acceptance(&request, |_reference| true)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Handoff(HandoffError::Replay))
        );
        drop(service);
        drop(store);

        let reopened = DurableHandoffService::open(
            Arc::new(SqliteStore::open(&path)?),
            tenant,
            provider,
            &CancellationToken::default(),
        )?;
        assert_eq!(reopened.generation()?, 2);
        assert_eq!(
            reopened.persisted_capsule(&capsule.handoff_id, &record(101)?, &BTreeSet::new())?,
            capsule
        );
        assert_eq!(
            reopened.persisted_acceptance(&acceptance.acceptance_id, &record(101)?)?,
            acceptance
        );
        assert_eq!(
            reopened.subscription_topics(&acceptance.acceptance_id)?,
            vec![
                CoordinationTopic::AtomInvalidation,
                CoordinationTopic::PolicySnapshot,
            ]
        );
        assert_eq!(
            reopened
                .inspect_acceptance(&request, |_reference| true)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Handoff(HandoffError::Replay))
        );
        Ok(())
    }

    #[test]
    fn durable_handoff_result_and_revocation_survive_sqlite_restarts()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("handoff-result.sqlite3");
        let tenant = record(60)?;
        let (provider, key_ref) = signing_provider()?;
        let service = DurableHandoffService::open(
            Arc::new(SqliteStore::open(&path)?),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let (capsule, _preview) = service.create(
            handoff_creation(key_ref, 320)?,
            &CancellationToken::default(),
        )?;
        let acceptance = service.accept(
            acceptance_request(capsule.clone(), 321)?,
            |_reference| true,
            |_context| recipient_bundle_receipt(&capsule, 322),
            &CancellationToken::default(),
        )?;
        let result_request = RecordHandoffResultRequest {
            expected_revision: ExpectedRevision(1),
            acceptance_id: acceptance.acceptance_id.clone(),
            actor_id: acceptance.recipient_id.clone(),
            current_project_ids: BTreeSet::from([record(102)?]),
            delta: handoff_delta(&capsule, &acceptance, 323)?,
            event_id: record(326)?,
        };
        let result = service.record_result(result_request, &CancellationToken::default())?;
        assert_eq!(service.generation()?, 3);
        drop(service);

        let reopened = DurableHandoffService::open(
            Arc::new(SqliteStore::open(&path)?),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        assert_eq!(
            reopened.persisted_result(&result.delta.delta_id, &capsule.issuer_id)?,
            result
        );
        assert_eq!(
            reopened.persisted_results(&capsule.handoff_id, &acceptance.recipient_id)?,
            vec![result.clone()]
        );
        assert!(
            reopened
                .verified_merge_material(
                    &result.delta.delta_id,
                    &capsule.issuer_id,
                    "tenant-a",
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                )
                .is_ok()
        );
        assert_eq!(
            reopened.handoff_revision(&capsule.handoff_id, &capsule.issuer_id, &BTreeSet::new(),)?,
            2
        );
        let revocation = reopened.revoke(
            RevokeHandoffRequest {
                handoff_id: capsule.handoff_id.clone(),
                expected_revision: ExpectedRevision(2),
                actor_id: capsule.issuer_id.clone(),
                policy_digest: content(327)?,
                reason_digest: content(329)?,
                revoked_at: time(23)?,
                event_id: record(328)?,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(revocation.revision, 3);
        assert_eq!(
            reopened
                .verified_merge_material(
                    &result.delta.delta_id,
                    &capsule.issuer_id,
                    "tenant-a",
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                )
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Handoff(HandoffError::Forbidden))
        );
        assert_eq!(reopened.generation()?, 4);
        drop(reopened);

        let restored = DurableHandoffService::open(
            Arc::new(SqliteStore::open(&path)?),
            tenant,
            provider,
            &CancellationToken::default(),
        )?;
        assert_eq!(
            restored.persisted_revocation(
                &capsule.handoff_id,
                &acceptance.recipient_id,
                &BTreeSet::new(),
            )?,
            Some(revocation)
        );
        assert_eq!(
            restored
                .inspect_acceptance(&acceptance_request(capsule.clone(), 329)?, |_reference| {
                    true
                },)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Handoff(HandoffError::Revoked))
        );
        assert_eq!(
            restored
                .verified_merge_material(
                    &result.delta.delta_id,
                    &capsule.issuer_id,
                    "tenant-a",
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                )
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Handoff(HandoffError::Forbidden))
        );
        Ok(())
    }

    #[test]
    fn concurrent_durable_result_and_revocation_have_one_root_winner()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = Arc::new(InMemoryStore::default());
        let tenant = record(61)?;
        let (provider, key_ref) = signing_provider()?;
        let bootstrap = DurableHandoffService::open(
            repository.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let (capsule, _preview) = bootstrap.create(
            handoff_creation(key_ref, 330)?,
            &CancellationToken::default(),
        )?;
        let acceptance = bootstrap.accept(
            acceptance_request(capsule.clone(), 331)?,
            |_reference| true,
            |_context| recipient_bundle_receipt(&capsule, 332),
            &CancellationToken::default(),
        )?;
        drop(bootstrap);

        let result_request = RecordHandoffResultRequest {
            expected_revision: ExpectedRevision(1),
            acceptance_id: acceptance.acceptance_id.clone(),
            actor_id: acceptance.recipient_id.clone(),
            current_project_ids: BTreeSet::from([record(102)?]),
            delta: handoff_delta(&capsule, &acceptance, 333)?,
            event_id: record(336)?,
        };
        let result_id = result_request.delta.delta_id.clone();
        let revocation_request = RevokeHandoffRequest {
            handoff_id: capsule.handoff_id.clone(),
            expected_revision: ExpectedRevision(1),
            actor_id: capsule.issuer_id.clone(),
            policy_digest: content(337)?,
            reason_digest: content(339)?,
            revoked_at: time(24)?,
            event_id: record(338)?,
        };
        let left = DurableHandoffService::open(
            repository.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let right = DurableHandoffService::open(
            repository.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let barrier = Arc::new(Barrier::new(2));
        let left_barrier = barrier.clone();
        let result_thread = thread::spawn(move || {
            left_barrier.wait();
            left.record_result(result_request, &CancellationToken::default())
        });
        let revocation_thread = thread::spawn(move || {
            barrier.wait();
            right.revoke(revocation_request, &CancellationToken::default())
        });
        let result = result_thread
            .join()
            .map_err(|_panic| "durable result thread panicked")?;
        let revocation = revocation_thread
            .join()
            .map_err(|_panic| "durable revocation thread panicked")?;
        assert_eq!(
            usize::from(result.is_ok()) + usize::from(revocation.is_ok()),
            1
        );
        let loser = result
            .as_ref()
            .err()
            .copied()
            .or_else(|| revocation.as_ref().err().copied())
            .ok_or("missing durable race loser")?;
        assert_eq!(
            loser.code(),
            DurableStateErrorCode::Snapshot(DurableSnapshotErrorCode::RevisionConflict)
        );

        let restored = DurableHandoffService::open(
            repository,
            tenant,
            provider,
            &CancellationToken::default(),
        )?;
        assert_eq!(restored.generation()?, 3);
        assert_eq!(
            restored.handoff_revision(&capsule.handoff_id, &capsule.issuer_id, &BTreeSet::new(),)?,
            2
        );
        if let Ok(result) = result {
            assert_eq!(
                restored.persisted_result(&result_id, &capsule.issuer_id)?,
                result
            );
            assert_eq!(
                restored.persisted_revocation(
                    &capsule.handoff_id,
                    &capsule.issuer_id,
                    &BTreeSet::new(),
                )?,
                None
            );
        } else if let Ok(revocation) = revocation {
            assert_eq!(
                restored.persisted_revocation(
                    &capsule.handoff_id,
                    &capsule.issuer_id,
                    &BTreeSet::new(),
                )?,
                Some(revocation)
            );
            assert_eq!(
                restored
                    .persisted_result(&result_id, &capsule.issuer_id)
                    .map_err(|error| error.code()),
                Err(DurableStateErrorCode::Handoff(HandoffError::Forbidden))
            );
        }
        Ok(())
    }

    #[test]
    fn concurrent_handoff_acceptance_has_one_durable_nonce_winner()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = Arc::new(InMemoryStore::default());
        let tenant = record(7)?;
        let (provider, key_ref) = signing_provider()?;
        let bootstrap = DurableHandoffService::open(
            repository.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let (capsule, _preview) = bootstrap.create(
            handoff_creation(key_ref, 310)?,
            &CancellationToken::default(),
        )?;
        drop(bootstrap);
        let left_request = acceptance_request(capsule.clone(), 311)?;
        let right_request = acceptance_request(capsule.clone(), 312)?;
        let left_id = left_request.acceptance_id.clone();
        let right_id = right_request.acceptance_id.clone();
        let bundle_receipt = recipient_bundle_receipt(&capsule, 313)?;
        let left = DurableHandoffService::open(
            repository.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let right = DurableHandoffService::open(
            repository.clone(),
            tenant.clone(),
            provider.clone(),
            &CancellationToken::default(),
        )?;
        let barrier = Arc::new(Barrier::new(2));
        let left_barrier = barrier.clone();
        let left_bundle = bundle_receipt.clone();
        let right_bundle = bundle_receipt;
        let left_thread = thread::spawn(move || {
            left_barrier.wait();
            left.accept(
                left_request,
                |_reference| true,
                |_context| Ok(left_bundle),
                &CancellationToken::default(),
            )
        });
        let right_thread = thread::spawn(move || {
            barrier.wait();
            right.accept(
                right_request,
                |_reference| true,
                |_context| Ok(right_bundle),
                &CancellationToken::default(),
            )
        });
        let left_result = left_thread
            .join()
            .map_err(|_panic| "left acceptance panicked")?;
        let right_result = right_thread
            .join()
            .map_err(|_panic| "right acceptance panicked")?;
        assert_eq!(
            usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
            1
        );
        let loser = if let Err(error) = &left_result {
            *error
        } else if let Err(error) = &right_result {
            *error
        } else {
            return Err("expected one acceptance root CAS loser".into());
        };
        assert_eq!(
            loser.code(),
            DurableStateErrorCode::Snapshot(DurableSnapshotErrorCode::RevisionConflict)
        );
        let winner = left_result.or(right_result)?;
        let restored = DurableHandoffService::open(
            repository,
            tenant,
            provider,
            &CancellationToken::default(),
        )?;
        assert_eq!(restored.generation()?, 2);
        assert_eq!(
            restored.persisted_acceptance(&winner.acceptance_id, &record(101)?)?,
            winner
        );
        let losing_id = if winner.acceptance_id == left_id {
            right_id
        } else {
            left_id
        };
        assert_eq!(
            restored
                .persisted_acceptance(&losing_id, &record(101)?)
                .map_err(|error| error.code()),
            Err(DurableStateErrorCode::Handoff(HandoffError::Forbidden))
        );
        Ok(())
    }
}
