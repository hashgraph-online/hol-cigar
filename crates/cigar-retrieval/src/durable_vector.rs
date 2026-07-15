//! macOS-only durable storage for immutable provider-neutral local vector generations.
//!
//! The format persists only version identifiers, processor-approved quantized vectors, and exact
//! configuration/content commitments. It has no atom-payload or raw-text input. Generations are
//! written below a private descriptor-pinned root, verified before activation, and selected only
//! by an explicitly published current-generation pointer.

use crate::local_vector::{
    LOCAL_VECTOR_ADAPTER_VERSION, LocalVectorConfiguration, LocalVectorDistanceMetric,
    LocalVectorEntry, LocalVectorParameters, LocalVectorQuantization, SealedLocalVectorAdapter,
};
use crate::vector::{finish_digest, hash_frame};
use crate::{ProcessorApprovedVector, VectorAdapter, VectorIndexBinding};
use cigar_protocol::{ContentDigest, RecordId, VersionId};
use cigar_store::StoreRevision;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path};
use std::sync::Mutex;

const GENERATIONS_DIRECTORY: &str = "generations";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const CURRENT_FILE: &str = "current.cigar-vector";
const DATA_FILE: &str = "vectors.cigar-vector";
const MANIFEST_FILE: &str = "manifest.cigar-vector";
const BUILDING_PREFIX: &str = ".building-";
const ACTIVATION_PREFIX: &str = ".activating-";
const QUARANTINE_PREFIX: &str = ".quarantine-";
const DATA_MAGIC: &[u8] = b"CIGAR-LOCAL-VECTOR-DATA\0v1\0";
const MANIFEST_MAGIC: &[u8] = b"CIGAR-LOCAL-VECTOR-MANIFEST\0v1\0";
const ACTIVATION_MAGIC: &[u8] = b"CIGAR-LOCAL-VECTOR-ACTIVATION\0v1\0";
const MAX_DURABLE_VECTOR_DATA_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DURABLE_VECTOR_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_DURABLE_VECTOR_ACTIVATION_BYTES: u64 = 4 * 1024;
const MAX_DURABLE_VECTOR_GENERATIONS: usize = 1_024;
const MAX_DURABLE_VECTOR_QUARANTINE_ENTRIES: usize = 16;
const MAX_DURABLE_STRING_BYTES: usize = 512;

/// Stable content-free failures from durable local vector operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableLocalVectorErrorCode {
    /// Configuration, path, generation, or activation metadata is invalid.
    InvalidMetadata,
    /// A fixed file, entry, generation, or byte bound was exceeded.
    LimitExceeded,
    /// A protected filesystem operation could not complete.
    Unavailable,
    /// Canonical bytes, content commitments, or generation bindings failed verification.
    Corrupt,
    /// An expected-current activation or immutable generation conflicted.
    Conflict,
    /// The requested immutable generation does not exist.
    NotFound,
    /// A named crash boundary interrupted publication.
    InjectedAbort,
}

/// Content-free durable vector error that never formats paths, identifiers, or vector values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DurableLocalVectorError {
    code: DurableLocalVectorErrorCode,
}

impl DurableLocalVectorError {
    const fn new(code: DurableLocalVectorErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> DurableLocalVectorErrorCode {
        self.code
    }
}

impl fmt::Debug for DurableLocalVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableLocalVectorError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for DurableLocalVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "durable local vector operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for DurableLocalVectorError {}

/// One-shot crash boundaries covering generation and activation publication.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DurableLocalVectorFailpoint {
    /// After the private temporary generation directory is created.
    AfterGenerationTemporaryCreate,
    /// After the vector-data file is created.
    AfterDataFileCreate,
    /// After all canonical vector-data bytes are written.
    AfterDataWrite,
    /// After vector-data file synchronization.
    AfterDataSync,
    /// After the manifest file is created.
    AfterManifestFileCreate,
    /// After all canonical manifest bytes are written.
    AfterManifestWrite,
    /// After manifest file synchronization.
    AfterManifestSync,
    /// After temporary generation directory synchronization.
    AfterGenerationDirectorySync,
    /// After no-replace generation rename.
    AfterGenerationRename,
    /// After generation-parent synchronization.
    AfterGenerationsParentSync,
    /// After the temporary activation file is created.
    AfterActivationTemporaryCreate,
    /// After all canonical activation bytes are written.
    AfterActivationWrite,
    /// After activation-file synchronization.
    AfterActivationSync,
    /// After atomic current-generation rename.
    AfterActivationRename,
    /// After root-directory synchronization.
    AfterActivationParentSync,
}

/// Why startup deliberately omitted the optional vector adapter and selected lexical fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableLocalVectorFallbackReason {
    /// No explicit current-generation pointer exists.
    NoActiveGeneration,
    /// The current-generation pointer was malformed or unsafe.
    InvalidActivation,
    /// The selected generation was absent or incomplete.
    ActiveGenerationMissing,
    /// The selected generation failed canonical or content-integrity verification.
    CorruptGeneration,
    /// The selected generation is valid but older than the caller's required catalog watermark.
    StaleWatermark,
}

/// Content-free descriptor for one verified durable vector generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableLocalVectorGenerationDescriptor {
    /// Exact generation and sealed adapter fingerprint.
    pub index_binding: VectorIndexBinding,
    /// Catalog revision represented by the processor-approved vectors.
    pub built_through_revision: StoreRevision,
    /// Digest of the canonical generation manifest.
    pub manifest_digest: ContentDigest,
    /// Digest of the canonical vector-data file.
    pub vector_data_digest: ContentDigest,
    /// Number of immutable version/vector entries.
    pub vector_count: u64,
}

/// Result of startup verification and deterministic optional-channel selection.
pub struct DurableLocalVectorStartup {
    /// Verified active generation metadata, absent on lexical fallback.
    pub descriptor: Option<DurableLocalVectorGenerationDescriptor>,
    /// Stable fallback reason, absent when an adapter was loaded.
    pub fallback_reason: Option<DurableLocalVectorFallbackReason>,
    /// Number of unsafe, incomplete, or corrupt entries moved to quarantine.
    pub quarantined_entries: u64,
    adapter: Option<SealedLocalVectorAdapter>,
}

impl DurableLocalVectorStartup {
    /// Borrows the verified adapter. `None` means callers must use deterministic non-vector stages.
    #[must_use]
    pub const fn adapter(&self) -> Option<&SealedLocalVectorAdapter> {
        self.adapter.as_ref()
    }

    /// Takes ownership of the verified adapter for an explicit internal registry insertion.
    #[must_use]
    pub fn into_adapter(self) -> Option<SealedLocalVectorAdapter> {
        self.adapter
    }
}

impl fmt::Debug for DurableLocalVectorStartup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableLocalVectorStartup")
            .field("descriptor", &self.descriptor)
            .field("fallback_reason", &self.fallback_reason)
            .field("quarantined_entries", &self.quarantined_entries)
            .field("adapter_loaded", &self.adapter.is_some())
            .finish()
    }
}

/// Descriptor-pinned macOS store for immutable local vector generations.
pub struct DurableLocalVectorStore {
    root: File,
    failpoints: Mutex<BTreeSet<DurableLocalVectorFailpoint>>,
}

impl fmt::Debug for DurableLocalVectorStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableLocalVectorStore([REDACTED])")
    }
}

impl DurableLocalVectorStore {
    /// Opens an existing absolute owner-private root without following any pathname symlink.
    ///
    /// The caller must explicitly create the root with owner-only permissions. Merely constructing
    /// a default local vector enablement never opens this store or activates a vector channel.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, DurableLocalVectorError> {
        let root = open_private_root(root.as_ref())?;
        let store = Self {
            root,
            failpoints: Mutex::new(BTreeSet::new()),
        };
        {
            let _lock = store.lock_root()?;
            let generations = ensure_private_subdirectory(&store.root, GENERATIONS_DIRECTORY)?;
            let quarantine = ensure_private_subdirectory(&store.root, QUARANTINE_DIRECTORY)?;
            generations.sync_all().map_err(unavailable)?;
            quarantine.sync_all().map_err(unavailable)?;
            store.root.sync_all().map_err(unavailable)?;
        }
        Ok(store)
    }

    /// Arms one one-shot crash boundary for deterministic recovery testing.
    pub fn inject_failpoint(
        &self,
        failpoint: DurableLocalVectorFailpoint,
    ) -> Result<(), DurableLocalVectorError> {
        self.failpoints
            .lock()
            .map_err(|_error| {
                DurableLocalVectorError::new(DurableLocalVectorErrorCode::Unavailable)
            })?
            .insert(failpoint);
        Ok(())
    }

    fn trip(&self, failpoint: DurableLocalVectorFailpoint) -> Result<(), DurableLocalVectorError> {
        let mut failpoints = self.failpoints.lock().map_err(|_error| {
            DurableLocalVectorError::new(DurableLocalVectorErrorCode::Unavailable)
        })?;
        if failpoints.remove(&failpoint) {
            Err(DurableLocalVectorError::new(
                DurableLocalVectorErrorCode::InjectedAbort,
            ))
        } else {
            Ok(())
        }
    }

    fn lock_root(&self) -> Result<RootOperationLock, DurableLocalVectorError> {
        use rustix::fs::{Mode, OFlags, openat};

        let lock = openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_error| DurableLocalVectorError::new(DurableLocalVectorErrorCode::Unavailable))?;
        match lock.try_lock() {
            Ok(()) => Ok(RootOperationLock(lock)),
            Err(std::fs::TryLockError::WouldBlock) => Err(DurableLocalVectorError::new(
                DurableLocalVectorErrorCode::Conflict,
            )),
            Err(std::fs::TryLockError::Error(_error)) => Err(DurableLocalVectorError::new(
                DurableLocalVectorErrorCode::Unavailable,
            )),
        }
    }

    /// Publishes one immutable verified generation without selecting it for queries.
    pub fn publish(
        &self,
        adapter: &SealedLocalVectorAdapter,
        built_through_revision: StoreRevision,
    ) -> Result<DurableLocalVectorGenerationDescriptor, DurableLocalVectorError> {
        let data = encode_vector_data(adapter)?;
        if u64::try_from(data.len()).map_or(true, |length| length > MAX_DURABLE_VECTOR_DATA_BYTES) {
            return Err(DurableLocalVectorError::new(
                DurableLocalVectorErrorCode::LimitExceeded,
            ));
        }
        let data_digest = content_digest(&data)?;
        let manifest =
            GenerationManifest::from_adapter(adapter, built_through_revision, data_digest.clone())?;
        let manifest_bytes = encode_manifest(&manifest)?;
        if u64::try_from(manifest_bytes.len())
            .map_or(true, |length| length > MAX_DURABLE_VECTOR_MANIFEST_BYTES)
        {
            return Err(DurableLocalVectorError::new(
                DurableLocalVectorErrorCode::LimitExceeded,
            ));
        }
        let manifest_digest = content_digest(&manifest_bytes)?;
        let descriptor = manifest.descriptor(manifest_digest);
        let generation_name = descriptor.index_binding.generation_id().as_str();

        let _lock = self.lock_root()?;
        let generations = open_private_subdirectory(&self.root, GENERATIONS_DIRECTORY)?;
        match load_generation(&generations, generation_name) {
            Ok((existing, _adapter)) if existing == descriptor => return Ok(existing),
            Ok((_existing, _adapter)) => {
                return Err(DurableLocalVectorError::new(
                    DurableLocalVectorErrorCode::Conflict,
                ));
            }
            Err(error) if error.code() == DurableLocalVectorErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }

        let temporary_name = format!("{BUILDING_PREFIX}{}", random_suffix()?);
        let temporary = create_private_directory_at(&generations, &temporary_name)?;
        self.trip(DurableLocalVectorFailpoint::AfterGenerationTemporaryCreate)?;

        let mut data_file = create_private_file_at(&temporary, DATA_FILE)?;
        self.trip(DurableLocalVectorFailpoint::AfterDataFileCreate)?;
        data_file.write_all(&data).map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterDataWrite)?;
        data_file.sync_all().map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterDataSync)?;

        let mut manifest_file = create_private_file_at(&temporary, MANIFEST_FILE)?;
        self.trip(DurableLocalVectorFailpoint::AfterManifestFileCreate)?;
        manifest_file
            .write_all(&manifest_bytes)
            .map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterManifestWrite)?;
        manifest_file.sync_all().map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterManifestSync)?;

        temporary.sync_all().map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterGenerationDirectorySync)?;
        rename_noreplace(
            &generations,
            OsStr::new(&temporary_name),
            &generations,
            OsStr::new(generation_name),
        )?;
        self.trip(DurableLocalVectorFailpoint::AfterGenerationRename)?;
        generations.sync_all().map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterGenerationsParentSync)?;
        Ok(descriptor)
    }

    /// Atomically selects one fully verified generation under an exact expected-current CAS.
    pub fn activate(
        &self,
        generation_id: &RecordId,
        expected_active: Option<&RecordId>,
    ) -> Result<DurableLocalVectorGenerationDescriptor, DurableLocalVectorError> {
        let _lock = self.lock_root()?;
        let current = match read_activation(&self.root) {
            Ok(pointer) => Some(pointer),
            Err(error) if error.code() == DurableLocalVectorErrorCode::NotFound => None,
            Err(error) => return Err(error),
        };
        if current.as_ref().map(|pointer| &pointer.generation_id) != expected_active {
            return Err(DurableLocalVectorError::new(
                DurableLocalVectorErrorCode::Conflict,
            ));
        }
        let generations = open_private_subdirectory(&self.root, GENERATIONS_DIRECTORY)?;
        let (descriptor, _adapter) = load_generation(&generations, generation_id.as_str())?;
        let pointer = ActivationPointer::from_descriptor(&descriptor);
        if current.as_ref().is_some_and(|current| current == &pointer) {
            return Ok(descriptor);
        }
        let bytes = encode_activation(&pointer)?;
        let temporary_name = format!("{ACTIVATION_PREFIX}{}", random_suffix()?);
        let mut temporary = create_private_file_at(&self.root, &temporary_name)?;
        self.trip(DurableLocalVectorFailpoint::AfterActivationTemporaryCreate)?;
        temporary.write_all(&bytes).map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterActivationWrite)?;
        temporary.sync_all().map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterActivationSync)?;
        rustix::fs::renameat(&self.root, &temporary_name, &self.root, CURRENT_FILE)
            .map_err(|_error| unavailable_error())?;
        self.trip(DurableLocalVectorFailpoint::AfterActivationRename)?;
        self.root.sync_all().map_err(unavailable)?;
        self.trip(DurableLocalVectorFailpoint::AfterActivationParentSync)?;
        Ok(descriptor)
    }

    /// Reconciles incomplete publications, verifies the explicit activation, and either loads the
    /// exact adapter or returns a deterministic lexical-fallback reason.
    pub fn startup(
        &self,
        required_revision: StoreRevision,
    ) -> Result<DurableLocalVectorStartup, DurableLocalVectorError> {
        let _lock = self.lock_root()?;
        let generations = open_private_subdirectory(&self.root, GENERATIONS_DIRECTORY)?;
        let quarantine = open_private_subdirectory(&self.root, QUARANTINE_DIRECTORY)?;
        let mut quarantined_entries = reconcile_activation_temporaries(&self.root, &quarantine)?;

        let (pointer, invalid_activation) = match read_activation(&self.root) {
            Ok(pointer) => (Some(pointer), false),
            Err(error) if error.code() == DurableLocalVectorErrorCode::NotFound => (None, false),
            Err(_error) => {
                quarantined_entries = quarantined_entries
                    .checked_add(u64::from(quarantine_entry(
                        &self.root,
                        OsStr::new(CURRENT_FILE),
                        &quarantine,
                    )?))
                    .ok_or_else(limit_error)?;
                (None, true)
            }
        };
        quarantined_entries = quarantined_entries
            .checked_add(reconcile_generation_entries(
                &generations,
                &quarantine,
                pointer.as_ref().map(|pointer| &pointer.generation_id),
            )?)
            .ok_or_else(limit_error)?;

        if invalid_activation {
            return Ok(fallback_startup(
                DurableLocalVectorFallbackReason::InvalidActivation,
                quarantined_entries,
            ));
        }
        let Some(pointer) = pointer else {
            return Ok(fallback_startup(
                DurableLocalVectorFallbackReason::NoActiveGeneration,
                quarantined_entries,
            ));
        };
        let loaded = load_generation(&generations, pointer.generation_id.as_str());
        let (descriptor, adapter) = match loaded {
            Ok(loaded) => loaded,
            Err(error) => {
                quarantined_entries = quarantined_entries
                    .checked_add(quarantine_active_generation(
                        &generations,
                        &self.root,
                        &quarantine,
                        &pointer.generation_id,
                    )?)
                    .ok_or_else(limit_error)?;
                let reason = if error.code() == DurableLocalVectorErrorCode::NotFound {
                    DurableLocalVectorFallbackReason::ActiveGenerationMissing
                } else {
                    DurableLocalVectorFallbackReason::CorruptGeneration
                };
                return Ok(fallback_startup(reason, quarantined_entries));
            }
        };
        if pointer != ActivationPointer::from_descriptor(&descriptor) {
            quarantined_entries = quarantined_entries
                .checked_add(quarantine_active_generation(
                    &generations,
                    &self.root,
                    &quarantine,
                    &pointer.generation_id,
                )?)
                .ok_or_else(limit_error)?;
            return Ok(fallback_startup(
                DurableLocalVectorFallbackReason::CorruptGeneration,
                quarantined_entries,
            ));
        }
        if descriptor.built_through_revision < required_revision {
            return Ok(fallback_startup(
                DurableLocalVectorFallbackReason::StaleWatermark,
                quarantined_entries,
            ));
        }
        Ok(DurableLocalVectorStartup {
            descriptor: Some(descriptor),
            fallback_reason: None,
            quarantined_entries,
            adapter: Some(adapter),
        })
    }
}

fn fallback_startup(
    reason: DurableLocalVectorFallbackReason,
    quarantined_entries: u64,
) -> DurableLocalVectorStartup {
    DurableLocalVectorStartup {
        descriptor: None,
        fallback_reason: Some(reason),
        quarantined_entries,
        adapter: None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GenerationManifest {
    adapter_version: String,
    model_id: String,
    model_fingerprint: ContentDigest,
    dimension: u64,
    preprocessing_id: String,
    preprocessing_fingerprint: ContentDigest,
    distance_metric: String,
    quantization: String,
    partition_digest: ContentDigest,
    processor_binding: ContentDigest,
    generation_id: RecordId,
    maximum_entries: u64,
    maximum_neighbors: u64,
    built_through_revision: StoreRevision,
    vector_count: u64,
    vector_data_digest: ContentDigest,
    sealed_fingerprint: ContentDigest,
}

impl GenerationManifest {
    fn from_adapter(
        adapter: &SealedLocalVectorAdapter,
        built_through_revision: StoreRevision,
        vector_data_digest: ContentDigest,
    ) -> Result<Self, DurableLocalVectorError> {
        let configuration = adapter.configuration();
        let parameters = configuration.parameters();
        Ok(Self {
            adapter_version: LOCAL_VECTOR_ADAPTER_VERSION.to_owned(),
            model_id: parameters.model_id.clone(),
            model_fingerprint: parameters.model_fingerprint.clone(),
            dimension: u64::try_from(parameters.dimension).map_err(|_error| limit_error())?,
            preprocessing_id: parameters.preprocessing_id.clone(),
            preprocessing_fingerprint: parameters.preprocessing_fingerprint.clone(),
            distance_metric: parameters.distance_metric.identifier().to_owned(),
            quantization: parameters.quantization.identifier().to_owned(),
            partition_digest: parameters.partition_digest.clone(),
            processor_binding: configuration.processor_binding().clone(),
            generation_id: parameters.index_generation_id.clone(),
            maximum_entries: u64::try_from(parameters.maximum_entries)
                .map_err(|_error| limit_error())?,
            maximum_neighbors: u64::try_from(parameters.maximum_neighbors)
                .map_err(|_error| limit_error())?,
            built_through_revision,
            vector_count: u64::try_from(adapter.vectors().len()).map_err(|_error| limit_error())?,
            vector_data_digest,
            sealed_fingerprint: adapter.index_binding().fingerprint().clone(),
        })
    }

    fn configuration(&self) -> Result<LocalVectorConfiguration, DurableLocalVectorError> {
        let dimension = usize::try_from(self.dimension).map_err(|_error| limit_error())?;
        let maximum_entries =
            usize::try_from(self.maximum_entries).map_err(|_error| limit_error())?;
        let maximum_neighbors =
            usize::try_from(self.maximum_neighbors).map_err(|_error| limit_error())?;
        let distance_metric = LocalVectorDistanceMetric::from_identifier(&self.distance_metric)
            .ok_or_else(invalid_error)?;
        let quantization = LocalVectorQuantization::from_identifier(&self.quantization)
            .ok_or_else(invalid_error)?;
        let configuration = LocalVectorConfiguration::new(LocalVectorParameters {
            model_id: self.model_id.clone(),
            model_fingerprint: self.model_fingerprint.clone(),
            dimension,
            preprocessing_id: self.preprocessing_id.clone(),
            preprocessing_fingerprint: self.preprocessing_fingerprint.clone(),
            distance_metric,
            quantization,
            partition_digest: self.partition_digest.clone(),
            index_generation_id: self.generation_id.clone(),
            maximum_entries,
            maximum_neighbors,
        })
        .map_err(|_error| corrupt_error())?;
        if self.adapter_version != LOCAL_VECTOR_ADAPTER_VERSION
            || configuration.processor_binding() != &self.processor_binding
            || self.vector_count > self.maximum_entries
        {
            return Err(corrupt_error());
        }
        Ok(configuration)
    }

    fn descriptor(&self, manifest_digest: ContentDigest) -> DurableLocalVectorGenerationDescriptor {
        DurableLocalVectorGenerationDescriptor {
            index_binding: VectorIndexBinding::new(
                self.generation_id.clone(),
                self.sealed_fingerprint.clone(),
            ),
            built_through_revision: self.built_through_revision,
            manifest_digest,
            vector_data_digest: self.vector_data_digest.clone(),
            vector_count: self.vector_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivationPointer {
    generation_id: RecordId,
    sealed_fingerprint: ContentDigest,
    manifest_digest: ContentDigest,
    vector_data_digest: ContentDigest,
    built_through_revision: StoreRevision,
    vector_count: u64,
}

impl ActivationPointer {
    fn from_descriptor(descriptor: &DurableLocalVectorGenerationDescriptor) -> Self {
        Self {
            generation_id: descriptor.index_binding.generation_id().clone(),
            sealed_fingerprint: descriptor.index_binding.fingerprint().clone(),
            manifest_digest: descriptor.manifest_digest.clone(),
            vector_data_digest: descriptor.vector_data_digest.clone(),
            built_through_revision: descriptor.built_through_revision,
            vector_count: descriptor.vector_count,
        }
    }
}

fn encode_vector_data(
    adapter: &SealedLocalVectorAdapter,
) -> Result<Vec<u8>, DurableLocalVectorError> {
    let dimension = u64::try_from(adapter.configuration().parameters().dimension)
        .map_err(|_error| limit_error())?;
    let count = u64::try_from(adapter.vectors().len()).map_err(|_error| limit_error())?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DATA_MAGIC);
    push_u64(&mut bytes, dimension);
    push_u64(&mut bytes, count);
    for (version_id, vector) in adapter.vectors() {
        push_text(&mut bytes, version_id.as_str(), MAX_DURABLE_STRING_BYTES)?;
        push_text(
            &mut bytes,
            vector.commitment().as_str(),
            MAX_DURABLE_STRING_BYTES,
        )?;
        bytes.extend(vector.values().iter().map(|value| value.to_be_bytes()[0]));
        if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_DURABLE_VECTOR_DATA_BYTES)
        {
            return Err(limit_error());
        }
    }
    Ok(bytes)
}

fn decode_vector_data(
    bytes: &[u8],
    manifest: &GenerationManifest,
    configuration: &LocalVectorConfiguration,
) -> Result<Vec<LocalVectorEntry>, DurableLocalVectorError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_magic(DATA_MAGIC)?;
    let dimension = decoder.read_u64()?;
    let count = decoder.read_u64()?;
    if dimension != manifest.dimension
        || count != manifest.vector_count
        || count > manifest.maximum_entries
    {
        return Err(corrupt_error());
    }
    let dimension = usize::try_from(dimension).map_err(|_error| limit_error())?;
    let count = usize::try_from(count).map_err(|_error| limit_error())?;
    let mut entries = Vec::with_capacity(count);
    let mut previous: Option<VersionId> = None;
    for _ in 0..count {
        let version_id = VersionId::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
            .map_err(|_error| corrupt_error())?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &version_id)
        {
            return Err(corrupt_error());
        }
        previous = Some(version_id.clone());
        let commitment = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
            .map_err(|_error| corrupt_error())?;
        let encoded_values = decoder.take(dimension)?;
        let values = encoded_values
            .iter()
            .map(|value| i16::from(i8::from_be_bytes([*value])))
            .collect::<Vec<_>>();
        let vector = ProcessorApprovedVector::try_from_processor_output(
            configuration.processor_binding().clone(),
            &values,
        )
        .map_err(|_error| corrupt_error())?;
        if vector.commitment() != &commitment {
            return Err(corrupt_error());
        }
        entries.push(LocalVectorEntry::new(version_id, vector));
    }
    decoder.finish()?;
    Ok(entries)
}

fn encode_manifest(manifest: &GenerationManifest) -> Result<Vec<u8>, DurableLocalVectorError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MANIFEST_MAGIC);
    for value in [
        manifest.adapter_version.as_str(),
        manifest.model_id.as_str(),
        manifest.model_fingerprint.as_str(),
    ] {
        push_text(&mut bytes, value, MAX_DURABLE_STRING_BYTES)?;
    }
    push_u64(&mut bytes, manifest.dimension);
    for value in [
        manifest.preprocessing_id.as_str(),
        manifest.preprocessing_fingerprint.as_str(),
        manifest.distance_metric.as_str(),
        manifest.quantization.as_str(),
        manifest.partition_digest.as_str(),
        manifest.processor_binding.as_str(),
        manifest.generation_id.as_str(),
    ] {
        push_text(&mut bytes, value, MAX_DURABLE_STRING_BYTES)?;
    }
    push_u64(&mut bytes, manifest.maximum_entries);
    push_u64(&mut bytes, manifest.maximum_neighbors);
    push_u64(&mut bytes, manifest.built_through_revision.0);
    push_u64(&mut bytes, manifest.vector_count);
    push_text(
        &mut bytes,
        manifest.vector_data_digest.as_str(),
        MAX_DURABLE_STRING_BYTES,
    )?;
    push_text(
        &mut bytes,
        manifest.sealed_fingerprint.as_str(),
        MAX_DURABLE_STRING_BYTES,
    )?;
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<GenerationManifest, DurableLocalVectorError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_magic(MANIFEST_MAGIC)?;
    let adapter_version = decoder.read_text(MAX_DURABLE_STRING_BYTES)?;
    let model_id = decoder.read_text(MAX_DURABLE_STRING_BYTES)?;
    let model_fingerprint = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let dimension = decoder.read_u64()?;
    let preprocessing_id = decoder.read_text(MAX_DURABLE_STRING_BYTES)?;
    let preprocessing_fingerprint =
        ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
            .map_err(|_error| corrupt_error())?;
    let distance_metric = decoder.read_text(MAX_DURABLE_STRING_BYTES)?;
    let quantization = decoder.read_text(MAX_DURABLE_STRING_BYTES)?;
    let partition_digest = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let processor_binding = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let generation_id = RecordId::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let maximum_entries = decoder.read_u64()?;
    let maximum_neighbors = decoder.read_u64()?;
    let built_through_revision = StoreRevision(decoder.read_u64()?);
    let vector_count = decoder.read_u64()?;
    let vector_data_digest = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let sealed_fingerprint = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    decoder.finish()?;
    let manifest = GenerationManifest {
        adapter_version,
        model_id,
        model_fingerprint,
        dimension,
        preprocessing_id,
        preprocessing_fingerprint,
        distance_metric,
        quantization,
        partition_digest,
        processor_binding,
        generation_id,
        maximum_entries,
        maximum_neighbors,
        built_through_revision,
        vector_count,
        vector_data_digest,
        sealed_fingerprint,
    };
    if encode_manifest(&manifest)? != bytes {
        return Err(corrupt_error());
    }
    Ok(manifest)
}

fn encode_activation(pointer: &ActivationPointer) -> Result<Vec<u8>, DurableLocalVectorError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ACTIVATION_MAGIC);
    for value in [
        pointer.generation_id.as_str(),
        pointer.sealed_fingerprint.as_str(),
        pointer.manifest_digest.as_str(),
        pointer.vector_data_digest.as_str(),
    ] {
        push_text(&mut bytes, value, MAX_DURABLE_STRING_BYTES)?;
    }
    push_u64(&mut bytes, pointer.built_through_revision.0);
    push_u64(&mut bytes, pointer.vector_count);
    Ok(bytes)
}

fn decode_activation(bytes: &[u8]) -> Result<ActivationPointer, DurableLocalVectorError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_magic(ACTIVATION_MAGIC)?;
    let generation_id = RecordId::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let sealed_fingerprint = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let manifest_digest = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let vector_data_digest = ContentDigest::new(decoder.read_text(MAX_DURABLE_STRING_BYTES)?)
        .map_err(|_error| corrupt_error())?;
    let built_through_revision = StoreRevision(decoder.read_u64()?);
    let vector_count = decoder.read_u64()?;
    decoder.finish()?;
    let pointer = ActivationPointer {
        generation_id,
        sealed_fingerprint,
        manifest_digest,
        vector_data_digest,
        built_through_revision,
        vector_count,
    };
    if encode_activation(&pointer)? != bytes {
        return Err(corrupt_error());
    }
    Ok(pointer)
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_text(
    bytes: &mut Vec<u8>,
    value: &str,
    maximum: usize,
) -> Result<(), DurableLocalVectorError> {
    if value.is_empty() || value.len() > maximum {
        return Err(limit_error());
    }
    let length = u32::try_from(value.len()).map_err(|_error| limit_error())?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn expect_magic(&mut self, expected: &[u8]) -> Result<(), DurableLocalVectorError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(corrupt_error())
        }
    }

    fn read_u64(&mut self) -> Result<u64, DurableLocalVectorError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_error| corrupt_error())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_text(&mut self, maximum: usize) -> Result<String, DurableLocalVectorError> {
        let length: [u8; 4] = self.take(4)?.try_into().map_err(|_error| corrupt_error())?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_error| limit_error())?;
        if length == 0 || length > maximum {
            return Err(corrupt_error());
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_error| corrupt_error())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableLocalVectorError> {
        if self.remaining.len() < length {
            return Err(corrupt_error());
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), DurableLocalVectorError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(corrupt_error())
        }
    }
}

fn load_generation(
    generations: &File,
    generation_name: &str,
) -> Result<
    (
        DurableLocalVectorGenerationDescriptor,
        SealedLocalVectorAdapter,
    ),
    DurableLocalVectorError,
> {
    let generation = open_private_directory_at(generations, generation_name)?;
    let names = list_directory_names(&generation)?;
    let expected = [OsString::from(DATA_FILE), OsString::from(MANIFEST_FILE)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if names.into_iter().collect::<BTreeSet<_>>() != expected {
        return Err(corrupt_error());
    }
    let manifest_bytes = read_private_file_at(
        &generation,
        MANIFEST_FILE,
        MAX_DURABLE_VECTOR_MANIFEST_BYTES,
    )?;
    let manifest_digest = content_digest(&manifest_bytes)?;
    let manifest = decode_manifest(&manifest_bytes)?;
    if manifest.generation_id.as_str() != generation_name {
        return Err(corrupt_error());
    }
    let configuration = manifest.configuration()?;
    let data = read_private_file_at(&generation, DATA_FILE, MAX_DURABLE_VECTOR_DATA_BYTES)?;
    if content_digest(&data)? != manifest.vector_data_digest {
        return Err(corrupt_error());
    }
    let entries = decode_vector_data(&data, &manifest, &configuration)?;
    let adapter =
        SealedLocalVectorAdapter::seal(configuration, entries).map_err(|_error| corrupt_error())?;
    if adapter.index_binding().generation_id() != &manifest.generation_id
        || adapter.index_binding().fingerprint() != &manifest.sealed_fingerprint
        || encode_vector_data(&adapter)? != data
    {
        return Err(corrupt_error());
    }
    Ok((manifest.descriptor(manifest_digest), adapter))
}

fn read_activation(root: &File) -> Result<ActivationPointer, DurableLocalVectorError> {
    let bytes = read_private_file_at(root, CURRENT_FILE, MAX_DURABLE_VECTOR_ACTIVATION_BYTES)?;
    decode_activation(&bytes)
}

fn reconcile_activation_temporaries(
    root: &File,
    quarantine: &File,
) -> Result<u64, DurableLocalVectorError> {
    let names = list_directory_names(root)?;
    let mut quarantined = 0_u64;
    for name in names {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(ACTIVATION_PREFIX))
        {
            quarantined = quarantined
                .checked_add(u64::from(quarantine_entry(root, &name, quarantine)?))
                .ok_or_else(limit_error)?;
        }
    }
    Ok(quarantined)
}

fn reconcile_generation_entries(
    generations: &File,
    quarantine: &File,
    active: Option<&RecordId>,
) -> Result<u64, DurableLocalVectorError> {
    let names = list_directory_names(generations)?;
    if names.len() > MAX_DURABLE_VECTOR_GENERATIONS {
        return Err(limit_error());
    }
    let mut quarantined = 0_u64;
    for name in names {
        let is_active = name
            .to_str()
            .is_some_and(|name| active.is_some_and(|active| active.as_str() == name));
        if is_active {
            continue;
        }
        // Inactive immutable generations are deliberately screened without reading or hashing
        // their content. Fully loading every staged generation would let accumulated generations
        // multiply the 512 MiB per-file bound during process startup. Activation performs the
        // complete canonical decode, digest verification, and adapter seal before publication.
        let valid_final = name.to_str().is_some_and(|name| {
            RecordId::new(name.to_owned()).is_ok()
                && structurally_validate_generation(generations, name).is_ok()
        });
        if valid_final {
            continue;
        }
        quarantined = quarantined
            .checked_add(u64::from(quarantine_entry(generations, &name, quarantine)?))
            .ok_or_else(limit_error)?;
    }
    Ok(quarantined)
}

fn structurally_validate_generation(
    generations: &File,
    generation_name: &str,
) -> Result<(), DurableLocalVectorError> {
    let generation = open_private_directory_at(generations, generation_name)?;
    let names = list_directory_names(&generation)?;
    let expected = [OsString::from(DATA_FILE), OsString::from(MANIFEST_FILE)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if names.into_iter().collect::<BTreeSet<_>>() != expected {
        return Err(corrupt_error());
    }
    validate_private_file_at(&generation, DATA_FILE, MAX_DURABLE_VECTOR_DATA_BYTES)?;
    validate_private_file_at(
        &generation,
        MANIFEST_FILE,
        MAX_DURABLE_VECTOR_MANIFEST_BYTES,
    )?;
    Ok(())
}

fn quarantine_entry(
    source: &File,
    name: &OsStr,
    quarantine: &File,
) -> Result<bool, DurableLocalVectorError> {
    use rustix::fs::{RenameFlags, renameat_with};

    if list_directory_names(quarantine)?.len() >= MAX_DURABLE_VECTOR_QUARANTINE_ENTRIES {
        // Quarantine is intentionally retained for diagnosis, but its top-level accumulation is
        // bounded. Refusing another move is fail-closed and leaves the source entry untouched.
        return Err(limit_error());
    }
    let destination = format!("{QUARANTINE_PREFIX}{}", random_suffix()?);
    match renameat_with(
        source,
        name,
        quarantine,
        &destination,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            source.sync_all().map_err(unavailable)?;
            quarantine.sync_all().map_err(unavailable)?;
            Ok(true)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(_error) => Err(unavailable_error()),
    }
}

fn quarantine_active_generation(
    generations: &File,
    root: &File,
    quarantine: &File,
    generation_id: &RecordId,
) -> Result<u64, DurableLocalVectorError> {
    let generation = u64::from(quarantine_entry(
        generations,
        OsStr::new(generation_id.as_str()),
        quarantine,
    )?);
    let activation = u64::from(quarantine_entry(
        root,
        OsStr::new(CURRENT_FILE),
        quarantine,
    )?);
    generation.checked_add(activation).ok_or_else(limit_error)
}

fn open_private_root(path: &Path) -> Result<File, DurableLocalVectorError> {
    use rustix::fs::{Mode, OFlags, open, openat};

    if !path.is_absolute() {
        return Err(invalid_error());
    }
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if names.is_empty() => {}
            Component::Normal(name) => names.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(invalid_error());
            }
        }
    }
    let (root_name, ancestors) = names.split_last().ok_or_else(invalid_error)?;
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| unavailable_error())?;
    validate_safe_ancestor(&directory.metadata().map_err(unavailable)?)?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            *ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_error| invalid_error())?;
        validate_safe_ancestor(&directory.metadata().map_err(unavailable)?)?;
    }
    let root = openat(
        &directory,
        *root_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| invalid_error())?;
    validate_private_directory(&root.metadata().map_err(unavailable)?)?;
    Ok(root)
}

fn validate_safe_ancestor(metadata: &std::fs::Metadata) -> Result<(), DurableLocalVectorError> {
    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if !metadata.is_dir()
        || (owner != 0 && owner != rustix::process::geteuid().as_raw())
        || (writable_by_others && !protected_sticky_root)
    {
        Err(invalid_error())
    } else {
        Ok(())
    }
}

fn validate_private_directory(metadata: &std::fs::Metadata) -> Result<(), DurableLocalVectorError> {
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        Err(invalid_error())
    } else {
        Ok(())
    }
}

fn ensure_private_subdirectory(parent: &File, name: &str) -> Result<File, DurableLocalVectorError> {
    use rustix::fs::{Mode, mkdirat};

    match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::EXIST => {}
        Err(_error) => return Err(unavailable_error()),
    }
    open_private_subdirectory(parent, name)
}

fn open_private_subdirectory(parent: &File, name: &str) -> Result<File, DurableLocalVectorError> {
    open_private_directory_at(parent, name)
}

fn open_private_directory_at(parent: &File, name: &str) -> Result<File, DurableLocalVectorError> {
    use rustix::fs::{Mode, OFlags, openat};

    let directory = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            DurableLocalVectorError::new(DurableLocalVectorErrorCode::NotFound)
        } else {
            invalid_error()
        }
    })?;
    validate_private_directory(&directory.metadata().map_err(unavailable)?)?;
    Ok(directory)
}

fn create_private_directory_at(parent: &File, name: &str) -> Result<File, DurableLocalVectorError> {
    use rustix::fs::{Mode, mkdirat};

    mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .map_err(|_error| unavailable_error())?;
    let directory = open_private_directory_at(parent, name)?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(unavailable)?;
    validate_private_directory(&directory.metadata().map_err(unavailable)?)?;
    Ok(directory)
}

fn create_private_file_at(parent: &File, name: &str) -> Result<File, DurableLocalVectorError> {
    use rustix::fs::{Mode, OFlags, openat};

    let file = openat(
        parent,
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|_error| unavailable_error())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(unavailable)?;
    validate_private_file_metadata(&file.metadata().map_err(unavailable)?, u64::MAX)?;
    Ok(file)
}

fn read_private_file_at(
    parent: &File,
    name: &str,
    maximum: u64,
) -> Result<Vec<u8>, DurableLocalVectorError> {
    use rustix::fs::{Mode, OFlags, openat};

    let mut file = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            DurableLocalVectorError::new(DurableLocalVectorErrorCode::NotFound)
        } else {
            corrupt_error()
        }
    })?;
    let before = file.metadata().map_err(unavailable)?;
    validate_private_file_metadata(&before, maximum)?;
    let capacity = usize::try_from(before.len()).map_err(|_error| limit_error())?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    let after = file.metadata().map_err(unavailable)?;
    validate_private_file_metadata(&after, maximum)?;
    if u64::try_from(bytes.len()).ok() != Some(before.len()) || !same_file_state(&before, &after) {
        return Err(corrupt_error());
    }
    Ok(bytes)
}

fn validate_private_file_at(
    parent: &File,
    name: &str,
    maximum: u64,
) -> Result<(), DurableLocalVectorError> {
    use rustix::fs::{Mode, OFlags, openat};

    let file = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            DurableLocalVectorError::new(DurableLocalVectorErrorCode::NotFound)
        } else {
            corrupt_error()
        }
    })?;
    validate_private_file_metadata(&file.metadata().map_err(unavailable)?, maximum)
}

fn validate_private_file_metadata(
    metadata: &std::fs::Metadata,
    maximum: u64,
) -> Result<(), DurableLocalVectorError> {
    if !metadata.is_file()
        || metadata.len() > maximum
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        Err(corrupt_error())
    } else {
        Ok(())
    }
}

fn same_file_state(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
}

fn list_directory_names(directory: &File) -> Result<Vec<OsString>, DurableLocalVectorError> {
    let mut stream = rustix::fs::Dir::read_from(directory).map_err(|_error| unavailable_error())?;
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let entry = entry.map_err(|_error| unavailable_error())?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(OsString::from_vec(bytes.to_vec()));
        if names.len() > MAX_DURABLE_VECTOR_GENERATIONS.saturating_add(16) {
            return Err(limit_error());
        }
    }
    names.sort();
    Ok(names)
}

fn rename_noreplace(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> Result<(), DurableLocalVectorError> {
    rustix::fs::renameat_with(
        source_directory,
        source_name,
        destination_directory,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            DurableLocalVectorError::new(DurableLocalVectorErrorCode::Conflict)
        } else {
            unavailable_error()
        }
    })
}

fn content_digest(bytes: &[u8]) -> Result<ContentDigest, DurableLocalVectorError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-DURABLE-LOCAL-VECTOR-CONTENT\0v1\0");
    hash_frame(&mut hasher, bytes).map_err(|_error| limit_error())?;
    finish_digest(hasher).map_err(|_error| corrupt_error())
}

fn random_suffix() -> Result<String, DurableLocalVectorError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_error| unavailable_error())?;
    let mut suffix = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in bytes {
        write!(&mut suffix, "{byte:02x}").map_err(|_error| unavailable_error())?;
    }
    Ok(suffix)
}

fn invalid_error() -> DurableLocalVectorError {
    DurableLocalVectorError::new(DurableLocalVectorErrorCode::InvalidMetadata)
}

fn limit_error() -> DurableLocalVectorError {
    DurableLocalVectorError::new(DurableLocalVectorErrorCode::LimitExceeded)
}

fn corrupt_error() -> DurableLocalVectorError {
    DurableLocalVectorError::new(DurableLocalVectorErrorCode::Corrupt)
}

fn unavailable_error() -> DurableLocalVectorError {
    DurableLocalVectorError::new(DurableLocalVectorErrorCode::Unavailable)
}

fn unavailable(_error: std::io::Error) -> DurableLocalVectorError {
    unavailable_error()
}

struct RootOperationLock(File);

impl Drop for RootOperationLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeterministicLocalVectorProcessor, LocalVectorAdapterEnablement, RetrievalContext,
        VectorQuery, configure_local_vector_adapter,
    };
    use cigar_store::CancellationToken;
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            format!("{value:02x}").repeat(32)
        ))?)
    }

    fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
        ))?)
    }

    fn version(value: u8) -> Result<VersionId, Box<dyn Error>> {
        Ok(VersionId::new(digest(value)?.as_str())?)
    }

    fn configuration(generation: u16) -> Result<LocalVectorConfiguration, Box<dyn Error>> {
        Ok(LocalVectorConfiguration::new(LocalVectorParameters {
            model_id: "provider-neutral/durable-model-v1".to_owned(),
            model_fingerprint: digest(230)?,
            dimension: 4,
            preprocessing_id: "approved-durable-preprocessing-v1".to_owned(),
            preprocessing_fingerprint: digest(231)?,
            distance_metric: LocalVectorDistanceMetric::SquaredEuclideanV1,
            quantization: LocalVectorQuantization::SymmetricInt8V1,
            partition_digest: digest(240)?,
            index_generation_id: record(generation)?,
            maximum_entries: 16,
            maximum_neighbors: 8,
        })?)
    }

    fn adapter(generation: u16, reverse: bool) -> Result<SealedLocalVectorAdapter, Box<dyn Error>> {
        let configuration = configuration(generation)?;
        let mut vectors = vec![
            (1, [10, 20, 30, 40]),
            (2, [10, 20, 30, 40]),
            (3, [-10, -20, -30, -40]),
        ];
        if reverse {
            vectors.reverse();
        }
        let entries = vectors
            .into_iter()
            .map(|(id, values)| {
                let vector = ProcessorApprovedVector::try_from_processor_output(
                    configuration.processor_binding().clone(),
                    &values,
                )?;
                Ok(LocalVectorEntry::new(version(id)?, vector))
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(configuration),
            entries,
        )?
        .ok_or_else(|| std::io::Error::other("enabled adapter missing").into())
    }

    fn private_root() -> Result<(tempfile::TempDir, PathBuf), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let parent = std::fs::canonicalize(temporary.path())?;
        let root = parent.join("durable-vector-root");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok((temporary, root))
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    fn generation_data_path(
        root: &Path,
        descriptor: &DurableLocalVectorGenerationDescriptor,
    ) -> PathBuf {
        root.join(GENERATIONS_DIRECTORY)
            .join(descriptor.index_binding.generation_id().as_str())
            .join(DATA_FILE)
    }

    #[test]
    fn canonical_generation_is_deterministic_restartable_and_policy_filtered()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = private_root()?;
        let forward = adapter(900, false)?;
        let reverse = adapter(900, true)?;
        assert_eq!(forward.index_binding(), reverse.index_binding());
        assert_eq!(encode_vector_data(&forward)?, encode_vector_data(&reverse)?);

        let store = DurableLocalVectorStore::open(&root)?;
        let descriptor = store.publish(&forward, StoreRevision(17))?;
        let repeated = store.publish(&reverse, StoreRevision(17))?;
        assert_eq!(descriptor, repeated);
        assert_eq!(
            store.activate(descriptor.index_binding.generation_id(), None)?,
            descriptor
        );

        let manifest_bytes = std::fs::read(
            root.join(GENERATIONS_DIRECTORY)
                .join(descriptor.index_binding.generation_id().as_str())
                .join(MANIFEST_FILE),
        )?;
        let manifest = decode_manifest(&manifest_bytes)?;
        assert_eq!(manifest.adapter_version, LOCAL_VECTOR_ADAPTER_VERSION);
        assert_eq!(manifest.model_id, "provider-neutral/durable-model-v1");
        assert_eq!(manifest.model_fingerprint, digest(230)?);
        assert_eq!(manifest.dimension, 4);
        assert_eq!(manifest.preprocessing_fingerprint, digest(231)?);
        assert_eq!(manifest.partition_digest, digest(240)?);
        assert_eq!(manifest.built_through_revision, StoreRevision(17));
        assert_eq!(manifest.vector_data_digest, descriptor.vector_data_digest);
        assert_eq!(content_digest(&manifest_bytes)?, descriptor.manifest_digest);
        drop(store);

        let reopened = DurableLocalVectorStore::open(&root)?;
        let startup = reopened.startup(StoreRevision(17))?;
        assert_eq!(startup.descriptor.as_ref(), Some(&descriptor));
        assert_eq!(startup.fallback_reason, None);
        assert_eq!(startup.quarantined_entries, 0);
        let loaded = startup
            .adapter()
            .ok_or_else(|| std::io::Error::other("adapter not loaded"))?;
        let configuration = configuration(900)?;
        let partition_digest = digest(240)?;
        let query = VectorQuery {
            partition_digest: partition_digest.clone(),
            index_binding: descriptor.index_binding.clone(),
            approved_vector: DeterministicLocalVectorProcessor::new(configuration)
                .approve_query_output(&partition_digest, &[10, 20, 30, 40])?,
            allowed_versions: [version(2)?].into_iter().collect(),
            limit: 1,
        };
        let neighbors = loaded.neighbors(&query, &context())?;
        assert_eq!(neighbors.len(), 1);
        assert_eq!(
            neighbors.first().map(|neighbor| &neighbor.version_id),
            Some(&version(2)?)
        );
        Ok(())
    }

    #[test]
    fn stale_watermark_and_missing_activation_select_deterministic_fallback()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = private_root()?;
        let store = DurableLocalVectorStore::open(&root)?;
        let empty = store.startup(StoreRevision(0))?;
        assert_eq!(
            empty.fallback_reason,
            Some(DurableLocalVectorFallbackReason::NoActiveGeneration)
        );
        let descriptor = store.publish(&adapter(901, false)?, StoreRevision(5))?;
        store.activate(descriptor.index_binding.generation_id(), None)?;
        let stale = store.startup(StoreRevision(6))?;
        assert_eq!(
            stale.fallback_reason,
            Some(DurableLocalVectorFallbackReason::StaleWatermark)
        );
        assert!(stale.adapter().is_none());
        assert_eq!(stale.quarantined_entries, 0);
        assert!(store.startup(StoreRevision(5))?.adapter().is_some());
        Ok(())
    }

    #[test]
    fn canonical_decoders_reject_trailing_or_noncanonical_bytes() -> Result<(), Box<dyn Error>> {
        let adapter = adapter(907, false)?;
        let mut data = encode_vector_data(&adapter)?;
        let data_digest = content_digest(&data)?;
        let manifest = GenerationManifest::from_adapter(&adapter, StoreRevision(6), data_digest)?;
        let configuration = manifest.configuration()?;
        data.push(0);
        assert!(decode_vector_data(&data, &manifest, &configuration).is_err());

        let mut manifest_bytes = encode_manifest(&manifest)?;
        manifest_bytes.push(0);
        assert!(decode_manifest(&manifest_bytes).is_err());

        let descriptor = manifest.descriptor(content_digest(&encode_manifest(&manifest)?)?);
        let mut activation = encode_activation(&ActivationPointer::from_descriptor(&descriptor))?;
        activation.push(0);
        assert!(decode_activation(&activation).is_err());
        Ok(())
    }

    #[test]
    fn corruption_and_invalid_activation_are_quarantined_without_vector_fallback()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = private_root()?;
        let store = DurableLocalVectorStore::open(&root)?;
        let descriptor = store.publish(&adapter(902, false)?, StoreRevision(9))?;
        store.activate(descriptor.index_binding.generation_id(), None)?;
        let data_path = generation_data_path(&root, &descriptor);
        let mut corrupt = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&data_path)?;
        corrupt.write_all(b"corrupt-vector-generation")?;
        corrupt.sync_all()?;
        drop(corrupt);

        let startup = store.startup(StoreRevision(9))?;
        assert_eq!(
            startup.fallback_reason,
            Some(DurableLocalVectorFallbackReason::CorruptGeneration)
        );
        assert!(startup.adapter().is_none());
        assert_eq!(startup.quarantined_entries, 2);
        assert!(!data_path.exists());
        assert!(!root.join(CURRENT_FILE).exists());

        let descriptor = store.publish(&adapter(903, false)?, StoreRevision(10))?;
        store.activate(descriptor.index_binding.generation_id(), None)?;
        let mut activation = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(root.join(CURRENT_FILE))?;
        activation.write_all(b"invalid-activation")?;
        activation.sync_all()?;
        drop(activation);
        let startup = store.startup(StoreRevision(10))?;
        assert_eq!(
            startup.fallback_reason,
            Some(DurableLocalVectorFallbackReason::InvalidActivation)
        );
        assert_eq!(startup.quarantined_entries, 1);
        assert!(startup.adapter().is_none());
        Ok(())
    }

    #[test]
    fn hostile_root_generation_data_links_and_incomplete_staged_generations_fail_closed()
    -> Result<(), Box<dyn Error>> {
        let (temporary, root) = private_root()?;
        let linked_root = std::fs::canonicalize(temporary.path())?.join("linked-root");
        std::os::unix::fs::symlink(&root, &linked_root)?;
        assert_eq!(
            DurableLocalVectorStore::open(&linked_root)
                .err()
                .map(DurableLocalVectorError::code),
            Some(DurableLocalVectorErrorCode::InvalidMetadata)
        );

        let store = DurableLocalVectorStore::open(&root)?;
        let descriptor = store.publish(&adapter(904, false)?, StoreRevision(11))?;
        store.activate(descriptor.index_binding.generation_id(), None)?;
        let data = generation_data_path(&root, &descriptor);
        let external_link = root.join("external-hard-link");
        std::fs::hard_link(&data, &external_link)?;
        let startup = store.startup(StoreRevision(11))?;
        assert_eq!(
            startup.fallback_reason,
            Some(DurableLocalVectorFallbackReason::CorruptGeneration)
        );
        assert!(startup.adapter().is_none());

        let descriptor = store.publish(&adapter(905, false)?, StoreRevision(12))?;
        store.activate(descriptor.index_binding.generation_id(), None)?;
        let data = generation_data_path(&root, &descriptor);
        let external_data = root.join("external-vector-data");
        std::fs::write(&external_data, std::fs::read(&data)?)?;
        std::fs::set_permissions(&external_data, std::fs::Permissions::from_mode(0o600))?;
        std::fs::remove_file(&data)?;
        std::os::unix::fs::symlink(&external_data, &data)?;
        let startup = store.startup(StoreRevision(12))?;
        assert_eq!(
            startup.fallback_reason,
            Some(DurableLocalVectorFallbackReason::CorruptGeneration)
        );
        assert!(startup.adapter().is_none());

        let incomplete_id = record(906)?;
        let incomplete = root
            .join(GENERATIONS_DIRECTORY)
            .join(incomplete_id.as_str());
        std::fs::create_dir(&incomplete)?;
        std::fs::set_permissions(&incomplete, std::fs::Permissions::from_mode(0o700))?;
        let startup = store.startup(StoreRevision(0))?;
        assert_eq!(
            startup.fallback_reason,
            Some(DurableLocalVectorFallbackReason::NoActiveGeneration)
        );
        assert_eq!(startup.quarantined_entries, 1);
        assert!(!incomplete.exists());
        Ok(())
    }

    #[test]
    fn many_large_inactive_generations_are_screened_without_content_verification()
    -> Result<(), Box<dyn Error>> {
        const INACTIVE_GENERATIONS: usize = 64;
        const INACTIVE_DATA_BYTES: usize = 1024 * 1024;

        let (_temporary, root) = private_root()?;
        let store = DurableLocalVectorStore::open(&root)?;
        let generations = root.join(GENERATIONS_DIRECTORY);
        let invalid_data = vec![0_u8; INACTIVE_DATA_BYTES];
        let invalid_data_digest = content_digest(&invalid_data)?;
        let mut first_generation = None;

        for offset in 0..INACTIVE_GENERATIONS {
            let generation =
                u16::try_from(1_300_usize.checked_add(offset).ok_or_else(|| {
                    std::io::Error::other("inactive generation fixture overflow")
                })?)?;
            let candidate = adapter(generation, false)?;
            let manifest = GenerationManifest::from_adapter(
                &candidate,
                StoreRevision(1),
                invalid_data_digest.clone(),
            )?;
            let generation_id = candidate.index_binding().generation_id().clone();
            first_generation.get_or_insert_with(|| generation_id.clone());
            let directory = generations.join(generation_id.as_str());
            std::fs::create_dir(&directory)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;

            let data_path = directory.join(DATA_FILE);
            let data_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&data_path)?;
            data_file.set_len(u64::try_from(INACTIVE_DATA_BYTES)?)?;
            data_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            drop(data_file);

            let manifest_path = directory.join(MANIFEST_FILE);
            std::fs::write(&manifest_path, encode_manifest(&manifest)?)?;
            std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))?;
        }

        let startup = store.startup(StoreRevision(0))?;
        assert_eq!(
            startup.fallback_reason,
            Some(DurableLocalVectorFallbackReason::NoActiveGeneration)
        );
        assert_eq!(startup.quarantined_entries, 0);
        assert_eq!(
            list_directory_names(&open_private_subdirectory(
                &store.root,
                GENERATIONS_DIRECTORY,
            )?)?
            .len(),
            INACTIVE_GENERATIONS
        );

        // Full content verification is deferred until an inactive generation is selected.
        let first_generation = first_generation
            .ok_or_else(|| std::io::Error::other("inactive generation fixture missing"))?;
        assert_eq!(
            store
                .activate(&first_generation, None)
                .err()
                .map(DurableLocalVectorError::code),
            Some(DurableLocalVectorErrorCode::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn quarantine_retention_has_a_fixed_top_level_entry_cap() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = private_root()?;
        let store = DurableLocalVectorStore::open(&root)?;
        let quarantine = open_private_subdirectory(&store.root, QUARANTINE_DIRECTORY)?;

        for offset in 0..MAX_DURABLE_VECTOR_QUARANTINE_ENTRIES {
            let name = format!("{ACTIVATION_PREFIX}bounded-{offset:02}");
            drop(create_private_file_at(&store.root, &name)?);
            assert!(quarantine_entry(
                &store.root,
                OsStr::new(&name),
                &quarantine,
            )?);
        }
        let overflow = format!("{ACTIVATION_PREFIX}overflow");
        drop(create_private_file_at(&store.root, &overflow)?);
        assert_eq!(
            quarantine_entry(&store.root, OsStr::new(&overflow), &quarantine)
                .err()
                .map(DurableLocalVectorError::code),
            Some(DurableLocalVectorErrorCode::LimitExceeded)
        );
        assert_eq!(
            list_directory_names(&quarantine)?.len(),
            MAX_DURABLE_VECTOR_QUARANTINE_ENTRIES
        );
        assert!(root.join(&overflow).exists());
        Ok(())
    }

    #[test]
    fn every_generation_publication_failpoint_is_restart_recoverable() -> Result<(), Box<dyn Error>>
    {
        let failpoints = [
            DurableLocalVectorFailpoint::AfterGenerationTemporaryCreate,
            DurableLocalVectorFailpoint::AfterDataFileCreate,
            DurableLocalVectorFailpoint::AfterDataWrite,
            DurableLocalVectorFailpoint::AfterDataSync,
            DurableLocalVectorFailpoint::AfterManifestFileCreate,
            DurableLocalVectorFailpoint::AfterManifestWrite,
            DurableLocalVectorFailpoint::AfterManifestSync,
            DurableLocalVectorFailpoint::AfterGenerationDirectorySync,
            DurableLocalVectorFailpoint::AfterGenerationRename,
            DurableLocalVectorFailpoint::AfterGenerationsParentSync,
        ];
        for (offset, failpoint) in failpoints.into_iter().enumerate() {
            let (_temporary, root) = private_root()?;
            let generation = u16::try_from(
                1_000_usize
                    .checked_add(offset)
                    .ok_or_else(|| std::io::Error::other("generation fixture overflow"))?,
            )?;
            let adapter = adapter(generation, false)?;
            let store = DurableLocalVectorStore::open(&root)?;
            store.inject_failpoint(failpoint)?;
            assert_eq!(
                store
                    .publish(&adapter, StoreRevision(21))
                    .err()
                    .map(DurableLocalVectorError::code),
                Some(DurableLocalVectorErrorCode::InjectedAbort),
                "failpoint did not trip: {failpoint:?}"
            );
            drop(store);

            let reopened = DurableLocalVectorStore::open(&root)?;
            let recovery = reopened.startup(StoreRevision(0))?;
            assert_eq!(
                recovery.fallback_reason,
                Some(DurableLocalVectorFallbackReason::NoActiveGeneration)
            );
            let descriptor = reopened.publish(&adapter, StoreRevision(21))?;
            reopened.activate(descriptor.index_binding.generation_id(), None)?;
            drop(reopened);
            let verified = DurableLocalVectorStore::open(&root)?.startup(StoreRevision(21))?;
            assert!(
                verified.adapter().is_some(),
                "restart failed after {failpoint:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn every_activation_failpoint_has_one_reconcilable_current_generation()
    -> Result<(), Box<dyn Error>> {
        let failpoints = [
            DurableLocalVectorFailpoint::AfterActivationTemporaryCreate,
            DurableLocalVectorFailpoint::AfterActivationWrite,
            DurableLocalVectorFailpoint::AfterActivationSync,
            DurableLocalVectorFailpoint::AfterActivationRename,
            DurableLocalVectorFailpoint::AfterActivationParentSync,
        ];
        for (offset, failpoint) in failpoints.into_iter().enumerate() {
            let (_temporary, root) = private_root()?;
            let generation = u16::try_from(
                1_100_usize
                    .checked_add(offset)
                    .ok_or_else(|| std::io::Error::other("activation fixture overflow"))?,
            )?;
            let adapter = adapter(generation, false)?;
            let store = DurableLocalVectorStore::open(&root)?;
            let descriptor = store.publish(&adapter, StoreRevision(31))?;
            store.inject_failpoint(failpoint)?;
            assert_eq!(
                store
                    .activate(descriptor.index_binding.generation_id(), None)
                    .err()
                    .map(DurableLocalVectorError::code),
                Some(DurableLocalVectorErrorCode::InjectedAbort)
            );
            drop(store);

            let reopened = DurableLocalVectorStore::open(&root)?;
            let recovery = reopened.startup(StoreRevision(31))?;
            if recovery.adapter().is_none() {
                assert_eq!(
                    recovery.fallback_reason,
                    Some(DurableLocalVectorFallbackReason::NoActiveGeneration)
                );
                reopened.activate(descriptor.index_binding.generation_id(), None)?;
            } else {
                assert_eq!(recovery.descriptor.as_ref(), Some(&descriptor));
            }
            drop(reopened);
            let verified = DurableLocalVectorStore::open(&root)?.startup(StoreRevision(31))?;
            assert_eq!(verified.descriptor.as_ref(), Some(&descriptor));
            assert!(verified.adapter().is_some());
        }
        Ok(())
    }

    #[test]
    fn activation_cas_serializes_competing_generations() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = private_root()?;
        let store = DurableLocalVectorStore::open(&root)?;
        let first = store.publish(&adapter(1_200, false)?, StoreRevision(41))?;
        let second = store.publish(&adapter(1_201, false)?, StoreRevision(41))?;
        drop(store);

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        let stores = [
            DurableLocalVectorStore::open(&root)?,
            DurableLocalVectorStore::open(&root)?,
        ];
        for (descriptor, store) in [first.clone(), second.clone()].into_iter().zip(stores) {
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                store.activate(descriptor.index_binding.generation_id(), None)
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_panic| std::io::Error::other("activation worker panicked"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    result
                        .as_ref()
                        .err()
                        .is_some_and(|error| error.code() == DurableLocalVectorErrorCode::Conflict)
                })
                .count(),
            1
        );
        let startup = DurableLocalVectorStore::open(&root)?.startup(StoreRevision(41))?;
        let active = startup
            .descriptor
            .as_ref()
            .ok_or_else(|| std::io::Error::other("race left no active generation"))?;
        assert!(active == &first || active == &second);
        assert!(startup.adapter().is_some());
        Ok(())
    }
}
