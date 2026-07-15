//! Optional durable deterministic local-vector projection for the native macOS cohort.

use crate::LocalVectorSettings;
use cigar_protocol::{AtomPayload, ContentDigest, ContextAtomV1, RecordId};
use cigar_retrieval::{
    DETERMINISTIC_LOCAL_VECTOR_MODEL_ID, DETERMINISTIC_LOCAL_VECTOR_PREPROCESSING_ID,
    DeterministicLocalVectorProcessor, DurableLocalVectorStore, InMemoryIndexManager,
    IndexSnapshot, LocalVectorAdapterEnablement, LocalVectorConfiguration,
    LocalVectorDistanceMetric, LocalVectorEntry, LocalVectorParameters, LocalVectorQuantization,
    QueryVectorProcessor, RetrievalContext, SealedLocalVectorAdapter, VectorAdapter,
    VectorIndexBinding, configure_local_vector_adapter,
};
use cigar_store::StoreRevision;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

const MODEL_FINGERPRINT_DOMAIN: &[u8] =
    b"cigar.deterministic-local-feature-hash.rust.v1\0sha2-256\0signed-int8";
const PREPROCESSING_FINGERPRINT_DOMAIN: &[u8] =
    b"cigar.normalized-term-set.rust.v1\0unicode-alphanumeric-underscore\0lowercase";

/// Content-free construction failure after the validated daemon configuration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionLocalVectorConfigurationError;

impl std::fmt::Display for ProductionLocalVectorConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("local vector configuration is invalid")
    }
}

impl std::error::Error for ProductionLocalVectorConfigurationError {}

/// Optional production-owned durable projection and trusted post-authorization query processor.
pub struct ProductionLocalVectorRuntime {
    root_directory: PathBuf,
    dimension: usize,
    maximum_entries: usize,
    maximum_neighbors: usize,
    model_fingerprint: ContentDigest,
    preprocessing_fingerprint: ContentDigest,
    projection_domain_digest: ContentDigest,
    query_processor: Arc<DeterministicLocalVectorProcessor>,
}

impl ProductionLocalVectorRuntime {
    /// Constructs an enabled runtime without opening storage or processing catalog content.
    pub fn new(
        settings: &LocalVectorSettings,
    ) -> Result<Self, ProductionLocalVectorConfigurationError> {
        if !settings.enabled {
            return Err(ProductionLocalVectorConfigurationError);
        }
        let root_directory = settings
            .root_directory
            .clone()
            .ok_or(ProductionLocalVectorConfigurationError)?;
        let model_fingerprint = content_digest(MODEL_FINGERPRINT_DOMAIN)
            .map_err(|()| ProductionLocalVectorConfigurationError)?;
        let preprocessing_fingerprint = content_digest(PREPROCESSING_FINGERPRINT_DOMAIN)
            .map_err(|()| ProductionLocalVectorConfigurationError)?;
        let projection_domain_digest = projection_domain_digest(settings)
            .map_err(|()| ProductionLocalVectorConfigurationError)?;
        let placeholder_generation = deterministic_record(&[
            b"CIGAR-PRODUCTION-LOCAL-VECTOR-QUERY-PROFILE\0v1\0",
            projection_domain_digest.as_str().as_bytes(),
        ])
        .map_err(|()| ProductionLocalVectorConfigurationError)?;
        let query_configuration = configuration(
            settings,
            model_fingerprint.clone(),
            preprocessing_fingerprint.clone(),
            projection_domain_digest.clone(),
            placeholder_generation,
        )
        .map_err(|()| ProductionLocalVectorConfigurationError)?;
        Ok(Self {
            root_directory,
            dimension: settings.dimension,
            maximum_entries: settings.maximum_entries,
            maximum_neighbors: settings.maximum_neighbors,
            model_fingerprint,
            preprocessing_fingerprint,
            projection_domain_digest,
            query_processor: Arc::new(DeterministicLocalVectorProcessor::new(query_configuration)),
        })
    }

    /// Returns the trusted processor injected into query planning after policy authorization.
    #[must_use]
    pub fn query_processor(&self) -> Arc<dyn QueryVectorProcessor> {
        self.query_processor.clone()
    }

    /// Rebuilds, verifies, persists, and installs one exact catalog generation.
    ///
    /// Any optional-channel failure removes the adapter and returns `None`; mandatory index
    /// correctness and availability remain independent.
    pub fn rebuild(
        &self,
        snapshot: &IndexSnapshot,
        revision: StoreRevision,
        manager: &InMemoryIndexManager,
        context: &RetrievalContext,
    ) -> Option<VectorIndexBinding> {
        match self.try_rebuild(snapshot, revision, context) {
            Ok(adapter) => {
                let binding = adapter.index_binding().clone();
                let adapter: Arc<dyn VectorAdapter> = Arc::new(adapter);
                if manager.replace_vector_adapter(Some(adapter)).is_ok() {
                    Some(binding)
                } else {
                    None
                }
            }
            Err(()) => {
                let _ignored = manager.replace_vector_adapter(None);
                None
            }
        }
    }

    fn try_rebuild(
        &self,
        snapshot: &IndexSnapshot,
        revision: StoreRevision,
        context: &RetrievalContext,
    ) -> Result<SealedLocalVectorAdapter, ()> {
        context.check().map_err(|_error| ())?;
        let generation_id = generation_id(snapshot, revision, &self.projection_domain_digest)?;
        let configuration = LocalVectorConfiguration::new(LocalVectorParameters {
            model_id: DETERMINISTIC_LOCAL_VECTOR_MODEL_ID.to_owned(),
            model_fingerprint: self.model_fingerprint.clone(),
            dimension: self.dimension,
            preprocessing_id: DETERMINISTIC_LOCAL_VECTOR_PREPROCESSING_ID.to_owned(),
            preprocessing_fingerprint: self.preprocessing_fingerprint.clone(),
            distance_metric: LocalVectorDistanceMetric::SquaredEuclideanV1,
            quantization: LocalVectorQuantization::SymmetricInt8V1,
            partition_digest: self.projection_domain_digest.clone(),
            index_generation_id: generation_id,
            maximum_entries: self.maximum_entries,
            maximum_neighbors: self.maximum_neighbors,
        })
        .map_err(|_error| ())?;
        let processor = DeterministicLocalVectorProcessor::new(configuration.clone());
        let mut entries = Vec::new();
        for (index, atom) in snapshot.atoms.iter().enumerate() {
            if index % 256 == 0 {
                context.check().map_err(|_error| ())?;
            }
            if !atom.retrieval.embedding_eligible {
                continue;
            }
            let terms = atom_terms(atom);
            if terms.is_empty() {
                continue;
            }
            let vector = processor.approve_index_terms(&terms).map_err(|_error| ())?;
            entries.push(LocalVectorEntry::new(atom.version_id.clone(), vector));
            if entries.len() > self.maximum_entries {
                return Err(());
            }
        }
        let adapter = configure_local_vector_adapter(
            LocalVectorAdapterEnablement::Enabled(configuration),
            entries,
        )
        .map_err(|_error| ())?
        .ok_or(())?;

        let store = DurableLocalVectorStore::open(&self.root_directory).map_err(|_error| ())?;
        let current = store.startup(StoreRevision(0)).map_err(|_error| ())?;
        let expected_current = current
            .descriptor
            .as_ref()
            .map(|descriptor| descriptor.index_binding.generation_id().clone());
        if current.descriptor.as_ref().is_some_and(|descriptor| {
            descriptor.built_through_revision == revision
                && descriptor.index_binding == *adapter.index_binding()
        }) {
            return current.into_adapter().ok_or(());
        }
        let descriptor = store.publish(&adapter, revision).map_err(|_error| ())?;
        store
            .activate(
                descriptor.index_binding.generation_id(),
                expected_current.as_ref(),
            )
            .map_err(|_error| ())?;
        Ok(adapter)
    }
}

impl std::fmt::Debug for ProductionLocalVectorRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionLocalVectorRuntime")
            .field("dimension", &self.dimension)
            .field("maximum_entries", &self.maximum_entries)
            .field("maximum_neighbors", &self.maximum_neighbors)
            .finish_non_exhaustive()
    }
}

fn configuration(
    settings: &LocalVectorSettings,
    model_fingerprint: ContentDigest,
    preprocessing_fingerprint: ContentDigest,
    projection_domain_digest: ContentDigest,
    generation_id: RecordId,
) -> Result<LocalVectorConfiguration, ()> {
    LocalVectorConfiguration::new(LocalVectorParameters {
        model_id: DETERMINISTIC_LOCAL_VECTOR_MODEL_ID.to_owned(),
        model_fingerprint,
        dimension: settings.dimension,
        preprocessing_id: DETERMINISTIC_LOCAL_VECTOR_PREPROCESSING_ID.to_owned(),
        preprocessing_fingerprint,
        distance_metric: LocalVectorDistanceMetric::SquaredEuclideanV1,
        quantization: LocalVectorQuantization::SymmetricInt8V1,
        partition_digest: projection_domain_digest,
        index_generation_id: generation_id,
        maximum_entries: settings.maximum_entries,
        maximum_neighbors: settings.maximum_neighbors,
    })
    .map_err(|_error| ())
}

fn atom_terms(atom: &ContextAtomV1) -> BTreeSet<String> {
    let mut terms = BTreeSet::new();
    for declared in &atom.retrieval.exact_terms {
        insert_terms(declared, &mut terms);
    }
    if let AtomPayload::InlineText(text) = &atom.payload {
        insert_terms(text, &mut terms);
    }
    terms
}

fn insert_terms(input: &str, output: &mut BTreeSet<String>) {
    for raw in input.split(|character: char| !character.is_alphanumeric() && character != '_') {
        if raw.is_empty() {
            continue;
        }
        let term = raw.to_lowercase();
        if term.len() <= 256 {
            output.insert(term);
            while output.len() > cigar_retrieval::MAX_QUERY_TERMS {
                let Some(last) = output.last().cloned() else {
                    break;
                };
                output.remove(&last);
            }
        }
    }
}

fn projection_domain_digest(settings: &LocalVectorSettings) -> Result<ContentDigest, ()> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PRODUCTION-LOCAL-VECTOR-PROJECTION-DOMAIN\0v1\0");
    hasher.update(settings.dimension.to_be_bytes());
    hasher.update(settings.maximum_entries.to_be_bytes());
    hasher.update(settings.maximum_neighbors.to_be_bytes());
    content_digest(&hasher.finalize())
}

fn generation_id(
    snapshot: &IndexSnapshot,
    revision: StoreRevision,
    projection_domain_digest: &ContentDigest,
) -> Result<RecordId, ()> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PRODUCTION-LOCAL-VECTOR-GENERATION\0v1\0");
    hasher.update(projection_domain_digest.as_str().as_bytes());
    hasher.update(revision.0.to_be_bytes());
    for (tenant, watermark) in &snapshot.tenant_watermarks {
        hasher.update(tenant.as_str().as_bytes());
        hasher.update(watermark.0.to_be_bytes());
    }
    for atom in &snapshot.atoms {
        if atom.retrieval.embedding_eligible {
            hasher.update(atom.version_id.as_str().as_bytes());
            hasher.update(atom.content_digest.as_str().as_bytes());
        }
    }
    deterministic_record(&[
        b"CIGAR-PRODUCTION-LOCAL-VECTOR-GENERATION-ID\0v1\0",
        &hasher.finalize(),
    ])
}

fn content_digest(bytes: &[u8]) -> Result<ContentDigest, ()> {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").map_err(|_error| ())?;
    }
    ContentDigest::new(encoded).map_err(|_error| ())
}

fn deterministic_record(parts: &[&[u8]]) -> Result<RecordId, ()> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    RecordId::new(format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    ))
    .map_err(|_error| ())
}

#[cfg(test)]
mod tests {
    use super::ProductionLocalVectorRuntime;
    use crate::LocalVectorSettings;
    use cigar_protocol::{AtomPayload, ContextAtomV1};
    use cigar_retrieval::{InMemoryIndexManager, IndexBuild, IndexSnapshot, RetrievalContext};
    use cigar_store::{CancellationToken, StoreRevision};
    use cigar_testkit::deterministic_protocol_fixture;
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fs;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn settings(root: &std::path::Path) -> LocalVectorSettings {
        LocalVectorSettings {
            enabled: true,
            root_directory: Some(root.to_path_buf()),
            dimension: 64,
            maximum_entries: 128,
            maximum_neighbors: 16,
        }
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    fn snapshot() -> Result<IndexSnapshot, Box<dyn Error>> {
        let fixture = deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing ContextAtomV1 fixture")?;
        let mut atom: ContextAtomV1 = serde_json::from_value(fixture.input)?;
        atom.payload = AtomPayload::InlineText("authorized vector retrieval term".to_owned());
        atom.retrieval.embedding_eligible = true;
        atom.retrieval.lexical_enabled = true;
        let tenant = atom.scope.tenant_id.clone();
        Ok(IndexSnapshot {
            atoms: vec![atom],
            edges: Vec::new(),
            tenant_watermarks: BTreeMap::from([(tenant, StoreRevision(1))]),
        })
    }

    #[test]
    fn restart_corruption_repair_and_storage_outage_preserve_mandatory_generation()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("vectors");
        fs::create_dir(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let root = fs::canonicalize(root)?;
        let settings = settings(&root);
        let snapshot = snapshot()?;
        let runtime = ProductionLocalVectorRuntime::new(&settings).map_err(|_error| "runtime")?;
        let manager = Arc::new(InMemoryIndexManager::default());
        let binding = runtime
            .rebuild(&snapshot, StoreRevision(1), &manager, &context())
            .ok_or("vector build failed")?;
        let descriptor = manager.build_generation(
            IndexBuild {
                atoms: snapshot.atoms.clone(),
                edges: Vec::new(),
                built_through_revision: StoreRevision(1),
                tenant_watermarks: snapshot.tenant_watermarks.clone(),
                configuration_digest: super::content_digest(b"mandatory-index")
                    .map_err(|()| "digest")?,
                verified_at: cigar_protocol::UtcTimestamp::parse_rfc3339("2026-07-14T00:00:00Z")?,
                vector_binding: Some(binding.clone()),
            },
            &context(),
        )?;
        manager.activate(&descriptor.generation_id, None)?;

        let restarted = InMemoryIndexManager::default();
        assert_eq!(
            ProductionLocalVectorRuntime::new(&settings)
                .map_err(|_error| "runtime")?
                .rebuild(&snapshot, StoreRevision(1), &restarted, &context()),
            Some(binding.clone())
        );

        fs::write(root.join("current.cigar-vector"), b"corrupt activation")?;
        assert_eq!(
            runtime.rebuild(&snapshot, StoreRevision(1), &manager, &context()),
            Some(binding)
        );

        fs::remove_dir_all(&root)?;
        fs::write(&root, b"unavailable")?;
        assert!(
            runtime
                .rebuild(&snapshot, StoreRevision(1), &manager, &context())
                .is_none()
        );
        assert_eq!(
            manager
                .active_generation()?
                .ok_or("mandatory generation disappeared")?
                .generation_id,
            descriptor.generation_id
        );
        Ok(())
    }
}
