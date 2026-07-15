//! Verified immutable in-memory index generations and authorization-first retrieval.

use crate::{
    CandidateBatch, CandidateFeatures, CandidateRef, IndexGenerationState, IndexKind,
    MatchEvidence, RetrievalConsistency, RetrievalContext, RetrievalDisclosure, RetrievalError,
    RetrievalErrorCode, RetrievalRequest, RetrievalStage, Retriever, VectorAdapter,
    VectorIndexBinding, VectorQuery,
};
use cigar_policy::RetrievalResourceAuthorizationRequest;
use cigar_protocol::{
    AtomPayload, Classification, ContentDigest, ContextAtomV1, ContextEdge, InstructionAuthority,
    Lifecycle, LineageId, RecordId, RelativePath, UtcTimestamp, Validate, VersionId,
};
use cigar_store::StoreRevision;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, RwLock};

/// Maximum canonical atoms accepted by one local generation build.
pub const MAX_INDEX_ATOMS: usize = 1_000_000;
/// Maximum graph edges accepted by one local generation build.
pub const MAX_INDEX_EDGES: usize = 10_000_000;

/// Complete canonical input for one disposable projection generation.
#[derive(Clone)]
pub struct IndexBuild {
    /// Canonical immutable atom set.
    pub atoms: Vec<ContextAtomV1>,
    /// Canonical immutable edge set.
    pub edges: Vec<ContextEdge>,
    /// Catalog revision represented by the input.
    pub built_through_revision: StoreRevision,
    /// Per-tenant catalog revisions represented by the input, including known empty tenants.
    pub tenant_watermarks: BTreeMap<RecordId, StoreRevision>,
    /// Analyzer, tokenizer, projection, and optional-vector configuration digest.
    pub configuration_digest: ContentDigest,
    /// Verification time supplied by the deterministic caller clock.
    pub verified_at: UtcTimestamp,
    /// Optional immutable vector projection generation and complete adapter fingerprint.
    pub vector_binding: Option<VectorIndexBinding>,
}

impl fmt::Debug for IndexBuild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexBuild")
            .field("atom_count", &self.atoms.len())
            .field("edge_count", &self.edges.len())
            .field("built_through_revision", &self.built_through_revision)
            .field("tenant_count", &self.tenant_watermarks.len())
            .field("configuration_digest", &self.configuration_digest)
            .field("verified_at", &self.verified_at)
            .field("vector_enabled", &self.vector_binding.is_some())
            .finish()
    }
}

/// Public immutable generation metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct IndexGenerationDescriptor {
    /// Deterministic generation identity.
    pub generation_id: RecordId,
    /// Build, verification, activation, or corruption state.
    pub state: IndexGenerationState,
    /// Catalog revision represented by every required projection.
    pub built_through_revision: StoreRevision,
    tenant_watermarks: BTreeMap<RecordId, StoreRevision>,
    /// Analyzer/projection configuration digest.
    pub configuration_digest: ContentDigest,
    /// Root over canonical indexed semantics.
    pub semantic_root: ContentDigest,
    /// Fingerprint bound into candidate evidence.
    pub index_fingerprint: ContentDigest,
    /// Optional immutable vector projection generation and complete adapter fingerprint.
    pub vector_binding: Option<VectorIndexBinding>,
    /// Required and optional projections present.
    pub projections: BTreeSet<IndexKind>,
    /// Last successful verification time.
    pub last_verified_at: UtcTimestamp,
}

impl IndexGenerationDescriptor {
    /// Returns the catalog revision represented for an authorized tenant.
    #[must_use]
    pub fn tenant_watermark(&self, tenant_id: &RecordId) -> Option<StoreRevision> {
        self.tenant_watermarks.get(tenant_id).copied()
    }
}

impl fmt::Debug for IndexGenerationDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexGenerationDescriptor")
            .field("generation_id", &self.generation_id)
            .field("state", &self.state)
            .field("built_through_revision", &self.built_through_revision)
            .field("tenant_count", &self.tenant_watermarks.len())
            .field("configuration_digest", &self.configuration_digest)
            .field("semantic_root", &self.semantic_root)
            .field("index_fingerprint", &self.index_fingerprint)
            .field("vector_enabled", &self.vector_binding.is_some())
            .field("projections", &self.projections)
            .field("last_verified_at", &self.last_verified_at)
            .finish()
    }
}

#[derive(Clone)]
struct IndexedDocument {
    atom: ContextAtomV1,
    declared_terms: BTreeSet<String>,
    lexical_terms: BTreeSet<String>,
    estimated_tokens: u32,
}

impl fmt::Debug for IndexedDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexedDocument")
            .field("version_id", &self.atom.version_id)
            .field("declared_term_count", &self.declared_terms.len())
            .field("lexical_term_count", &self.lexical_terms.len())
            .field("estimated_tokens", &self.estimated_tokens)
            .finish()
    }
}

#[derive(Clone)]
struct IndexGeneration {
    descriptor: IndexGenerationDescriptor,
    documents: BTreeMap<VersionId, IndexedDocument>,
    adjacency: BTreeMap<VersionId, BTreeSet<VersionId>>,
    lineage_projection: LineageProjection,
    edge_projection: BTreeMap<LineageEdgeKey, BTreeSet<(VersionId, VersionId)>>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ScopeKey {
    tenant_id: RecordId,
    project_id: RecordId,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct TenantLineageKey {
    tenant_id: RecordId,
    lineage_id: LineageId,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct LineageEdgeKey {
    tenant_id: RecordId,
    first_lineage: LineageId,
    second_lineage: LineageId,
}

#[derive(Clone, Default)]
struct LineageProjection {
    project_versions: BTreeMap<ScopeKey, GovernanceVersionProjection>,
    histories: BTreeMap<TenantLineageKey, BTreeSet<VersionId>>,
}

#[derive(Clone, Default)]
struct GovernanceVersionProjection {
    purposes: BTreeMap<String, BTreeSet<VersionId>>,
    wildcard_purpose: BTreeSet<VersionId>,
    processors: BTreeMap<String, BTreeSet<VersionId>>,
    unrestricted_processor: BTreeSet<VersionId>,
    classifications: BTreeMap<Classification, BTreeSet<VersionId>>,
    instruction_authorities: BTreeMap<InstructionAuthority, BTreeSet<VersionId>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RetrievalWork {
    partition_lookups: usize,
    lineage_timelines: usize,
    timeline_versions: usize,
    lineage_winners: usize,
    policy_checks: usize,
    scored_candidates: usize,
    graph_lineage_pair_lookups: usize,
    authorized_graph_edges: usize,
}

#[derive(Default)]
struct ManagerState {
    staged: BTreeMap<RecordId, Arc<IndexGeneration>>,
    active: Option<Arc<IndexGeneration>>,
}

/// Thread-safe generation builder, verifier, activator, and retriever.
pub struct InMemoryIndexManager {
    state: RwLock<ManagerState>,
    vector_adapter: RwLock<Option<Arc<dyn VectorAdapter>>>,
}

impl Default for InMemoryIndexManager {
    fn default() -> Self {
        Self {
            state: RwLock::new(ManagerState::default()),
            vector_adapter: RwLock::new(None),
        }
    }
}

impl fmt::Debug for InMemoryIndexManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryIndexManager")
    }
}

impl InMemoryIndexManager {
    /// Creates a manager with one optional fingerprint-bound vector backend.
    #[must_use]
    pub fn with_vector_adapter(adapter: Arc<dyn VectorAdapter>) -> Self {
        Self {
            state: RwLock::new(ManagerState::default()),
            vector_adapter: RwLock::new(Some(adapter)),
        }
    }

    /// Atomically replaces the optional adapter used by future retrieval snapshots.
    ///
    /// A concurrent request can observe either complete adapter. If its active mandatory-index
    /// binding differs, the optional vector stage returns channel-unavailable and uses only its
    /// explicitly permitted non-vector fallback.
    pub fn replace_vector_adapter(
        &self,
        adapter: Option<Arc<dyn VectorAdapter>>,
    ) -> Result<(), RetrievalError> {
        *self
            .vector_adapter
            .write()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))? = adapter;
        Ok(())
    }

    /// Builds and verifies a complete unservable generation.
    pub fn build_generation(
        &self,
        build: IndexBuild,
        context: &RetrievalContext,
    ) -> Result<IndexGenerationDescriptor, RetrievalError> {
        context.check()?;
        {
            let adapter = self
                .vector_adapter
                .read()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
            if let (Some(adapter), Some(binding)) = (adapter.as_ref(), &build.vector_binding)
                && adapter.index_binding() != binding
            {
                return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
            }
        }
        if build.atoms.len() > MAX_INDEX_ATOMS || build.edges.len() > MAX_INDEX_EDGES {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        let mut documents = BTreeMap::new();
        for atom in build.atoms {
            context.check()?;
            atom.validate()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            let version = atom.version_id.clone();
            let document = index_document(atom)?;
            if documents.insert(version, document).is_some() {
                return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
            }
        }
        if documents.values().any(|document| {
            !build
                .tenant_watermarks
                .contains_key(&document.atom.scope.tenant_id)
        }) || build
            .tenant_watermarks
            .values()
            .any(|watermark| *watermark > build.built_through_revision)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        let mut adjacency: BTreeMap<VersionId, BTreeSet<VersionId>> = BTreeMap::new();
        let mut edge_projection = BTreeMap::new();
        for edge in build.edges {
            context.check()?;
            edge.validate()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            if !documents.contains_key(&edge.from_version)
                || !documents.contains_key(&edge.to_version)
            {
                return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
            }
            if edge.lifecycle == Lifecycle::Active {
                let from_document = documents
                    .get(&edge.from_version)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                let to_document = documents
                    .get(&edge.to_version)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                if from_document.atom.scope.tenant_id != to_document.atom.scope.tenant_id {
                    return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
                }
                let (first_lineage, second_lineage) =
                    if from_document.atom.lineage_id <= to_document.atom.lineage_id {
                        (
                            from_document.atom.lineage_id.clone(),
                            to_document.atom.lineage_id.clone(),
                        )
                    } else {
                        (
                            to_document.atom.lineage_id.clone(),
                            from_document.atom.lineage_id.clone(),
                        )
                    };
                let (first_version, second_version) = if edge.from_version <= edge.to_version {
                    (edge.from_version.clone(), edge.to_version.clone())
                } else {
                    (edge.to_version.clone(), edge.from_version.clone())
                };
                edge_projection
                    .entry(LineageEdgeKey {
                        tenant_id: from_document.atom.scope.tenant_id.clone(),
                        first_lineage,
                        second_lineage,
                    })
                    .or_insert_with(BTreeSet::new)
                    .insert((first_version, second_version));
                adjacency
                    .entry(edge.from_version.clone())
                    .or_default()
                    .insert(edge.to_version.clone());
                adjacency
                    .entry(edge.to_version)
                    .or_default()
                    .insert(edge.from_version);
            }
        }
        let semantic_root = semantic_root(&documents, &adjacency)?;
        let lineage_projection = lineage_projection(&documents);
        let index_fingerprint = fingerprint(
            &build.configuration_digest,
            &semantic_root,
            build.built_through_revision,
            &build.tenant_watermarks,
            build.vector_binding.as_ref(),
        )?;
        let generation_id = RecordId::new(deterministic_uuid(&[
            b"CIGAR-INDEX-GENERATION\0v1\0",
            index_fingerprint.as_str().as_bytes(),
        ]))
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let mut projections: BTreeSet<_> = [
            IndexKind::Exact,
            IndexKind::Scope,
            IndexKind::Path,
            IndexKind::Symbol,
            IndexKind::Entity,
            IndexKind::Temporal,
            IndexKind::Authority,
            IndexKind::Lexical,
            IndexKind::Graph,
            IndexKind::ActiveState,
        ]
        .into_iter()
        .collect();
        if build.vector_binding.is_some() {
            projections.insert(IndexKind::Vector);
        }
        let descriptor = IndexGenerationDescriptor {
            generation_id: generation_id.clone(),
            state: IndexGenerationState::Verified,
            built_through_revision: build.built_through_revision,
            tenant_watermarks: build.tenant_watermarks,
            configuration_digest: build.configuration_digest,
            semantic_root,
            index_fingerprint,
            vector_binding: build.vector_binding,
            projections,
            last_verified_at: build.verified_at,
        };
        let generation = Arc::new(IndexGeneration {
            descriptor: descriptor.clone(),
            documents,
            adjacency,
            lineage_projection,
            edge_projection,
        });
        self.state
            .write()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
            .staged
            .insert(generation_id, generation);
        Ok(descriptor)
    }

    /// Atomically activates a verified generation under an optional expected prior identity.
    pub fn activate(
        &self,
        generation_id: &RecordId,
        expected_active: Option<&RecordId>,
    ) -> Result<IndexGenerationDescriptor, RetrievalError> {
        let mut state = self
            .state
            .write()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        if state
            .active
            .as_ref()
            .map(|generation| &generation.descriptor.generation_id)
            != expected_active
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        let staged = state
            .staged
            .get(generation_id)
            .cloned()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        if staged.descriptor.state != IndexGenerationState::Verified
            || semantic_root(&staged.documents, &staged.adjacency)?
                != staged.descriptor.semantic_root
        {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        let mut active = staged.as_ref().clone();
        active.descriptor.state = IndexGenerationState::Active;
        let active = Arc::new(active);
        let descriptor = active.descriptor.clone();
        state.active = Some(active);
        Ok(descriptor)
    }

    /// Deletes a non-active disposable generation.
    pub fn delete_generation(&self, generation_id: &RecordId) -> Result<bool, RetrievalError> {
        let mut state = self
            .state
            .write()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        if state
            .active
            .as_ref()
            .is_some_and(|active| &active.descriptor.generation_id == generation_id)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        Ok(state.staged.remove(generation_id).is_some())
    }

    /// Quarantines a staged generation after an integrity failure.
    pub fn quarantine_generation(
        &self,
        generation_id: &RecordId,
    ) -> Result<IndexGenerationDescriptor, RetrievalError> {
        let mut state = self
            .state
            .write()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        if state
            .active
            .as_ref()
            .is_some_and(|active| &active.descriptor.generation_id == generation_id)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        let staged = state
            .staged
            .get(generation_id)
            .cloned()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        let mut corrupt = staged.as_ref().clone();
        corrupt.descriptor.state = IndexGenerationState::Corrupt;
        let descriptor = corrupt.descriptor.clone();
        state
            .staged
            .insert(generation_id.clone(), Arc::new(corrupt));
        Ok(descriptor)
    }

    /// Returns active generation metadata without exposing projection contents.
    pub fn active_generation(&self) -> Result<Option<IndexGenerationDescriptor>, RetrievalError> {
        Ok(self
            .state
            .read()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
            .active
            .as_ref()
            .map(|generation| generation.descriptor.clone()))
    }
}

impl Retriever for InMemoryIndexManager {
    fn retrieve(
        &self,
        request: &RetrievalRequest,
        context: &RetrievalContext,
    ) -> Result<CandidateBatch, RetrievalError> {
        self.retrieve_with_work(request, context)
            .map(|(batch, _work)| batch)
    }
}

impl InMemoryIndexManager {
    fn retrieve_with_work(
        &self,
        request: &RetrievalRequest,
        context: &RetrievalContext,
    ) -> Result<(CandidateBatch, RetrievalWork), RetrievalError> {
        context.check()?;
        request.validate()?;
        let generation = self
            .state
            .read()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
            .active
            .clone()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        let tenant_watermark = generation
            .descriptor
            .tenant_watermark(request.partition.tenant_id())
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        let lag = revision_lag(
            tenant_watermark,
            request.required_revision,
            request.consistency,
        )?;
        let mut work = RetrievalWork::default();
        let lineages = authorized_lineages(
            &generation.documents,
            &generation.lineage_projection,
            &request.partition,
            &mut work,
        );
        let authorized = authorized_current_documents(
            &generation.documents,
            &generation.lineage_projection,
            &lineages,
            request,
            &mut work,
        )?;
        let mut evidence_by_version: BTreeMap<VersionId, BTreeSet<MatchEvidence>> = BTreeMap::new();
        let mut semantic_scores = BTreeMap::new();
        let mut fallback_used = false;
        let mut authorized_vector_binding = None;
        let vector_adapter = self
            .vector_adapter
            .read()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
            .clone();
        match request.stage {
            RetrievalStage::Exact => {
                collect_exact_matches(request, &authorized, &mut evidence_by_version)
            }
            RetrievalStage::Metadata => {
                collect_metadata_matches(request, &authorized, &mut evidence_by_version)
            }
            RetrievalStage::Lexical => {
                collect_lexical_matches(request, &authorized, &mut evidence_by_version)
            }
            RetrievalStage::Graph => collect_graph_matches(
                request,
                &authorized,
                &generation.edge_projection,
                &mut evidence_by_version,
                context,
                &mut work,
            )?,
            RetrievalStage::Augment => {
                for version in authorized.keys() {
                    evidence_by_version
                        .entry(version.clone())
                        .or_default()
                        .insert(MatchEvidence::Augment);
                }
            }
            RetrievalStage::Vector => match collect_vector_matches(
                request,
                &authorized,
                &generation.descriptor,
                vector_adapter.as_deref(),
                &mut evidence_by_version,
                &mut semantic_scores,
                context,
            ) {
                Ok(binding) => authorized_vector_binding = Some(binding),
                Err(error)
                    if request.allow_fallback
                        && !matches!(
                            error.code(),
                            RetrievalErrorCode::Cancelled
                                | RetrievalErrorCode::DeadlineExceeded
                                | RetrievalErrorCode::Denied
                        ) =>
                {
                    fallback_used = true;
                    collect_lexical_matches(request, &authorized, &mut evidence_by_version);
                    collect_metadata_matches(request, &authorized, &mut evidence_by_version);
                }
                Err(error) => return Err(error),
            },
        }
        let mut candidates = Vec::new();
        for (version, evidence) in evidence_by_version {
            context.check()?;
            let document = authorized
                .get(&version)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            let features = candidate_features(
                document,
                &evidence,
                semantic_scores.get(&version).copied().unwrap_or_default(),
                lag,
            );
            let total_score = features.balanced_score()?;
            candidates.push(CandidateRef {
                version_id: version,
                canonical_uri: document.atom.source.uri.clone(),
                relative_path: document.atom.source.relative_path.clone(),
                instruction_authority: document.atom.governance.instruction_authority,
                features,
                total_score,
                evidence,
            });
            work.scored_candidates = work.scored_candidates.saturating_add(1);
        }
        candidates.sort_by(candidate_order);
        candidates.truncate(request.limit);
        request.partition.validate()?;
        let partition_semantic_root = partition_semantic_root(
            &authorized,
            &generation.edge_projection,
            request.partition.tenant_id(),
            &mut work,
        )?;
        let partition_fingerprint = partition_fingerprint(
            &generation.descriptor.configuration_digest,
            &partition_semantic_root,
            request.partition.partition_digest(),
            request.stage,
            authorized_vector_binding.as_ref(),
        )?;
        let partition_generation_id = RecordId::new(deterministic_uuid(&[
            b"CIGAR-AUTHORIZED-INDEX-GENERATION\0v1\0",
            partition_fingerprint.as_str().as_bytes(),
        ]))
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let visible_revision = StoreRevision(request.required_revision.0.saturating_sub(lag));
        let last_verified_at = authorized
            .values()
            .map(|document| document.atom.temporal.observed_at)
            .max()
            .unwrap_or_else(|| request.partition.observed_as_of());
        Ok((
            CandidateBatch {
                candidates,
                disclosure: RetrievalDisclosure {
                    generation_id: partition_generation_id,
                    index_fingerprint: partition_fingerprint,
                    built_through_revision: visible_revision,
                    actual_revision_lag: lag,
                    fallback_used,
                    last_verified_at,
                },
            },
            work,
        ))
    }
}

fn lineage_projection(documents: &BTreeMap<VersionId, IndexedDocument>) -> LineageProjection {
    let mut projection = LineageProjection::default();
    for (version, document) in documents {
        projection
            .histories
            .entry(TenantLineageKey {
                tenant_id: document.atom.scope.tenant_id.clone(),
                lineage_id: document.atom.lineage_id.clone(),
            })
            .or_default()
            .insert(version.clone());
        for project_id in &document.atom.scope.project_ids {
            let governance = projection
                .project_versions
                .entry(ScopeKey {
                    tenant_id: document.atom.scope.tenant_id.clone(),
                    project_id: project_id.clone(),
                })
                .or_default();
            for purpose in &document.atom.governance.allowed_purposes {
                if purpose == "*" {
                    governance.wildcard_purpose.insert(version.clone());
                } else {
                    governance
                        .purposes
                        .entry(purpose.clone())
                        .or_default()
                        .insert(version.clone());
                }
            }
            if document.atom.governance.processor_constraints.is_empty() {
                governance.unrestricted_processor.insert(version.clone());
            } else {
                for processor in &document.atom.governance.processor_constraints {
                    governance
                        .processors
                        .entry(processor.clone())
                        .or_default()
                        .insert(version.clone());
                }
            }
            governance
                .classifications
                .entry(document.atom.governance.classification)
                .or_default()
                .insert(version.clone());
            governance
                .instruction_authorities
                .entry(document.atom.governance.instruction_authority)
                .or_default()
                .insert(version.clone());
        }
    }
    projection
}

fn authorized_lineages(
    documents: &BTreeMap<VersionId, IndexedDocument>,
    projection: &LineageProjection,
    partition: &crate::AuthorizedPartition,
    work: &mut RetrievalWork,
) -> BTreeSet<LineageId> {
    let mut lineages = BTreeSet::new();
    for project_id in partition.project_ids() {
        work.partition_lookups = work.partition_lookups.saturating_add(1);
        let Some(governance) = projection.project_versions.get(&ScopeKey {
            tenant_id: partition.tenant_id().clone(),
            project_id: project_id.clone(),
        }) else {
            continue;
        };
        let mut purpose_versions = governance.wildcard_purpose.clone();
        if let Some(exact) = governance.purposes.get(partition.purpose()) {
            purpose_versions.extend(exact.iter().cloned());
        }
        let mut processor_versions = governance.unrestricted_processor.clone();
        if let Some(exact) = governance.processors.get(partition.processor()) {
            processor_versions.extend(exact.iter().cloned());
        }
        let classification_versions: BTreeSet<_> = governance
            .classifications
            .range(..=partition.maximum_classification())
            .flat_map(|(_classification, candidates)| candidates.iter().cloned())
            .collect();
        let authority_versions: BTreeSet<_> = governance
            .instruction_authorities
            .range(..=partition.maximum_instruction_authority())
            .flat_map(|(_authority, candidates)| candidates.iter().cloned())
            .collect();
        purpose_versions.retain(|version| {
            processor_versions.contains(version)
                && classification_versions.contains(version)
                && authority_versions.contains(version)
        });
        for version in purpose_versions {
            if let Some(document) = documents.get(&version) {
                lineages.insert(document.atom.lineage_id.clone());
            }
        }
    }
    work.lineage_timelines = lineages.len();
    lineages
}

fn authorized_current_documents<'a>(
    documents: &'a BTreeMap<VersionId, IndexedDocument>,
    projection: &LineageProjection,
    lineages: &BTreeSet<LineageId>,
    request: &RetrievalRequest,
    work: &mut RetrievalWork,
) -> Result<BTreeMap<VersionId, &'a IndexedDocument>, RetrievalError> {
    let mut authorized = BTreeMap::new();
    for lineage_id in lineages {
        let history = projection
            .histories
            .get(&TenantLineageKey {
                tenant_id: request.partition.tenant_id().clone(),
                lineage_id: lineage_id.clone(),
            })
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        work.timeline_versions = work.timeline_versions.saturating_add(history.len());
        let mut winner: Option<(VersionId, &'a IndexedDocument)> = None;
        for version in history {
            let document = documents
                .get(version)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            if document.atom.temporal.valid_from > request.partition.valid_at()
                || document
                    .atom
                    .temporal
                    .valid_until
                    .is_some_and(|valid_until| request.partition.valid_at() >= valid_until)
                || document.atom.temporal.observed_at > request.partition.observed_as_of()
            {
                continue;
            }
            match &winner {
                None => winner = Some((version.clone(), document)),
                Some((current_version, current_document)) => {
                    if document.atom.temporal.observed_at
                        > current_document.atom.temporal.observed_at
                    {
                        winner = Some((version.clone(), document));
                    } else if document.atom.temporal.observed_at
                        == current_document.atom.temporal.observed_at
                        && version != current_version
                    {
                        return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
                    }
                }
            }
        }
        let Some((version, document)) = winner else {
            continue;
        };
        work.lineage_winners = work.lineage_winners.saturating_add(1);
        if !winner_governance_allows(document, &request.partition) {
            continue;
        }
        work.policy_checks = work.policy_checks.saturating_add(1);
        let policy_request = RetrievalResourceAuthorizationRequest {
            input_digest: document.atom.content_digest.clone(),
            tenant_id: document.atom.scope.tenant_id.clone(),
            project_ids: document.atom.scope.project_ids.iter().cloned().collect(),
            allowed_purposes: document
                .atom
                .governance
                .allowed_purposes
                .iter()
                .cloned()
                .collect(),
            allowed_processors: document
                .atom
                .governance
                .processor_constraints
                .iter()
                .cloned()
                .collect(),
            classification: document.atom.governance.classification,
            lifecycle: document.atom.lifecycle,
            integrity_verified: true,
            valid_from: document.atom.temporal.valid_from,
            valid_until: document.atom.temporal.valid_until,
            observed_at: document.atom.temporal.observed_at,
            instruction_authority: document.atom.governance.instruction_authority,
        };
        if request
            .partition
            .authorize_resource(&policy_request, request.stage == RetrievalStage::Vector)?
        {
            authorized.insert(version, document);
        }
    }
    Ok(authorized)
}

fn winner_governance_allows(
    document: &IndexedDocument,
    partition: &crate::AuthorizedPartition,
) -> bool {
    document.atom.lifecycle == Lifecycle::Active
        && document.atom.scope.tenant_id == *partition.tenant_id()
        && document
            .atom
            .scope
            .project_ids
            .iter()
            .any(|project_id| partition.project_ids().contains(project_id))
        && document
            .atom
            .governance
            .allowed_purposes
            .iter()
            .any(|purpose| purpose == "*" || purpose == partition.purpose())
        && (document.atom.governance.processor_constraints.is_empty()
            || document
                .atom
                .governance
                .processor_constraints
                .iter()
                .any(|processor| processor == partition.processor()))
        && document.atom.governance.classification <= partition.maximum_classification()
        && document.atom.governance.instruction_authority
            <= partition.maximum_instruction_authority()
}

fn index_document(atom: ContextAtomV1) -> Result<IndexedDocument, RetrievalError> {
    let declared_terms = atom
        .retrieval
        .exact_terms
        .iter()
        .map(|term| normalize_term(term))
        .collect();
    let lexical_terms = if atom.retrieval.lexical_enabled {
        lexical_terms(&atom.payload)
    } else {
        BTreeSet::new()
    };
    let payload_bytes = match &atom.payload {
        AtomPayload::InlineText(value) => value.len(),
        AtomPayload::Structured(value) => format!("{value:?}").len(),
        AtomPayload::Blob(value) => usize::try_from(value.size_bytes)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
    };
    let estimated_tokens = u32::try_from(payload_bytes.saturating_add(3) / 4)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    Ok(IndexedDocument {
        atom,
        declared_terms,
        lexical_terms,
        estimated_tokens,
    })
}

fn lexical_terms(payload: &AtomPayload) -> BTreeSet<String> {
    let AtomPayload::InlineText(text) = payload else {
        return BTreeSet::new();
    };
    text.split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|term| !term.is_empty() && term.len() <= 256)
        .map(normalize_term)
        .collect()
}

fn normalize_term(term: &str) -> String {
    term.to_lowercase()
}

fn collect_exact_matches(
    request: &RetrievalRequest,
    authorized: &BTreeMap<VersionId, &IndexedDocument>,
    output: &mut BTreeMap<VersionId, BTreeSet<MatchEvidence>>,
) {
    for (version, document) in authorized {
        if request.exact_versions.contains(version)
            || request.atom_ids.contains(&document.atom.atom_id)
            || request.lineage_ids.contains(&document.atom.lineage_id)
            || request
                .content_digests
                .contains(&document.atom.content_digest)
            || request.canonical_uris.contains(&document.atom.source.uri)
            || request
                .source_revisions
                .contains(&document.atom.source.revision)
        {
            output
                .entry(version.clone())
                .or_default()
                .insert(MatchEvidence::ExactIdentity);
        }
    }
}

fn collect_metadata_matches(
    request: &RetrievalRequest,
    authorized: &BTreeMap<VersionId, &IndexedDocument>,
    output: &mut BTreeMap<VersionId, BTreeSet<MatchEvidence>>,
) {
    let terms: BTreeSet<_> = request
        .terms
        .iter()
        .map(|term| normalize_term(term))
        .collect();
    for (version, document) in authorized {
        let path_match = document
            .atom
            .source
            .relative_path
            .as_ref()
            .is_some_and(|path| request.paths.contains(path));
        let term_match = !terms.is_disjoint(&document.declared_terms);
        if path_match {
            output
                .entry(version.clone())
                .or_default()
                .insert(MatchEvidence::ExactPath);
        }
        if term_match {
            output
                .entry(version.clone())
                .or_default()
                .insert(MatchEvidence::DeclaredTerm);
        }
    }
}

fn collect_lexical_matches(
    request: &RetrievalRequest,
    authorized: &BTreeMap<VersionId, &IndexedDocument>,
    output: &mut BTreeMap<VersionId, BTreeSet<MatchEvidence>>,
) {
    let terms: BTreeSet<_> = request
        .terms
        .iter()
        .map(|term| normalize_term(term))
        .collect();
    if terms.is_empty() {
        return;
    }
    for (version, document) in authorized {
        if !terms.is_disjoint(&document.lexical_terms) {
            output
                .entry(version.clone())
                .or_default()
                .insert(MatchEvidence::Lexical);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_vector_matches(
    request: &RetrievalRequest,
    authorized: &BTreeMap<VersionId, &IndexedDocument>,
    descriptor: &IndexGenerationDescriptor,
    adapter: Option<&dyn VectorAdapter>,
    output: &mut BTreeMap<VersionId, BTreeSet<MatchEvidence>>,
    semantic_scores: &mut BTreeMap<VersionId, u16>,
    context: &RetrievalContext,
) -> Result<VectorIndexBinding, RetrievalError> {
    let adapter =
        adapter.ok_or_else(|| RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))?;
    if descriptor.vector_binding.as_ref() != Some(adapter.index_binding()) {
        return Err(RetrievalError::new(RetrievalErrorCode::ChannelUnavailable));
    }
    let index_binding = descriptor
        .vector_binding
        .clone()
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))?;
    let approved_vector = request
        .approved_vector
        .clone()
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))?;
    let query = VectorQuery {
        partition_digest: request.partition.partition_digest().clone(),
        index_binding,
        approved_vector,
        allowed_versions: authorized.keys().cloned().collect(),
        limit: request.limit,
    };
    let authorized_binding = adapter.authorized_partition_binding(&query, context)?;
    let neighbors = adapter.neighbors(&query, context)?;
    if neighbors.len() > request.limit {
        return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
    }
    for neighbor in neighbors {
        context.check()?;
        if neighbor.similarity > crate::MAX_FEATURE_VALUE
            || !authorized.contains_key(&neighbor.version_id)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        output
            .entry(neighbor.version_id.clone())
            .or_default()
            .insert(MatchEvidence::Vector);
        semantic_scores
            .entry(neighbor.version_id)
            .and_modify(|score| *score = (*score).max(neighbor.similarity))
            .or_insert(neighbor.similarity);
    }
    Ok(authorized_binding)
}

fn collect_graph_matches(
    request: &RetrievalRequest,
    authorized: &BTreeMap<VersionId, &IndexedDocument>,
    edge_projection: &BTreeMap<LineageEdgeKey, BTreeSet<(VersionId, VersionId)>>,
    output: &mut BTreeMap<VersionId, BTreeSet<MatchEvidence>>,
    context: &RetrievalContext,
    work: &mut RetrievalWork,
) -> Result<(), RetrievalError> {
    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();
    for root in &request.graph_roots {
        if authorized.contains_key(root) {
            queue.push_back((root.clone(), 0_u16));
        }
    }
    while let Some((version, depth)) = queue.pop_front() {
        context.check()?;
        if !visited.insert(version.clone()) {
            continue;
        }
        output
            .entry(version.clone())
            .or_default()
            .insert(MatchEvidence::Graph { depth });
        if depth == request.graph_depth {
            continue;
        }
        let source = authorized
            .get(&version)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        for (neighbor, target) in authorized {
            work.graph_lineage_pair_lookups = work.graph_lineage_pair_lookups.saturating_add(1);
            let (first_lineage, second_lineage) =
                if source.atom.lineage_id <= target.atom.lineage_id {
                    (
                        source.atom.lineage_id.clone(),
                        target.atom.lineage_id.clone(),
                    )
                } else {
                    (
                        target.atom.lineage_id.clone(),
                        source.atom.lineage_id.clone(),
                    )
                };
            let (first_version, second_version) = if version <= *neighbor {
                (version.clone(), neighbor.clone())
            } else {
                (neighbor.clone(), version.clone())
            };
            let connected = edge_projection
                .get(&LineageEdgeKey {
                    tenant_id: request.partition.tenant_id().clone(),
                    first_lineage,
                    second_lineage,
                })
                .is_some_and(|edges| edges.contains(&(first_version, second_version)));
            if connected && !visited.contains(neighbor) {
                work.authorized_graph_edges = work.authorized_graph_edges.saturating_add(1);
                queue.push_back((neighbor.clone(), depth + 1));
            }
        }
        if visited.len() > crate::MAX_CANDIDATES {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
    }
    Ok(())
}

fn candidate_features(
    document: &IndexedDocument,
    evidence: &BTreeSet<MatchEvidence>,
    semantic_score: u16,
    lag: u64,
) -> CandidateFeatures {
    let minimum_depth = evidence
        .iter()
        .filter_map(|evidence| {
            if let MatchEvidence::Graph { depth } = evidence {
                Some(*depth)
            } else {
                None
            }
        })
        .min();
    CandidateFeatures {
        requirement_match: u16::from(!evidence.is_empty()) * 10_000,
        exact_match: u16::from(evidence.contains(&MatchEvidence::ExactIdentity)) * 10_000,
        lexical_match: u16::from(evidence.contains(&MatchEvidence::Lexical)) * 10_000,
        semantic_match: semantic_score,
        graph_proximity: minimum_depth.map_or(0, |depth| {
            10_000_u16.saturating_sub(depth.saturating_mul(250))
        }),
        project_proximity: 10_000,
        task_proximity: 0,
        authority: authority_feature(document.atom.governance.instruction_authority),
        verification: 0,
        freshness: if lag == 0 { 10_000 } else { 5_000 },
        novelty: 0,
        conflict_risk: 0,
        staleness: u16::try_from(lag.min(10_000)).unwrap_or(10_000),
        estimated_tokens: document.estimated_tokens,
        requirement_coverage_bits: 0,
        entity_coverage_bits: 0,
    }
}

const fn authority_feature(authority: InstructionAuthority) -> u16 {
    match authority {
        InstructionAuthority::Data => 2_500,
        InstructionAuthority::Advisory => 5_000,
        InstructionAuthority::Project => 7_500,
        InstructionAuthority::System => 10_000,
    }
}

fn candidate_order(left: &CandidateRef, right: &CandidateRef) -> std::cmp::Ordering {
    right
        .total_score
        .cmp(&left.total_score)
        .then_with(|| {
            left.features
                .estimated_tokens
                .cmp(&right.features.estimated_tokens)
        })
        .then_with(|| {
            left.canonical_uri
                .as_str()
                .cmp(right.canonical_uri.as_str())
        })
        .then_with(|| {
            left.relative_path
                .as_ref()
                .map(RelativePath::as_bytes)
                .cmp(&right.relative_path.as_ref().map(RelativePath::as_bytes))
        })
        .then_with(|| left.version_id.cmp(&right.version_id))
}

fn revision_lag(
    built: StoreRevision,
    required: StoreRevision,
    consistency: RetrievalConsistency,
) -> Result<u64, RetrievalError> {
    let lag = required.0.saturating_sub(built.0);
    match consistency {
        RetrievalConsistency::Strong if lag != 0 => {
            Err(RetrievalError::new(RetrievalErrorCode::IndexStale))
        }
        RetrievalConsistency::BoundedStale { max_revision_lag } if lag > max_revision_lag => {
            Err(RetrievalError::new(RetrievalErrorCode::IndexStale))
        }
        RetrievalConsistency::Strong | RetrievalConsistency::BoundedStale { .. } => Ok(lag),
    }
}

fn semantic_root(
    documents: &BTreeMap<VersionId, IndexedDocument>,
    adjacency: &BTreeMap<VersionId, BTreeSet<VersionId>>,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-INDEX-SEMANTIC-ROOT\0v1\0");
    for (version, document) in documents {
        hasher.update(version.as_str().as_bytes());
        hasher.update(document.atom.content_digest.as_str().as_bytes());
        hasher.update([document.atom.lifecycle as u8]);
    }
    for (version, neighbors) in adjacency {
        hasher.update(version.as_str().as_bytes());
        for neighbor in neighbors {
            hasher.update(neighbor.as_str().as_bytes());
        }
    }
    finish_digest(hasher)
}

fn partition_semantic_root(
    documents: &BTreeMap<VersionId, &IndexedDocument>,
    edge_projection: &BTreeMap<LineageEdgeKey, BTreeSet<(VersionId, VersionId)>>,
    tenant_id: &RecordId,
    work: &mut RetrievalWork,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-AUTHORIZED-INDEX-SEMANTIC-ROOT\0v1\0");
    for (version, document) in documents {
        hasher.update(version.as_str().as_bytes());
        hasher.update(document.atom.content_digest.as_str().as_bytes());
        hasher.update([document.atom.lifecycle as u8]);
    }
    let documents: Vec<_> = documents.iter().collect();
    for (left_index, (left_version, left_document)) in documents.iter().enumerate() {
        for (right_version, right_document) in documents.iter().skip(left_index) {
            work.graph_lineage_pair_lookups = work.graph_lineage_pair_lookups.saturating_add(1);
            let (first_lineage, second_lineage) =
                if left_document.atom.lineage_id <= right_document.atom.lineage_id {
                    (
                        left_document.atom.lineage_id.clone(),
                        right_document.atom.lineage_id.clone(),
                    )
                } else {
                    (
                        right_document.atom.lineage_id.clone(),
                        left_document.atom.lineage_id.clone(),
                    )
                };
            let (first_version, second_version) = if left_version <= right_version {
                ((*left_version).clone(), (*right_version).clone())
            } else {
                ((*right_version).clone(), (*left_version).clone())
            };
            if edge_projection
                .get(&LineageEdgeKey {
                    tenant_id: tenant_id.clone(),
                    first_lineage,
                    second_lineage,
                })
                .is_some_and(|edges| {
                    edges.contains(&(first_version.clone(), second_version.clone()))
                })
            {
                work.authorized_graph_edges = work.authorized_graph_edges.saturating_add(1);
                hasher.update(first_version.as_str().as_bytes());
                hasher.update(second_version.as_str().as_bytes());
            }
        }
    }
    finish_digest(hasher)
}

fn partition_fingerprint(
    configuration: &ContentDigest,
    semantic_root: &ContentDigest,
    partition_digest: &ContentDigest,
    stage: RetrievalStage,
    vector: Option<&VectorIndexBinding>,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-AUTHORIZED-INDEX-FINGERPRINT\0v1\0");
    hasher.update(configuration.as_str().as_bytes());
    hasher.update(semantic_root.as_str().as_bytes());
    hasher.update(partition_digest.as_str().as_bytes());
    if stage == RetrievalStage::Vector {
        hasher.update(b"VECTOR-STAGE\0");
        if let Some(vector) = vector {
            hasher.update(b"BOUND\0");
            hasher.update(vector.generation_id().as_str().as_bytes());
            hasher.update(vector.fingerprint().as_str().as_bytes());
        } else {
            hasher.update(b"UNBOUND\0");
        }
    } else {
        hasher.update(b"NON-VECTOR-STAGE\0");
    }
    finish_digest(hasher)
}

fn fingerprint(
    configuration: &ContentDigest,
    semantic_root: &ContentDigest,
    revision: StoreRevision,
    tenant_watermarks: &BTreeMap<RecordId, StoreRevision>,
    vector: Option<&VectorIndexBinding>,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-INDEX-FINGERPRINT\0v1\0");
    hasher.update(configuration.as_str().as_bytes());
    hasher.update(semantic_root.as_str().as_bytes());
    hasher.update(revision.0.to_be_bytes());
    for (tenant_id, watermark) in tenant_watermarks {
        hasher.update(tenant_id.as_str().as_bytes());
        hasher.update(watermark.0.to_be_bytes());
    }
    if let Some(vector) = vector {
        hasher.update(vector.generation_id().as_str().as_bytes());
        hasher.update(vector.fingerprint().as_str().as_bytes());
    }
    finish_digest(hasher)
}

fn finish_digest(hasher: Sha256) -> Result<ContentDigest, RetrievalError> {
    let digest = hasher.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
    }
    ContentDigest::new(value)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
}

fn deterministic_uuid(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    )
}

#[cfg(test)]
mod tests {
    use super::{InMemoryIndexManager, IndexBuild, finish_digest};
    use crate::{
        AuthorizedPartition, IndexGenerationState, ProcessorApprovedVector, RetrievalConsistency,
        RetrievalContext, RetrievalError, RetrievalErrorCode, RetrievalRequest, RetrievalStage,
        Retriever, VectorAdapter, VectorIndexBinding, VectorNeighbor, VectorQuery,
    };
    use cigar_protocol::{
        Classification, ContentDigest, ContextAtomV1, ContextEdge, InstructionAuthority, Lifecycle,
        RecordId, RelativePath, SourceUri, UtcTimestamp, VersionId,
    };
    use cigar_store::{CancellationToken, StoreRevision};
    use cigar_testkit::deterministic_protocol_fixture;
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{Duration, Instant};

    fn timestamp(value: &str) -> Result<UtcTimestamp, Box<dyn Error>> {
        Ok(UtcTimestamp::parse_rfc3339(value)?)
    }

    fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            format!("{value:02x}").repeat(32)
        ))?)
    }

    fn version(value: u8) -> Result<VersionId, Box<dyn Error>> {
        Ok(VersionId::new(digest(value)?.as_str())?)
    }

    fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
        ))?)
    }

    fn atom(
        value: u8,
        tenant: &RecordId,
        project: &RecordId,
        text: &str,
    ) -> Result<ContextAtomV1, Box<dyn Error>> {
        let fixture = deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing deterministic ContextAtomV1 fixture")?;
        let mut atom: ContextAtomV1 = serde_json::from_value(fixture.input)?;
        atom.atom_id = record(u16::from(value) + 100)?;
        atom.lineage_id =
            cigar_protocol::LineageId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"))?;
        atom.version_id = version(value)?;
        atom.content_digest = digest(value.saturating_add(64))?;
        atom.payload = cigar_protocol::AtomPayload::InlineText(text.to_owned());
        atom.source.uri = SourceUri::new(format!("file:///project/{value:02x}.md"))?;
        atom.source.relative_path = Some(RelativePath::new(
            format!("docs/{value:02x}.md").into_bytes(),
        )?);
        atom.scope.tenant_id = tenant.clone();
        atom.scope.project_ids = vec![project.clone()];
        atom.retrieval.exact_terms = vec!["cigar".to_owned(), format!("term-{value:02x}")];
        Ok(atom)
    }

    fn successor(
        base: &ContextAtomV1,
        value: u8,
        observed_at: UtcTimestamp,
    ) -> Result<ContextAtomV1, Box<dyn Error>> {
        let mut atom = base.clone();
        atom.version_id = version(value)?;
        atom.content_digest = digest(value.saturating_add(64))?;
        atom.temporal.observed_at = observed_at;
        Ok(atom)
    }

    fn edge(value: u16, from: &VersionId, to: &VersionId) -> Result<ContextEdge, Box<dyn Error>> {
        let fixture = deterministic_protocol_fixture("ContextEdge")
            .ok_or("missing deterministic ContextEdge fixture")?;
        let mut edge: ContextEdge = serde_json::from_value(fixture.input)?;
        edge.edge_id = record(value + 500)?;
        edge.from_version = from.clone();
        edge.to_version = to.clone();
        Ok(edge)
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    fn partition(
        tenant: &RecordId,
        projects: impl IntoIterator<Item = RecordId>,
    ) -> Result<AuthorizedPartition, Box<dyn Error>> {
        partition_with_vector(tenant, projects, false)
    }

    fn partition_with_vector(
        tenant: &RecordId,
        projects: impl IntoIterator<Item = RecordId>,
        vector_capability: bool,
    ) -> Result<AuthorizedPartition, Box<dyn Error>> {
        partition_at(
            tenant,
            projects,
            "coding",
            "local",
            Classification::Internal,
            vector_capability,
            timestamp("2026-07-10T00:00:02Z")?,
        )
    }

    fn partition_at(
        tenant: &RecordId,
        projects: impl IntoIterator<Item = RecordId>,
        purpose: &str,
        processor: &str,
        maximum_classification: Classification,
        vector_capability: bool,
        observed_as_of: UtcTimestamp,
    ) -> Result<AuthorizedPartition, Box<dyn Error>> {
        crate::test_support::authorized_partition(
            tenant.clone(),
            record(998)?,
            projects.into_iter().collect(),
            purpose,
            processor,
            maximum_classification,
            InstructionAuthority::Data,
            vector_capability,
            observed_as_of,
            observed_as_of,
        )
    }

    fn request(
        stage: RetrievalStage,
        partition: AuthorizedPartition,
        revision: u64,
    ) -> RetrievalRequest {
        RetrievalRequest {
            stage,
            partition,
            required_revision: StoreRevision(revision),
            consistency: RetrievalConsistency::Strong,
            exact_versions: BTreeSet::new(),
            atom_ids: BTreeSet::new(),
            lineage_ids: BTreeSet::new(),
            content_digests: BTreeSet::new(),
            canonical_uris: BTreeSet::new(),
            source_revisions: BTreeSet::new(),
            paths: BTreeSet::new(),
            terms: BTreeSet::new(),
            approved_vector: None,
            graph_roots: BTreeSet::new(),
            graph_depth: 0,
            limit: 100,
            allow_fallback: false,
        }
    }

    fn build(
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
        revision: u64,
        vector: bool,
    ) -> Result<IndexBuild, Box<dyn Error>> {
        let tenant_watermarks = atoms
            .iter()
            .map(|atom| (atom.scope.tenant_id.clone(), StoreRevision(revision)))
            .collect();
        Ok(IndexBuild {
            atoms,
            edges,
            built_through_revision: StoreRevision(revision),
            tenant_watermarks,
            configuration_digest: digest(241)?,
            verified_at: timestamp("2026-07-10T00:00:03Z")?,
            vector_binding: vector
                .then(|| {
                    Ok::<_, Box<dyn Error>>(VectorIndexBinding::new(record(999)?, digest(242)?))
                })
                .transpose()?,
        })
    }

    struct RecordingVectorAdapter {
        index_binding: VectorIndexBinding,
        seen: Arc<Mutex<Option<VectorQuery>>>,
    }

    impl VectorAdapter for RecordingVectorAdapter {
        fn index_binding(&self) -> &VectorIndexBinding {
            &self.index_binding
        }

        fn authorized_partition_binding(
            &self,
            query: &VectorQuery,
            context: &RetrievalContext,
        ) -> Result<VectorIndexBinding, RetrievalError> {
            context.check()?;
            let mut hasher = Sha256::new();
            hasher.update(b"CIGAR-TEST-AUTHORIZED-VECTOR-PARTITION\0v1\0");
            hasher.update(query.partition_digest.as_str().as_bytes());
            for version in &query.allowed_versions {
                hasher.update(version.as_str().as_bytes());
            }
            Ok(VectorIndexBinding::new(
                record(995)
                    .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
                finish_digest(hasher)?,
            ))
        }

        fn neighbors(
            &self,
            query: &VectorQuery,
            context: &RetrievalContext,
        ) -> Result<Vec<VectorNeighbor>, RetrievalError> {
            context.check()?;
            *self
                .seen
                .lock()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))? =
                Some(query.clone());
            Ok(query
                .allowed_versions
                .iter()
                .next()
                .cloned()
                .map(|version_id| {
                    vec![VectorNeighbor {
                        version_id,
                        similarity: 7_777,
                    }]
                })
                .unwrap_or_default())
        }
    }

    #[test]
    fn generation_rebuild_is_semantically_stable_and_activation_is_atomic()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(1)?;
        let project = record(2)?;
        let indexed = atom(1, &tenant, &project, "cigar generation stable")?;
        let manager = InMemoryIndexManager::default();
        let first = manager.build_generation(
            build(vec![indexed.clone()], Vec::new(), 7, false)?,
            &context(),
        )?;
        assert_eq!(first.state, IndexGenerationState::Verified);
        let active = manager.activate(&first.generation_id, None)?;
        assert_eq!(active.state, IndexGenerationState::Active);

        let mut exact = request(
            RetrievalStage::Exact,
            partition(&tenant, [project.clone()])?,
            7,
        );
        exact.exact_versions.insert(indexed.version_id.clone());
        let before = manager.retrieve(&exact, &context())?;
        assert_eq!(before.candidates.len(), 1);

        let second =
            manager.build_generation(build(vec![indexed], Vec::new(), 8, false)?, &context())?;
        assert_eq!(first.semantic_root, second.semantic_root);
        assert_ne!(first.index_fingerprint, second.index_fingerprint);
        let rebuilt = manager.activate(&second.generation_id, Some(&first.generation_id))?;
        let after = manager.retrieve(&exact, &context())?;
        assert_eq!(after.candidates, before.candidates);
        assert_eq!(after.disclosure, before.disclosure);
        assert!(manager.delete_generation(&first.generation_id)?);
        assert_eq!(manager.active_generation()?, Some(rebuilt));
        assert_eq!(
            manager
                .delete_generation(&second.generation_id)
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );
        Ok(())
    }

    #[test]
    fn concurrent_readers_never_observe_a_mixed_activation_generation() -> Result<(), Box<dyn Error>>
    {
        const READER_COUNT: usize = 4;
        const READS_PER_READER: usize = 1_000;

        let tenant = record(70)?;
        let project = record(71)?;
        let old_atom = atom(70, &tenant, &project, "old complete generation")?;
        let new_atom = atom(71, &tenant, &project, "new complete generation")?;
        let manager = Arc::new(InMemoryIndexManager::default());
        let old_generation = manager.build_generation(
            build(vec![old_atom.clone()], Vec::new(), 7, false)?,
            &context(),
        )?;
        manager.activate(&old_generation.generation_id, None)?;
        let new_generation = manager.build_generation(
            build(vec![new_atom.clone()], Vec::new(), 8, false)?,
            &context(),
        )?;

        let mut exact = request(RetrievalStage::Exact, partition(&tenant, [project])?, 7);
        exact.exact_versions.insert(old_atom.version_id.clone());
        exact.exact_versions.insert(new_atom.version_id.clone());
        let complete_old = manager.retrieve(&exact, &context())?;
        let reference_new = InMemoryIndexManager::default();
        let reference_new_generation = reference_new
            .build_generation(build(vec![new_atom], Vec::new(), 8, false)?, &context())?;
        reference_new.activate(&reference_new_generation.generation_id, None)?;
        let complete_new = reference_new.retrieve(&exact, &context())?;
        assert_ne!(complete_old, complete_new);

        let barrier = Arc::new(Barrier::new(READER_COUNT + 1));
        let mut readers = Vec::with_capacity(READER_COUNT);
        for _reader in 0..READER_COUNT {
            let manager = Arc::clone(&manager);
            let request = exact.clone();
            let barrier = Arc::clone(&barrier);
            let complete_old = complete_old.clone();
            let complete_new = complete_new.clone();
            readers.push(std::thread::spawn(move || -> Result<(), RetrievalError> {
                barrier.wait();
                for _read in 0..READS_PER_READER {
                    let batch = manager.retrieve(&request, &context())?;
                    if batch != complete_old && batch != complete_new {
                        return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
                    }
                }
                Ok(())
            }));
        }

        barrier.wait();
        manager.activate(
            &new_generation.generation_id,
            Some(&old_generation.generation_id),
        )?;
        for reader in readers {
            reader.join().map_err(|_panic| "reader thread panicked")??;
        }
        let active = manager
            .active_generation()?
            .ok_or("missing active generation")?;
        assert_eq!(active.generation_id, new_generation.generation_id);
        assert_eq!(active.built_through_revision, StoreRevision(8));
        Ok(())
    }

    #[test]
    fn quarantine_and_consistency_fail_closed() -> Result<(), Box<dyn Error>> {
        let tenant = record(3)?;
        let project = record(4)?;
        let manager = InMemoryIndexManager::default();
        let staged = manager.build_generation(
            build(
                vec![atom(2, &tenant, &project, "bounded lag")?],
                Vec::new(),
                10,
                false,
            )?,
            &context(),
        )?;
        assert_eq!(
            manager.quarantine_generation(&staged.generation_id)?.state,
            IndexGenerationState::Corrupt
        );
        assert_eq!(
            manager
                .activate(&staged.generation_id, None)
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::CorruptGeneration)
        );

        let manager = InMemoryIndexManager::default();
        let verified = manager.build_generation(
            build(
                vec![atom(3, &tenant, &project, "bounded lag")?],
                Vec::new(),
                10,
                false,
            )?,
            &context(),
        )?;
        manager.activate(&verified.generation_id, None)?;
        let mut stale = request(RetrievalStage::Augment, partition(&tenant, [project])?, 12);
        assert_eq!(
            manager
                .retrieve(&stale, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::IndexStale)
        );
        stale.consistency = RetrievalConsistency::BoundedStale {
            max_revision_lag: 2,
        };
        let bounded = manager.retrieve(&stale, &context())?;
        assert_eq!(bounded.disclosure.actual_revision_lag, 2);
        assert_eq!(bounded.disclosure.built_through_revision, StoreRevision(10));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert_eq!(
            manager
                .retrieve(
                    &stale,
                    &RetrievalContext {
                        cancellation: cancelled,
                        deadline: Instant::now() + Duration::from_secs(1),
                    },
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::Cancelled)
        );
        assert_eq!(
            manager
                .retrieve(
                    &stale,
                    &RetrievalContext {
                        cancellation: CancellationToken::default(),
                        deadline: Instant::now(),
                    },
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::DeadlineExceeded)
        );
        Ok(())
    }

    #[test]
    fn unauthorized_projects_classification_authority_and_time_never_become_candidates()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(5)?;
        let project_a = record(6)?;
        let project_b = record(7)?;
        let allowed = atom(4, &tenant, &project_a, "shared secret_term")?;
        let mut denied_project = atom(5, &tenant, &project_b, "secret_term project-b-path")?;
        denied_project.source.uri = SourceUri::new("file:///private/project-b-secret.md")?;
        let mut denied_class = atom(6, &tenant, &project_a, "secret_term restricted")?;
        denied_class.governance.classification = Classification::Restricted;
        let mut denied_authority = atom(7, &tenant, &project_a, "secret_term system")?;
        denied_authority.governance.instruction_authority = InstructionAuthority::System;
        let mut denied_time = atom(8, &tenant, &project_a, "secret_term future")?;
        denied_time.temporal.valid_from = timestamp("2026-07-11T00:00:00Z")?;
        denied_time.temporal.observed_at = timestamp("2026-07-11T00:00:01Z")?;

        let manager = InMemoryIndexManager::default();
        let generation = manager.build_generation(
            build(
                vec![
                    allowed.clone(),
                    denied_project,
                    denied_class,
                    denied_authority,
                    denied_time,
                ],
                Vec::new(),
                20,
                false,
            )?,
            &context(),
        )?;
        manager.activate(&generation.generation_id, None)?;
        let mut lexical = request(
            RetrievalStage::Lexical,
            partition(&tenant, [project_a])?,
            20,
        );
        lexical.terms.insert("secret_term".to_owned());
        let batch = manager.retrieve(&lexical, &context())?;
        assert_eq!(
            batch
                .candidates
                .iter()
                .map(|candidate| &candidate.version_id)
                .collect::<Vec<_>>(),
            vec![&allowed.version_id]
        );
        let diagnostic = format!("{lexical:?} {batch:?} {manager:?}");
        assert!(!diagnostic.contains("secret_term"));
        assert!(!diagnostic.contains("project-b-secret"));
        Ok(())
    }

    #[test]
    fn graph_cycles_are_bounded_and_vector_denial_or_fallback_is_explicit()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(8)?;
        let project = record(9)?;
        let first = atom(9, &tenant, &project, "cigar graph first")?;
        let second = atom(10, &tenant, &project, "cigar graph second")?;
        let third = atom(11, &tenant, &project, "cigar graph third")?;
        let edges = vec![
            edge(1, &first.version_id, &second.version_id)?,
            edge(2, &second.version_id, &third.version_id)?,
            edge(3, &third.version_id, &first.version_id)?,
        ];
        let manager = InMemoryIndexManager::default();
        let generation = manager.build_generation(
            build(vec![first.clone(), second, third], edges, 30, true)?,
            &context(),
        )?;
        manager.activate(&generation.generation_id, None)?;

        let mut graph = request(
            RetrievalStage::Graph,
            partition(&tenant, [project.clone()])?,
            30,
        );
        graph.graph_roots.insert(first.version_id);
        graph.graph_depth = 1;
        let graph_batch = manager.retrieve(&graph, &context())?;
        assert_eq!(graph_batch.candidates.len(), 3);

        let denied_vector = request(
            RetrievalStage::Vector,
            partition(&tenant, [project.clone()])?,
            30,
        );
        assert_eq!(
            manager
                .retrieve(&denied_vector, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::Denied)
        );
        let fallback_partition = partition_with_vector(&tenant, [project], true)?;
        let mut fallback = request(RetrievalStage::Vector, fallback_partition, 30);
        // `graph` occurs only in authorized payload-derived lexical terms, not declared metadata;
        // this proves vector outage uses the deterministic lexical path.
        fallback.terms.insert("graph".to_owned());
        assert_eq!(
            manager
                .retrieve(&fallback, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );
        fallback.allow_fallback = true;
        let fallback_batch = manager.retrieve(&fallback, &context())?;
        assert!(fallback_batch.disclosure.fallback_used);
        assert_eq!(fallback_batch.candidates.len(), 3);
        Ok(())
    }

    #[test]
    fn vector_request_shape_rejects_cross_channel_selectors_and_unapproved_scoring()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(58)?;
        let project = record(59)?;
        let partition = partition_with_vector(&tenant, [project], true)?;
        let mut request = request(RetrievalStage::Vector, partition, 1);
        request.terms.insert("authorized".to_owned());
        assert_eq!(
            request.validate().map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );

        request.allow_fallback = true;
        request.exact_versions.insert(version(1)?);
        assert_eq!(
            request.validate().map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );
        request.exact_versions.clear();
        request.graph_roots.insert(version(2)?);
        assert_eq!(
            request.validate().map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );
        request.graph_roots.clear();
        assert!(request.validate().is_ok());
        Ok(())
    }

    #[test]
    fn vector_adapter_receives_only_authorized_versions_and_quantized_scores()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(10)?;
        let project_a = record(11)?;
        let project_b = record(12)?;
        let allowed = atom(12, &tenant, &project_a, "private_vector_query allowed")?;
        let denied = atom(13, &tenant, &project_b, "private_vector_query denied")?;
        let index_binding = VectorIndexBinding::new(record(999)?, digest(242)?);
        let seen = Arc::new(Mutex::new(None));
        let manager = InMemoryIndexManager::with_vector_adapter(Arc::new(RecordingVectorAdapter {
            index_binding: index_binding.clone(),
            seen: Arc::clone(&seen),
        }));
        let generation = manager.build_generation(
            IndexBuild {
                vector_binding: Some(index_binding),
                ..build(vec![allowed.clone(), denied], Vec::new(), 31, false)?
            },
            &context(),
        )?;
        manager.activate(&generation.generation_id, None)?;
        let authorized_partition = partition_with_vector(&tenant, [project_a], true)?;
        let mut vector = request(RetrievalStage::Vector, authorized_partition, 31);
        vector.terms.insert("private_vector_query".to_owned());
        vector.approved_vector = Some(ProcessorApprovedVector::try_from_processor_output(
            digest(243)?,
            &[1, 2, 3, 4],
        )?);
        let batch = manager.retrieve(&vector, &context())?;
        assert!(!batch.disclosure.fallback_used);
        assert_eq!(batch.candidates.len(), 1);
        let candidate = batch.candidates.first().ok_or("missing vector candidate")?;
        assert_eq!(candidate.version_id, allowed.version_id);
        assert_eq!(candidate.features.semantic_match, 7_777);
        let captured = seen
            .lock()
            .map_err(|_error| "vector capture lock poisoned")?
            .clone()
            .ok_or("vector adapter was not called")?;
        assert_eq!(
            captured.allowed_versions,
            [allowed.version_id].into_iter().collect()
        );
        assert!(!format!("{captured:?}").contains("private_vector_query"));
        Ok(())
    }

    #[test]
    fn exact_features_and_ties_follow_the_published_order() -> Result<(), Box<dyn Error>> {
        let tenant = record(13)?;
        let project = record(14)?;
        let mut later_uri = atom(14, &tenant, &project, "same size")?;
        later_uri.source.uri = SourceUri::new("file:///z-later.md")?;
        let mut earlier_uri = atom(15, &tenant, &project, "same size")?;
        earlier_uri.source.uri = SourceUri::new("file:///a-earlier.md")?;
        earlier_uri.content_digest = later_uri.content_digest.clone();
        let manager = InMemoryIndexManager::default();
        let generation = manager.build_generation(
            build(
                vec![later_uri.clone(), earlier_uri.clone()],
                Vec::new(),
                32,
                false,
            )?,
            &context(),
        )?;
        manager.activate(&generation.generation_id, None)?;
        let mut exact = request(RetrievalStage::Exact, partition(&tenant, [project])?, 32);
        exact.content_digests.insert(later_uri.content_digest);
        let batch = manager.retrieve(&exact, &context())?;
        assert_eq!(
            batch
                .candidates
                .iter()
                .map(|candidate| &candidate.version_id)
                .collect::<Vec<_>>(),
            vec![&earlier_uri.version_id, &later_uri.version_id]
        );
        for candidate in batch.candidates {
            assert_eq!(candidate.features.requirement_match, 10_000);
            assert_eq!(candidate.features.exact_match, 10_000);
            assert_eq!(candidate.features.lexical_match, 0);
            assert_eq!(candidate.features.semantic_match, 0);
            assert_eq!(candidate.features.project_proximity, 10_000);
            assert_eq!(candidate.features.freshness, 10_000);
            assert_eq!(candidate.total_score, 5_575_000);
        }
        Ok(())
    }

    #[test]
    fn latest_lineage_version_is_resolved_before_governance_and_lifecycle_filters()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(30)?;
        let project = record(31)?;
        let other_project = record(32)?;
        let successor_time = timestamp("2026-07-10T00:00:02Z")?;
        let mut atoms = Vec::new();

        let purpose_base = atom(30, &tenant, &project, "purpose base")?;
        let mut purpose_later = successor(&purpose_base, 31, successor_time)?;
        purpose_later.governance.allowed_purposes = vec!["review".to_owned()];
        atoms.extend([purpose_base.clone(), purpose_later]);

        let class_base = atom(32, &tenant, &project, "class base")?;
        let mut class_later = successor(&class_base, 33, successor_time)?;
        class_later.governance.classification = Classification::Restricted;
        atoms.extend([class_base.clone(), class_later]);

        let processor_base = atom(34, &tenant, &project, "processor base")?;
        let mut processor_later = successor(&processor_base, 35, successor_time)?;
        processor_later.governance.processor_constraints = vec!["remote".to_owned()];
        atoms.extend([processor_base.clone(), processor_later]);

        let project_base = atom(36, &tenant, &project, "project base")?;
        let mut project_later = successor(&project_base, 37, successor_time)?;
        project_later.scope.project_ids = vec![other_project];
        atoms.extend([project_base.clone(), project_later]);

        let lifecycle_base = atom(38, &tenant, &project, "lifecycle base")?;
        let mut lifecycle_later = successor(&lifecycle_base, 39, successor_time)?;
        lifecycle_later.lifecycle = Lifecycle::Tombstoned;
        atoms.extend([lifecycle_base.clone(), lifecycle_later]);

        let manager = InMemoryIndexManager::default();
        let descriptor =
            manager.build_generation(build(atoms, Vec::new(), 40, false)?, &context())?;
        manager.activate(&descriptor.generation_id, None)?;

        let current = request(
            RetrievalStage::Augment,
            partition_at(
                &tenant,
                [project.clone()],
                "coding",
                "local",
                Classification::Internal,
                false,
                timestamp("2026-07-10T00:00:03Z")?,
            )?,
            40,
        );
        assert!(
            manager
                .retrieve(&current, &context())?
                .candidates
                .is_empty()
        );

        let historical = request(
            RetrievalStage::Augment,
            partition_at(
                &tenant,
                [project],
                "coding",
                "local",
                Classification::Internal,
                false,
                timestamp("2026-07-10T00:00:01Z")?,
            )?,
            40,
        );
        let historical_versions: BTreeSet<_> = manager
            .retrieve(&historical, &context())?
            .candidates
            .into_iter()
            .map(|candidate| candidate.version_id)
            .collect();
        assert_eq!(
            historical_versions,
            [
                purpose_base.version_id,
                class_base.version_id,
                processor_base.version_id,
                project_base.version_id,
                lifecycle_base.version_id,
            ]
            .into_iter()
            .collect()
        );
        Ok(())
    }

    #[test]
    fn governance_dimensions_cannot_be_composed_across_versions() -> Result<(), Box<dyn Error>> {
        let tenant = record(40)?;
        let project = record(41)?;
        let mut earlier = atom(40, &tenant, &project, "earlier remote")?;
        earlier.governance.processor_constraints = vec!["remote".to_owned()];
        let mut later = successor(&earlier, 41, timestamp("2026-07-10T00:00:02Z")?)?;
        later.governance.allowed_purposes = vec!["review".to_owned()];
        later.governance.processor_constraints = vec!["local".to_owned()];
        let manager = InMemoryIndexManager::default();
        let descriptor = manager.build_generation(
            build(vec![earlier, later], Vec::new(), 41, false)?,
            &context(),
        )?;
        manager.activate(&descriptor.generation_id, None)?;
        let query = request(
            RetrievalStage::Augment,
            partition_at(
                &tenant,
                [project],
                "coding",
                "local",
                Classification::Internal,
                false,
                timestamp("2026-07-10T00:00:03Z")?,
            )?,
            41,
        );
        let (batch, work) = manager.retrieve_with_work(&query, &context())?;
        assert!(batch.candidates.is_empty());
        assert_eq!(work.lineage_timelines, 0);
        assert_eq!(work.timeline_versions, 0);
        assert_eq!(work.policy_checks, 0);
        Ok(())
    }

    #[test]
    fn tenant_lineages_watermarks_and_denied_topology_are_partition_local()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(50)?;
        let other_tenant = record(51)?;
        let project = record(52)?;
        let other_project = record(53)?;
        let first = atom(50, &tenant, &project, "cigar allowed first")?;
        let second = atom(51, &tenant, &project, "cigar allowed second")?;
        let allowed_edge = edge(50, &first.version_id, &second.version_id)?;

        let baseline = InMemoryIndexManager::default();
        let mut baseline_build = build(
            vec![first.clone(), second.clone()],
            vec![allowed_edge.clone()],
            60,
            false,
        )?;
        baseline_build
            .tenant_watermarks
            .insert(tenant.clone(), StoreRevision(55));
        let baseline_descriptor = baseline.build_generation(baseline_build, &context())?;
        baseline.activate(&baseline_descriptor.generation_id, None)?;

        let mut denied_project = atom(52, &tenant, &other_project, "denied project")?;
        let mut denied_purpose = atom(53, &tenant, &project, "denied purpose")?;
        denied_purpose.governance.allowed_purposes = vec!["review".to_owned()];
        let mut denied_class = atom(54, &tenant, &project, "denied class")?;
        denied_class.governance.classification = Classification::Restricted;
        let mut denied_processor = atom(55, &tenant, &project, "denied processor")?;
        denied_processor.governance.processor_constraints = vec!["remote".to_owned()];
        let mut same_lineage_other_tenant = atom(56, &other_tenant, &project, "other tenant")?;
        same_lineage_other_tenant.lineage_id = first.lineage_id.clone();
        denied_project.source.uri = SourceUri::new("file:///denied/project.md")?;
        let denied_edge = edge(51, &first.version_id, &denied_purpose.version_id)?;

        let noisy = InMemoryIndexManager::default();
        let mut noisy_build = build(
            vec![
                first.clone(),
                second.clone(),
                denied_project,
                denied_purpose,
                denied_class,
                denied_processor,
                same_lineage_other_tenant,
            ],
            vec![allowed_edge, denied_edge],
            80,
            false,
        )?;
        noisy_build
            .tenant_watermarks
            .insert(tenant.clone(), StoreRevision(55));
        noisy_build
            .tenant_watermarks
            .insert(other_tenant, StoreRevision(80));
        let noisy_descriptor = noisy.build_generation(noisy_build, &context())?;
        noisy.activate(&noisy_descriptor.generation_id, None)?;

        let mut graph = request(RetrievalStage::Graph, partition(&tenant, [project])?, 55);
        graph.graph_roots.insert(first.version_id.clone());
        graph.graph_depth = 2;
        let (baseline_batch, baseline_work) = baseline.retrieve_with_work(&graph, &context())?;
        let (noisy_batch, noisy_work) = noisy.retrieve_with_work(&graph, &context())?;
        assert_eq!(noisy_batch, baseline_batch);
        assert_eq!(noisy_work, baseline_work);
        assert!(!format!("{noisy_batch:?} {noisy_work:?}").contains("denied"));

        let mut stale = graph;
        stale.required_revision = StoreRevision(56);
        assert_eq!(
            noisy
                .retrieve(&stale, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::IndexStale)
        );
        stale.consistency = RetrievalConsistency::BoundedStale {
            max_revision_lag: 1,
        };
        let bounded = noisy.retrieve(&stale, &context())?;
        assert_eq!(bounded.disclosure.actual_revision_lag, 1);
        assert_eq!(bounded.disclosure.built_through_revision, StoreRevision(55));
        Ok(())
    }

    #[test]
    fn authorized_edges_and_vector_bindings_are_bound_into_partition_disclosure()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(60)?;
        let project = record(61)?;
        let first = atom(60, &tenant, &project, "cigar graph first")?;
        let second = atom(61, &tenant, &project, "cigar graph second")?;

        let without_edge = InMemoryIndexManager::default();
        let descriptor = without_edge.build_generation(
            build(vec![first.clone(), second.clone()], Vec::new(), 61, false)?,
            &context(),
        )?;
        without_edge.activate(&descriptor.generation_id, None)?;
        let with_edge = InMemoryIndexManager::default();
        let descriptor = with_edge.build_generation(
            build(
                vec![first.clone(), second.clone()],
                vec![edge(60, &first.version_id, &second.version_id)?],
                61,
                false,
            )?,
            &context(),
        )?;
        with_edge.activate(&descriptor.generation_id, None)?;
        let mut graph = request(
            RetrievalStage::Graph,
            partition(&tenant, [project.clone()])?,
            61,
        );
        graph.graph_roots.insert(first.version_id.clone());
        graph.graph_depth = 1;
        let disconnected = without_edge.retrieve(&graph, &context())?;
        let connected = with_edge.retrieve(&graph, &context())?;
        assert_ne!(connected.candidates, disconnected.candidates);
        assert_ne!(
            connected.disclosure.index_fingerprint,
            disconnected.disclosure.index_fingerprint
        );

        let first_vector = InMemoryIndexManager::default();
        let first_descriptor = first_vector.build_generation(
            build(vec![first.clone()], Vec::new(), 61, true)?,
            &context(),
        )?;
        first_vector.activate(&first_descriptor.generation_id, None)?;
        let second_vector = InMemoryIndexManager::default();
        let mut second_build = build(vec![first], Vec::new(), 61, false)?;
        second_build.vector_binding = Some(VectorIndexBinding::new(record(996)?, digest(246)?));
        let second_descriptor = second_vector.build_generation(second_build, &context())?;
        second_vector.activate(&second_descriptor.generation_id, None)?;
        let mut vector = request(
            RetrievalStage::Vector,
            partition_with_vector(&tenant, [project], true)?,
            61,
        );
        vector.terms.insert("cigar".to_owned());
        vector.approved_vector = Some(ProcessorApprovedVector::try_from_processor_output(
            digest(245)?,
            &[1, 2, 3],
        )?);
        vector.allow_fallback = true;
        let first_batch = first_vector.retrieve(&vector, &context())?;
        let second_batch = second_vector.retrieve(&vector, &context())?;
        assert_eq!(first_batch.candidates, second_batch.candidates);
        assert_eq!(
            first_batch.disclosure.index_fingerprint,
            second_batch.disclosure.index_fingerprint
        );
        Ok(())
    }

    #[test]
    fn resource_revocation_and_policy_outage_fail_before_index_disclosure()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(70)?;
        let project = record(71)?;
        let indexed = atom(70, &tenant, &project, "revocation protected body")?;
        let (partition, policy) = crate::test_support::authorized_partition_and_engine(
            tenant.clone(),
            record(998)?,
            [project].into_iter().collect(),
            "coding",
            "local",
            Classification::Internal,
            InstructionAuthority::Data,
            false,
            timestamp("2026-07-10T00:00:02Z")?,
            timestamp("2026-07-10T00:00:02Z")?,
        )?;
        let manager = InMemoryIndexManager::default();
        let descriptor = manager.build_generation(
            build(vec![indexed.clone()], Vec::new(), 70, false)?,
            &context(),
        )?;
        manager.activate(&descriptor.generation_id, None)?;
        let query = request(RetrievalStage::Augment, partition.clone(), 70);
        assert_eq!(manager.retrieve(&query, &context())?.candidates.len(), 1);

        policy.revoke_resource(
            indexed.content_digest.clone(),
            timestamp("2026-07-10T00:00:03Z")?,
        )?;
        let Err(revoked) = manager.retrieve(&query, &context()) else {
            return Err("revoked proof unexpectedly retrieved candidates".into());
        };
        assert_eq!(revoked.code(), RetrievalErrorCode::Denied);
        let diagnostic = format!("{revoked:?} {revoked} {partition:?}");
        assert!(!diagnostic.contains(indexed.version_id.as_str()));
        assert!(!diagnostic.contains(indexed.content_digest.as_str()));
        assert!(!diagnostic.contains(indexed.source.uri.as_str()));

        let (outage_partition, outage_policy) =
            crate::test_support::authorized_partition_and_engine(
                tenant,
                record(997)?,
                [record(71)?].into_iter().collect(),
                "coding",
                "local",
                Classification::Internal,
                InstructionAuthority::Data,
                false,
                timestamp("2026-07-10T00:00:02Z")?,
                timestamp("2026-07-10T00:00:02Z")?,
            )?;
        outage_policy.set_available(false)?;
        let Err(outage) = manager.retrieve(
            &request(RetrievalStage::Augment, outage_partition, 70),
            &context(),
        ) else {
            return Err("unavailable policy unexpectedly retrieved candidates".into());
        };
        assert_eq!(outage, revoked);
        Ok(())
    }

    #[test]
    fn tenant_watermark_map_is_mandatory_for_nonempty_generations() -> Result<(), Box<dyn Error>> {
        let tenant = record(80)?;
        let project = record(81)?;
        let indexed = atom(80, &tenant, &project, "tenant watermark")?;
        let manager = InMemoryIndexManager::default();
        let mut missing = build(vec![indexed], Vec::new(), 80, false)?;
        missing.tenant_watermarks = BTreeMap::new();
        assert_eq!(
            manager
                .build_generation(missing, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::CorruptGeneration)
        );

        let empty = manager.build_generation(
            IndexBuild {
                atoms: Vec::new(),
                edges: Vec::new(),
                built_through_revision: StoreRevision(0),
                tenant_watermarks: [(tenant.clone(), StoreRevision(0))].into_iter().collect(),
                configuration_digest: digest(241)?,
                verified_at: timestamp("2026-07-10T00:00:03Z")?,
                vector_binding: None,
            },
            &context(),
        )?;
        manager.activate(&empty.generation_id, None)?;
        let batch = manager.retrieve(
            &request(RetrievalStage::Augment, partition(&tenant, [project])?, 0),
            &context(),
        )?;
        assert!(batch.candidates.is_empty());
        Ok(())
    }
}
