//! Verified immutable in-memory index generations and authorization-first retrieval.

use crate::{
    CandidateBatch, CandidateFeatures, CandidateRef, IndexGenerationState, IndexKind,
    MatchEvidence, RetrievalConsistency, RetrievalContext, RetrievalDisclosure, RetrievalError,
    RetrievalErrorCode, RetrievalRequest, RetrievalStage, Retriever, VectorAdapter, VectorQuery,
};
use cigar_protocol::{
    AtomPayload, ContentDigest, ContextAtomV1, ContextEdge, InstructionAuthority, Lifecycle,
    RecordId, RelativePath, UtcTimestamp, Validate, VersionId,
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
    /// Analyzer, tokenizer, projection, and optional-vector configuration digest.
    pub configuration_digest: ContentDigest,
    /// Verification time supplied by the deterministic caller clock.
    pub verified_at: UtcTimestamp,
    /// Optional vector model/preprocessing fingerprint.
    pub vector_fingerprint: Option<ContentDigest>,
}

impl fmt::Debug for IndexBuild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexBuild")
            .field("atom_count", &self.atoms.len())
            .field("edge_count", &self.edges.len())
            .field("built_through_revision", &self.built_through_revision)
            .field("configuration_digest", &self.configuration_digest)
            .field("verified_at", &self.verified_at)
            .field("vector_enabled", &self.vector_fingerprint.is_some())
            .finish()
    }
}

/// Public immutable generation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexGenerationDescriptor {
    /// Deterministic generation identity.
    pub generation_id: RecordId,
    /// Build, verification, activation, or corruption state.
    pub state: IndexGenerationState,
    /// Catalog revision represented by every required projection.
    pub built_through_revision: StoreRevision,
    /// Analyzer/projection configuration digest.
    pub configuration_digest: ContentDigest,
    /// Root over canonical indexed semantics.
    pub semantic_root: ContentDigest,
    /// Fingerprint bound into candidate evidence.
    pub index_fingerprint: ContentDigest,
    /// Optional vector model and preprocessing fingerprint.
    pub vector_fingerprint: Option<ContentDigest>,
    /// Required and optional projections present.
    pub projections: BTreeSet<IndexKind>,
    /// Last successful verification time.
    pub last_verified_at: UtcTimestamp,
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
}

#[derive(Default)]
struct ManagerState {
    staged: BTreeMap<RecordId, Arc<IndexGeneration>>,
    active: Option<Arc<IndexGeneration>>,
}

/// Thread-safe generation builder, verifier, activator, and retriever.
pub struct InMemoryIndexManager {
    state: RwLock<ManagerState>,
    vector_adapter: Option<Arc<dyn VectorAdapter>>,
}

impl Default for InMemoryIndexManager {
    fn default() -> Self {
        Self {
            state: RwLock::new(ManagerState::default()),
            vector_adapter: None,
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
            vector_adapter: Some(adapter),
        }
    }

    /// Builds and verifies a complete unservable generation.
    pub fn build_generation(
        &self,
        build: IndexBuild,
        context: &RetrievalContext,
    ) -> Result<IndexGenerationDescriptor, RetrievalError> {
        context.check()?;
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
        let mut adjacency: BTreeMap<VersionId, BTreeSet<VersionId>> = BTreeMap::new();
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
        let index_fingerprint = fingerprint(
            &build.configuration_digest,
            &semantic_root,
            build.built_through_revision,
            build.vector_fingerprint.as_ref(),
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
        if build.vector_fingerprint.is_some() {
            projections.insert(IndexKind::Vector);
        }
        let descriptor = IndexGenerationDescriptor {
            generation_id: generation_id.clone(),
            state: IndexGenerationState::Verified,
            built_through_revision: build.built_through_revision,
            configuration_digest: build.configuration_digest,
            semantic_root,
            index_fingerprint,
            vector_fingerprint: build.vector_fingerprint,
            projections,
            last_verified_at: build.verified_at,
        };
        let generation = Arc::new(IndexGeneration {
            descriptor: descriptor.clone(),
            documents,
            adjacency,
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
        context.check()?;
        request.validate()?;
        let generation = self
            .state
            .read()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
            .active
            .clone()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        let lag = revision_lag(
            generation.descriptor.built_through_revision,
            request.required_revision,
            request.consistency,
        )?;
        let authorized: BTreeMap<VersionId, &IndexedDocument> = generation
            .documents
            .iter()
            .filter(|(_version, document)| authorized(document, &request.partition))
            .map(|(version, document)| (version.clone(), document))
            .collect();
        let mut evidence_by_version: BTreeMap<VersionId, BTreeSet<MatchEvidence>> = BTreeMap::new();
        let mut semantic_scores = BTreeMap::new();
        let mut fallback_used = false;
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
                &generation.adjacency,
                &mut evidence_by_version,
                context,
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
                self.vector_adapter.as_deref(),
                &mut evidence_by_version,
                &mut semantic_scores,
                context,
            ) {
                Ok(()) => {}
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
        }
        candidates.sort_by(candidate_order);
        candidates.truncate(request.limit);
        Ok(CandidateBatch {
            candidates,
            disclosure: RetrievalDisclosure {
                generation_id: generation.descriptor.generation_id.clone(),
                index_fingerprint: generation.descriptor.index_fingerprint.clone(),
                built_through_revision: generation.descriptor.built_through_revision,
                actual_revision_lag: lag,
                fallback_used,
                last_verified_at: generation.descriptor.last_verified_at,
            },
        })
    }
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

fn authorized(document: &IndexedDocument, partition: &crate::AuthorizedPartition) -> bool {
    document.atom.scope.tenant_id == partition.tenant_id
        && document
            .atom
            .scope
            .project_ids
            .iter()
            .any(|project| partition.project_ids.contains(project))
        && document
            .atom
            .governance
            .allowed_purposes
            .iter()
            .any(|purpose| purpose == "*" || purpose == &partition.purpose)
        && (document.atom.governance.processor_constraints.is_empty()
            || document
                .atom
                .governance
                .processor_constraints
                .contains(&partition.processor))
        && document.atom.governance.classification <= partition.maximum_classification
        && document.atom.governance.instruction_authority <= partition.maximum_instruction_authority
        && document.atom.temporal.valid_from <= partition.valid_at
        && document
            .atom
            .temporal
            .valid_until
            .is_none_or(|valid_until| partition.valid_at < valid_until)
        && document.atom.temporal.observed_at <= partition.observed_as_of
        && document.atom.lifecycle == Lifecycle::Active
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
) -> Result<(), RetrievalError> {
    let adapter =
        adapter.ok_or_else(|| RetrievalError::new(RetrievalErrorCode::ChannelUnavailable))?;
    if descriptor.vector_fingerprint.as_ref() != Some(adapter.fingerprint()) {
        return Err(RetrievalError::new(RetrievalErrorCode::ChannelUnavailable));
    }
    let query = VectorQuery {
        partition_digest: request.partition.partition_digest.clone(),
        terms: request.terms.clone(),
        allowed_versions: authorized.keys().cloned().collect(),
        limit: request.limit,
    };
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
    Ok(())
}

fn collect_graph_matches(
    request: &RetrievalRequest,
    authorized: &BTreeMap<VersionId, &IndexedDocument>,
    adjacency: &BTreeMap<VersionId, BTreeSet<VersionId>>,
    output: &mut BTreeMap<VersionId, BTreeSet<MatchEvidence>>,
    context: &RetrievalContext,
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
        if let Some(neighbors) = adjacency.get(&version) {
            for neighbor in neighbors {
                if authorized.contains_key(neighbor) && !visited.contains(neighbor) {
                    queue.push_back((neighbor.clone(), depth + 1));
                }
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
        staleness: u16::try_from(lag.min(10_000)).map_or(10_000, |value| value),
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

fn fingerprint(
    configuration: &ContentDigest,
    semantic_root: &ContentDigest,
    revision: StoreRevision,
    vector: Option<&ContentDigest>,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-INDEX-FINGERPRINT\0v1\0");
    hasher.update(configuration.as_str().as_bytes());
    hasher.update(semantic_root.as_str().as_bytes());
    hasher.update(revision.0.to_be_bytes());
    if let Some(vector) = vector {
        hasher.update(vector.as_str().as_bytes());
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
    use super::{InMemoryIndexManager, IndexBuild};
    use crate::{
        AuthorizedPartition, IndexGenerationState, RetrievalConsistency, RetrievalContext,
        RetrievalError, RetrievalErrorCode, RetrievalRequest, RetrievalStage, Retriever,
        VectorAdapter, VectorNeighbor, VectorQuery,
    };
    use cigar_protocol::{
        Classification, ContentDigest, ContextAtomV1, ContextEdge, InstructionAuthority, RecordId,
        RelativePath, SourceUri, UtcTimestamp, VersionId,
    };
    use cigar_store::{CancellationToken, StoreRevision};
    use cigar_testkit::deterministic_protocol_fixture;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::sync::{Arc, Mutex};
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
        Ok(AuthorizedPartition {
            tenant_id: tenant.clone(),
            project_ids: projects.into_iter().collect(),
            purpose: "coding".to_owned(),
            processor: "local".to_owned(),
            maximum_classification: Classification::Internal,
            maximum_instruction_authority: InstructionAuthority::Data,
            valid_at: timestamp("2026-07-10T00:00:02Z")?,
            observed_as_of: timestamp("2026-07-10T00:00:02Z")?,
            vector_allowed: false,
            partition_digest: digest(240)?,
        })
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
        Ok(IndexBuild {
            atoms,
            edges,
            built_through_revision: StoreRevision(revision),
            configuration_digest: digest(241)?,
            verified_at: timestamp("2026-07-10T00:00:03Z")?,
            vector_fingerprint: vector.then(|| digest(242)).transpose()?,
        })
    }

    struct RecordingVectorAdapter {
        fingerprint: ContentDigest,
        seen: Arc<Mutex<Option<VectorQuery>>>,
    }

    impl VectorAdapter for RecordingVectorAdapter {
        fn fingerprint(&self) -> &ContentDigest {
            &self.fingerprint
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
        assert_eq!(after.disclosure.built_through_revision, StoreRevision(8));
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
        let mut fallback_partition = partition(&tenant, [project])?;
        fallback_partition.vector_allowed = true;
        let mut fallback = request(RetrievalStage::Vector, fallback_partition, 30);
        fallback.terms.insert("cigar".to_owned());
        assert_eq!(
            manager
                .retrieve(&fallback, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::ChannelUnavailable)
        );
        fallback.allow_fallback = true;
        let fallback_batch = manager.retrieve(&fallback, &context())?;
        assert!(fallback_batch.disclosure.fallback_used);
        assert_eq!(fallback_batch.candidates.len(), 3);
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
        let fingerprint = digest(242)?;
        let seen = Arc::new(Mutex::new(None));
        let manager = InMemoryIndexManager::with_vector_adapter(Arc::new(RecordingVectorAdapter {
            fingerprint: fingerprint.clone(),
            seen: Arc::clone(&seen),
        }));
        let generation = manager.build_generation(
            IndexBuild {
                vector_fingerprint: Some(fingerprint),
                ..build(vec![allowed.clone(), denied], Vec::new(), 31, false)?
            },
            &context(),
        )?;
        manager.activate(&generation.generation_id, None)?;
        let mut authorized_partition = partition(&tenant, [project_a])?;
        authorized_partition.vector_allowed = true;
        let mut vector = request(RetrievalStage::Vector, authorized_partition, 31);
        vector.terms.insert("private_vector_query".to_owned());
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
}
