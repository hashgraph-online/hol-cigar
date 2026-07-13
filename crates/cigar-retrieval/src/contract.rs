//! Bounded authorization-first retrieval and index-generation contracts.

use cigar_protocol::{
    Classification, ContentDigest, InstructionAuthority, LineageId, RecordId, RelativePath,
    SourceUri, UtcTimestamp, VersionId,
};
use cigar_store::{CancellationToken, StoreRevision};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Instant;

/// Maximum candidates returned by one retrieval stage.
pub const MAX_CANDIDATES: usize = 100_000;
/// Maximum exact selectors in one stage.
pub const MAX_EXACT_SELECTORS: usize = 10_000;
/// Maximum normalized query terms in one lexical stage.
pub const MAX_QUERY_TERMS: usize = 1_024;
/// Maximum graph traversal depth.
pub const MAX_GRAPH_DEPTH: u16 = 32;
/// Maximum normalized integer feature value.
pub const MAX_FEATURE_VALUE: u16 = 10_000;

/// Stable content-free retrieval failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetrievalErrorCode {
    /// Query, partition, generation, descriptor, or selector metadata is invalid.
    InvalidMetadata,
    /// A byte, item, graph, score, or output bound was exceeded.
    LimitExceeded,
    /// Authorization partition denied the requested stage or processor.
    Denied,
    /// No verified active index generation exists.
    IndexUnavailable,
    /// Required strong or bounded-stale watermark was not met.
    IndexStale,
    /// Generation fingerprints or projection semantics failed verification.
    CorruptGeneration,
    /// Cooperative cancellation was requested.
    Cancelled,
    /// Exact monotonic deadline was reached.
    DeadlineExceeded,
    /// Optional channel failed and the request forbade fallback.
    ChannelUnavailable,
    /// A compile-blocking planned stage produced no authorized candidate.
    RequiredCandidateMissing,
}

/// Content-free retrieval error safe for caller-visible diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RetrievalError {
    code: RetrievalErrorCode,
}

impl RetrievalError {
    /// Creates one safe stable error.
    #[must_use]
    pub const fn new(code: RetrievalErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable category.
    #[must_use]
    pub const fn code(self) -> RetrievalErrorCode {
        self.code
    }
}

impl fmt::Debug for RetrievalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for RetrievalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "retrieval failed: {:?}", self.code)
    }
}

impl std::error::Error for RetrievalError {}

/// Exact cancellation and monotonic deadline for one retrieval stage.
#[derive(Clone)]
pub struct RetrievalContext {
    /// Cooperative cancellation shared with repository work.
    pub cancellation: CancellationToken,
    /// Exact monotonic deadline.
    pub deadline: Instant,
}

impl RetrievalContext {
    /// Fails at every bounded loop boundary after cancellation or deadline.
    pub fn check(&self) -> Result<(), RetrievalError> {
        if self.cancellation.is_cancelled() {
            Err(RetrievalError::new(RetrievalErrorCode::Cancelled))
        } else if Instant::now() >= self.deadline {
            Err(RetrievalError::new(RetrievalErrorCode::DeadlineExceeded))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for RetrievalContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalContext")
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// Closed required and optional projection registry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IndexKind {
    /// Exact record, lineage, digest, URI, and revision identities.
    Exact,
    /// Tenant, project, purpose, and processor scope metadata.
    Scope,
    /// Source path and filename.
    Path,
    /// Fully qualified symbol term.
    Symbol,
    /// Declared entity and tag terms.
    Entity,
    /// Bitemporal validity and freshness.
    Temporal,
    /// Instruction authority and classification.
    Authority,
    /// Authorized lexical full text.
    Lexical,
    /// Forward and reverse typed provenance graph.
    Graph,
    /// Current active lineage and lifecycle state.
    ActiveState,
    /// Optional partitioned vector neighbors.
    Vector,
}

/// Immutable index generation lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexGenerationState {
    /// Projection build is incomplete and unservable.
    Building,
    /// Projection is replaying causal outbox records.
    CatchingUp,
    /// Counts, roots, bounds, and samples passed verification.
    Verified,
    /// Atomically selected for new retrieval snapshots.
    Active,
    /// Integrity verification failed; generation is unservable.
    Corrupt,
}

/// Authorization result fixed before any retrieval channel executes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedPartition {
    /// Exact owning tenant.
    pub tenant_id: RecordId,
    /// Sorted non-empty visible projects.
    pub project_ids: BTreeSet<RecordId>,
    /// Exact allowed purpose selector.
    pub purpose: String,
    /// Exact approved processor identifier.
    pub processor: String,
    /// Greatest information classification visible to the caller.
    pub maximum_classification: Classification,
    /// Greatest instruction authority visible to the caller.
    pub maximum_instruction_authority: InstructionAuthority,
    /// World-valid instant selected by the caller's immutable snapshot.
    pub valid_at: UtcTimestamp,
    /// Transaction-time observation bound selected by the immutable snapshot.
    pub observed_as_of: UtcTimestamp,
    /// Whether authorized plaintext may reach the configured vector processor.
    pub vector_allowed: bool,
    /// Digest of the policy decision and partition semantics.
    pub partition_digest: ContentDigest,
}

impl AuthorizedPartition {
    /// Validates a non-empty bounded partition before retrieval begins.
    pub fn validate(&self) -> Result<(), RetrievalError> {
        if self.project_ids.is_empty()
            || self.project_ids.len() > 1_024
            || self.purpose.is_empty()
            || self.purpose.len() > 256
            || self.processor.is_empty()
            || self.processor.len() > 256
            || self
                .purpose
                .bytes()
                .chain(self.processor.bytes())
                .any(|byte| byte.is_ascii_control())
        {
            Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for AuthorizedPartition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedPartition")
            .field("project_count", &self.project_ids.len())
            .field("purpose_bytes", &self.purpose.len())
            .field("processor_bytes", &self.processor.len())
            .field("maximum_classification", &self.maximum_classification)
            .field(
                "maximum_instruction_authority",
                &self.maximum_instruction_authority,
            )
            .field("valid_at", &self.valid_at)
            .field("observed_as_of", &self.observed_as_of)
            .field("vector_allowed", &self.vector_allowed)
            .field("partition_digest", &self.partition_digest)
            .finish_non_exhaustive()
    }
}

/// Independent bounded retrieval stages.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetrievalStage {
    /// Mandatory exact identities.
    Exact,
    /// Path, symbol, entity, and declared-term lookup.
    Metadata,
    /// Authorized lexical matching.
    Lexical,
    /// Optional authorized vector neighbors.
    Vector,
    /// Bounded graph expansion.
    Graph,
    /// Temporal, freshness, authority, and active-state augmentation.
    Augment,
}

/// Explicit consistency requirement pinned to a catalog revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetrievalConsistency {
    /// Every required projection must be built through the requested revision.
    Strong,
    /// Exact maximum accepted catalog-commit lag.
    BoundedStale {
        /// Maximum revision difference.
        max_revision_lag: u64,
    },
}

/// One immutable bounded stage request.
#[derive(Clone, Eq, PartialEq)]
pub struct RetrievalRequest {
    /// Stage being executed.
    pub stage: RetrievalStage,
    /// Authorization partition frozen before channel execution.
    pub partition: AuthorizedPartition,
    /// Required catalog commit.
    pub required_revision: StoreRevision,
    /// Strong or explicitly bounded-stale behavior.
    pub consistency: RetrievalConsistency,
    /// Sorted exact semantic versions.
    pub exact_versions: BTreeSet<VersionId>,
    /// Sorted exact immutable atom record identities.
    pub atom_ids: BTreeSet<RecordId>,
    /// Sorted exact semantic lineage identities.
    pub lineage_ids: BTreeSet<LineageId>,
    /// Sorted exact protected-content digests.
    pub content_digests: BTreeSet<ContentDigest>,
    /// Sorted exact canonical source URIs.
    pub canonical_uris: BTreeSet<SourceUri>,
    /// Sorted exact immutable connector revisions.
    pub source_revisions: BTreeSet<String>,
    /// Sorted platform-neutral path selectors.
    pub paths: BTreeSet<RelativePath>,
    /// Sorted normalized lexical/symbol/entity terms.
    pub terms: BTreeSet<String>,
    /// Sorted graph roots.
    pub graph_roots: BTreeSet<VersionId>,
    /// Maximum graph depth.
    pub graph_depth: u16,
    /// Hard candidate cap.
    pub limit: usize,
    /// Whether an optional vector outage may fall back to non-vector channels.
    pub allow_fallback: bool,
}

impl RetrievalRequest {
    /// Validates every cap before touching a generation or adapter.
    pub fn validate(&self) -> Result<(), RetrievalError> {
        self.partition.validate()?;
        if self.limit == 0
            || self.limit > MAX_CANDIDATES
            || self.exact_versions.len() > MAX_EXACT_SELECTORS
            || self.atom_ids.len() > MAX_EXACT_SELECTORS
            || self.lineage_ids.len() > MAX_EXACT_SELECTORS
            || self.content_digests.len() > MAX_EXACT_SELECTORS
            || self.canonical_uris.len() > MAX_EXACT_SELECTORS
            || self.source_revisions.len() > MAX_EXACT_SELECTORS
            || self.paths.len() > MAX_EXACT_SELECTORS
            || self.terms.len() > MAX_QUERY_TERMS
            || self.graph_roots.len() > MAX_EXACT_SELECTORS
            || self.graph_depth > MAX_GRAPH_DEPTH
            || self
                .terms
                .iter()
                .any(|term| term.is_empty() || term.len() > 256)
            || self.source_revisions.iter().any(|revision| {
                revision.is_empty()
                    || revision.len() > 1_024
                    || revision.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        if self.stage == RetrievalStage::Vector && !self.partition.vector_allowed {
            return Err(RetrievalError::new(RetrievalErrorCode::Denied));
        }
        Ok(())
    }
}

impl fmt::Debug for RetrievalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalRequest")
            .field("stage", &self.stage)
            .field("partition", &self.partition)
            .field("required_revision", &self.required_revision)
            .field("consistency", &self.consistency)
            .field("exact_count", &self.exact_versions.len())
            .field("atom_id_count", &self.atom_ids.len())
            .field("lineage_id_count", &self.lineage_ids.len())
            .field("content_digest_count", &self.content_digests.len())
            .field("canonical_uri_count", &self.canonical_uris.len())
            .field("source_revision_count", &self.source_revisions.len())
            .field("path_count", &self.paths.len())
            .field("term_count", &self.terms.len())
            .field("graph_root_count", &self.graph_roots.len())
            .field("graph_depth", &self.graph_depth)
            .field("limit", &self.limit)
            .field("allow_fallback", &self.allow_fallback)
            .finish()
    }
}

/// Quantized deterministic v1 candidate feature vector.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidateFeatures {
    /// Requirement selector match.
    pub requirement_match: u16,
    /// Exact selector match.
    pub exact_match: u16,
    /// Lexical match.
    pub lexical_match: u16,
    /// Quantized vector/semantic match.
    pub semantic_match: u16,
    /// Graph proximity.
    pub graph_proximity: u16,
    /// Project proximity.
    pub project_proximity: u16,
    /// Task proximity.
    pub task_proximity: u16,
    /// Authority signal.
    pub authority: u16,
    /// Verification signal.
    pub verification: u16,
    /// Freshness signal.
    pub freshness: u16,
    /// Novelty signal.
    pub novelty: u16,
    /// Conflict risk penalty.
    pub conflict_risk: u16,
    /// Staleness penalty.
    pub staleness: u16,
    /// Deterministic representation token estimate.
    pub estimated_tokens: u32,
    /// Requirement coverage bitset.
    pub requirement_coverage_bits: u64,
    /// Entity coverage bitset.
    pub entity_coverage_bits: u64,
}

impl CandidateFeatures {
    /// Validates all normalized features and computes the checked balanced-v1 score.
    pub fn balanced_score(self) -> Result<i64, RetrievalError> {
        let normalized = [
            self.requirement_match,
            self.exact_match,
            self.lexical_match,
            self.semantic_match,
            self.graph_proximity,
            self.project_proximity,
            self.task_proximity,
            self.authority,
            self.verification,
            self.freshness,
            self.novelty,
            self.conflict_risk,
            self.staleness,
        ];
        if normalized.iter().any(|value| *value > MAX_FEATURE_VALUE) {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        let positive = [
            (280_i64, self.requirement_match),
            (150, self.exact_match),
            (110, self.lexical_match),
            (80, self.semantic_match),
            (90, self.graph_proximity),
            (70, self.project_proximity),
            (60, self.task_proximity),
            (90, self.authority),
            (45, self.verification),
            (35, self.freshness),
            (30, self.novelty),
        ];
        let negative = [(130_i64, self.conflict_risk), (100, self.staleness)];
        let mut score = 0_i64;
        for (weight, value) in positive {
            score = score
                .checked_add(weight * i64::from(value))
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        for (weight, value) in negative {
            score = score
                .checked_sub(weight * i64::from(value))
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        Ok(score)
    }
}

/// Content-free reason proving why one channel returned a candidate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MatchEvidence {
    /// Exact identity selector matched.
    ExactIdentity,
    /// Exact path selector matched.
    ExactPath,
    /// Declared symbol/entity term matched.
    DeclaredTerm,
    /// Authorized lexical term matched.
    Lexical,
    /// Quantized vector neighbor matched.
    Vector,
    /// Graph root and bounded depth reached the version.
    Graph {
        /// Minimum traversal depth from an authorized root.
        depth: u16,
    },
    /// Temporal/authority/current-state augmentation included the version.
    Augment,
}

/// Metadata-only candidate reference returned before protected content loading.
#[derive(Clone, Eq, PartialEq)]
pub struct CandidateRef {
    /// Exact immutable semantic version.
    pub version_id: VersionId,
    /// Canonical source URI, available only after partition authorization.
    pub canonical_uri: SourceUri,
    /// Optional exact platform-neutral path.
    pub relative_path: Option<RelativePath>,
    /// Instruction authority used by deterministic feature generation.
    pub instruction_authority: InstructionAuthority,
    /// Quantized features.
    pub features: CandidateFeatures,
    /// Checked balanced-v1 score.
    pub total_score: i64,
    /// Sorted evidence classes.
    pub evidence: BTreeSet<MatchEvidence>,
}

impl fmt::Debug for CandidateRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateRef")
            .field("version_id", &self.version_id)
            .field("has_path", &self.relative_path.is_some())
            .field("instruction_authority", &self.instruction_authority)
            .field("features", &self.features)
            .field("total_score", &self.total_score)
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

/// Exact index consistency and fallback disclosure returned with every batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievalDisclosure {
    /// Active immutable generation identity.
    pub generation_id: RecordId,
    /// Generation configuration/index fingerprint.
    pub index_fingerprint: ContentDigest,
    /// Catalog revision built into the generation.
    pub built_through_revision: StoreRevision,
    /// Exact revision lag relative to the request.
    pub actual_revision_lag: u64,
    /// Whether an optional channel degraded to deterministic non-vector retrieval.
    pub fallback_used: bool,
    /// UTC verification time for the active generation.
    pub last_verified_at: UtcTimestamp,
}

/// Deterministically ordered bounded candidate batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateBatch {
    /// Ordered metadata-only candidates.
    pub candidates: Vec<CandidateRef>,
    /// Exact generation, watermark, lag, and fallback disclosure.
    pub disclosure: RetrievalDisclosure,
}

/// Backend-neutral authorized retrieval stage.
pub trait Retriever: Send + Sync {
    /// Executes one immutable bounded stage without returning protected content.
    fn retrieve(
        &self,
        request: &RetrievalRequest,
        context: &RetrievalContext,
    ) -> Result<CandidateBatch, RetrievalError>;
}

#[cfg(test)]
mod tests {
    use super::CandidateFeatures;
    use std::error::Error;
    use std::time::{Duration, Instant};

    #[test]
    fn one_million_candidate_feature_stress_is_exact_and_bounded() -> Result<(), Box<dyn Error>> {
        if std::env::var("CIGAR_PERFORMANCE_GATES").ok().as_deref() != Some("1") {
            return Ok(());
        }
        let started = Instant::now();
        let mut checksum = 0_i128;
        let mut minimum = i64::MAX;
        let mut maximum = i64::MIN;
        for index in 0..1_000_000_u64 {
            let quantized = u16::try_from(index % 10_001)?;
            let features = CandidateFeatures {
                requirement_match: 10_000,
                exact_match: quantized,
                lexical_match: 10_000_u16.saturating_sub(quantized),
                semantic_match: quantized / 2,
                graph_proximity: 5_000,
                project_proximity: 10_000,
                task_proximity: 2_500,
                authority: 7_500,
                verification: 8_000,
                freshness: 9_000,
                novelty: 1_000,
                conflict_risk: quantized / 4,
                staleness: quantized / 8,
                estimated_tokens: u32::from(quantized) + 1,
                requirement_coverage_bits: index,
                entity_coverage_bits: index.rotate_left(17),
            };
            let score = features.balanced_score()?;
            checksum = checksum
                .checked_add(i128::from(score))
                .ok_or("checksum overflow")?;
            minimum = minimum.min(score);
            maximum = maximum.max(score);
        }
        let elapsed = started.elapsed();
        println!(
            "WP06_CANDIDATE_STRESS candidates=1000000 elapsed_ms={} checksum={checksum} minimum={minimum} maximum={maximum}",
            elapsed.as_millis()
        );
        assert!(elapsed < Duration::from_secs(5));
        assert!(checksum != 0);
        assert!(minimum < maximum);
        Ok(())
    }
}
