//! Frozen compiler profiles, candidates, representations, and output evidence.

use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    CandidateDisposition, Classification, ContentDigest, ContextBundle, ContextContract,
    InstructionAuthority, LaneKind, LineageId, ManifestEntry, RepresentationKind,
    SelectionManifest, SourceUri, UtcTimestamp, VersionId,
};
use cigar_retrieval::{CandidateFeatures, RequirementRankingEvidence, RetrievalProfile};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Maximum deterministic local-swap passes.
pub const MAX_LOCAL_SWAP_PASSES: u16 = 64;

/// Stable compiler failure categories without protected content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompilerErrorCode {
    /// Contract, profile, candidate, representation, or frozen input is malformed.
    InvalidInput,
    /// A byte, token, candidate, dependency, iteration, or output bound was exceeded.
    LimitExceeded,
    /// One or more mandatory candidates or their lossless closure cannot fit.
    BudgetUnsatisfiable,
    /// A blocking requirement has no selected authorized candidate.
    RequiredMissing,
    /// Required dependency graph contains a cycle or missing node.
    InvalidDependency,
    /// A critical claim conflict remains unresolved.
    UnresolvedCriticalConflict,
    /// A pinned catalog, graph, policy, index, tokenizer, materializer, or profile differs.
    PinMismatch,
    /// Policy disposition is not eligible for compilation.
    PolicyDenied,
    /// Canonical sealing or protocol validation failed.
    SealFailed,
}

/// Content-free compiler error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CompilerError {
    code: CompilerErrorCode,
    minimum_required_tokens: Option<u32>,
}

impl CompilerError {
    /// Creates one stable compiler error.
    #[must_use]
    pub const fn new(code: CompilerErrorCode) -> Self {
        Self {
            code,
            minimum_required_tokens: None,
        }
    }

    /// Creates an unsatisfiable-budget error with its exact mandatory lower bound.
    #[must_use]
    pub const fn budget(minimum_required_tokens: u32) -> Self {
        Self {
            code: CompilerErrorCode::BudgetUnsatisfiable,
            minimum_required_tokens: Some(minimum_required_tokens),
        }
    }

    /// Returns the stable category.
    #[must_use]
    pub const fn code(self) -> CompilerErrorCode {
        self.code
    }

    /// Returns the exact mandatory lower bound when budget feasibility failed.
    #[must_use]
    pub const fn minimum_required_tokens(self) -> Option<u32> {
        self.minimum_required_tokens
    }
}

impl fmt::Debug for CompilerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompilerError")
            .field("code", &self.code)
            .field("minimum_required_tokens", &self.minimum_required_tokens)
            .finish()
    }
}

impl fmt::Display for CompilerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "context compilation failed: {:?}", self.code)
    }
}

impl std::error::Error for CompilerError {}

/// Exact immutable dependencies frozen during planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenInputs {
    /// Catalog snapshot or commit fingerprint.
    pub catalog_watermark: ContentDigest,
    /// Graph projection revision fingerprint.
    pub graph_revision: ContentDigest,
    /// Current policy snapshot digest.
    pub policy_digest: ContentDigest,
    /// Sorted required index fingerprints.
    pub index_fingerprints: BTreeSet<ContentDigest>,
    /// Deterministic staged retrieval-plan fingerprint.
    pub retrieval_plan_digest: ContentDigest,
    /// Compiler profile fingerprint.
    pub compiler_profile_digest: ContentDigest,
    /// Target tokenizer fingerprint copied from the normalized contract.
    pub tokenizer_fingerprint: ContentDigest,
    /// Target materializer fingerprint copied from the normalized contract.
    pub materializer_fingerprint: ContentDigest,
}

/// Deterministic v1 packing and quota profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerProfile {
    /// Must be `cigar.compiler-profile.balanced.v1`.
    pub profile_id: String,
    /// Retrieval score profile used by the compiler's packing utility.
    pub retrieval_profile: RetrievalProfile,
    /// Minimum selected items per declared lane when eligible candidates exist.
    pub minimum_items: BTreeMap<LaneKind, u16>,
    /// Maximum selected items per lane.
    pub maximum_items: BTreeMap<LaneKind, u16>,
    /// Fixed bounded local-swap passes.
    pub local_swap_passes: u16,
    /// Maximum top-ranked alternatives considered by each local-swap pass.
    pub local_swap_alternatives: u16,
    /// Requirement coverage gain.
    pub requirement_coverage_weight: i64,
    /// Entity coverage gain.
    pub entity_coverage_weight: i64,
    /// Information-loss penalty per loss tier.
    pub loss_penalty: i64,
    /// Rank optional candidates by utility per token instead of absolute utility.
    pub utility_density_ranking: bool,
    /// Minimum deterministic lexical feature admitted for optional packing.
    pub minimum_lexical_match: u16,
    /// Dynamic gain per newly covered requirement in the H1 profile.
    pub marginal_requirement_weight: i64,
    /// Dynamic gain per newly covered entity bit in the H1 profile.
    pub marginal_entity_weight: i64,
    /// Cost per direct dependency in an optional closure in the H1 profile.
    pub dependency_cost_penalty: i64,
    /// Gain when a candidate adds a lane not yet represented in the H1 profile.
    pub diversity_weight: i64,
    /// Penalty per already-covered requirement/entity in the H1 profile.
    pub redundancy_penalty: i64,
    /// Evidence items retained per requirement before optional context is saturated.
    ///
    /// Zero preserves fill-to-budget behavior. A positive value still admits candidates that
    /// add a previously uncovered entity bit, then stops packing redundant context.
    pub sufficient_items_per_requirement: u16,
}

impl Default for CompilerProfile {
    fn default() -> Self {
        Self {
            profile_id: "cigar.compiler-profile.balanced.v1".to_owned(),
            retrieval_profile: RetrievalProfile::BalancedV1,
            minimum_items: BTreeMap::new(),
            maximum_items: BTreeMap::new(),
            local_swap_passes: 8,
            local_swap_alternatives: 32,
            requirement_coverage_weight: 250_000,
            entity_coverage_weight: 100_000,
            loss_penalty: 50_000,
            utility_density_ranking: true,
            minimum_lexical_match: 0,
            marginal_requirement_weight: 0,
            marginal_entity_weight: 0,
            dependency_cost_penalty: 0,
            diversity_weight: 0,
            redundancy_penalty: 0,
            sufficient_items_per_requirement: 0,
        }
    }
}

impl CompilerProfile {
    /// Honey 0.9.2 H1 compiler profile.
    #[must_use]
    pub fn balanced_v2_candidate() -> Self {
        Self {
            profile_id: "cigar.compiler-profile.balanced.v2-candidate.1".to_owned(),
            retrieval_profile: RetrievalProfile::BalancedV2Candidate,
            local_swap_passes: 0,
            requirement_coverage_weight: 50_000,
            entity_coverage_weight: 20_000,
            utility_density_ranking: false,
            minimum_lexical_match: 8_000,
            marginal_requirement_weight: 300_000,
            marginal_entity_weight: 120_000,
            dependency_cost_penalty: 40_000,
            diversity_weight: 75_000,
            redundancy_penalty: 90_000,
            ..Self::default()
        }
    }

    /// Requirement-aware ranking candidate with the H1 packing policy held constant.
    #[must_use]
    pub fn balanced_v2_requirement_aware_candidate() -> Self {
        Self {
            profile_id: "cigar.compiler-profile.balanced.v2-candidate.2".to_owned(),
            retrieval_profile: RetrievalProfile::BalancedV2RequirementAwareCandidate,
            ..Self::balanced_v2_candidate()
        }
    }

    /// CIGAR 0.9.3 requirement-aware, coverage-saturating production profile.
    #[must_use]
    pub fn balanced_v3() -> Self {
        Self {
            profile_id: "cigar.compiler-profile.balanced.v3".to_owned(),
            sufficient_items_per_requirement: 2,
            ..Self::balanced_v2_requirement_aware_candidate()
        }
    }

    /// CIGAR 0.9.4 value-of-information packing profile.
    #[must_use]
    pub fn balanced_v4() -> Self {
        Self {
            profile_id: "cigar.compiler-profile.balanced.v4".to_owned(),
            retrieval_profile: RetrievalProfile::BalancedV4,
            local_swap_passes: 0,
            sufficient_items_per_requirement: 0,
            ..Self::balanced_v2_requirement_aware_candidate()
        }
    }
}

/// Information loss class for one deterministic representation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LossClass {
    /// Exact or structurally lossless representation.
    Lossless,
    /// Extractive representation retaining direct evidence.
    Extractive,
    /// Pre-existing verified lossy representation.
    VerifiedLossy,
}

/// One mutually exclusive representation of a logical candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepresentationVariant {
    /// Protocol representation kind.
    pub kind: RepresentationKind,
    /// Exact rendered-content digest.
    pub content_digest: ContentDigest,
    /// Exact physical target token cost.
    pub token_count: u32,
    /// Information loss class.
    pub loss: LossClass,
    /// Required evidence receipt for extracted or summarized content.
    pub transform_receipt: Option<ContentDigest>,
}

impl RepresentationVariant {
    /// Creates an exact lossless representation.
    pub fn exact(content_digest: ContentDigest, token_count: u32) -> Result<Self, CompilerError> {
        representation(
            RepresentationKind::Exact,
            content_digest,
            token_count,
            LossClass::Lossless,
            None,
        )
    }

    /// Creates an evidence-backed extractive representation.
    pub fn extracted(
        content_digest: ContentDigest,
        token_count: u32,
        transform_receipt: ContentDigest,
    ) -> Result<Self, CompilerError> {
        representation(
            RepresentationKind::Extracted,
            content_digest,
            token_count,
            LossClass::Extractive,
            Some(transform_receipt),
        )
    }

    /// Creates a pre-existing verified evidence-carrying summary representation.
    pub fn verified_summary(
        content_digest: ContentDigest,
        token_count: u32,
        validation_receipt: ContentDigest,
    ) -> Result<Self, CompilerError> {
        representation(
            RepresentationKind::Summarized,
            content_digest,
            token_count,
            LossClass::VerifiedLossy,
            Some(validation_receipt),
        )
    }

    /// Creates a typed redacted marker representation.
    pub fn redacted(
        content_digest: ContentDigest,
        token_count: u32,
    ) -> Result<Self, CompilerError> {
        representation(
            RepresentationKind::Redacted,
            content_digest,
            token_count,
            LossClass::Lossless,
            None,
        )
    }
}

fn representation(
    kind: RepresentationKind,
    content_digest: ContentDigest,
    token_count: u32,
    loss: LossClass,
    transform_receipt: Option<ContentDigest>,
) -> Result<RepresentationVariant, CompilerError> {
    if token_count == 0 {
        Err(CompilerError::new(CompilerErrorCode::InvalidInput))
    } else {
        Ok(RepresentationVariant {
            kind,
            content_digest,
            token_count,
            loss,
            transform_receipt,
        })
    }
}

/// Typed claim used for deterministic conflict reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateClaim {
    /// Normalized subject and predicate key.
    pub key: String,
    /// Canonical claim-value digest.
    pub value_digest: ContentDigest,
    /// World-valid time used after explicit supersession.
    pub valid_at: UtcTimestamp,
    /// Observation time used after world-valid time.
    pub observed_at: UtcTimestamp,
    /// Source authority used after time.
    pub authority: u16,
    /// Whether a validation receipt supports the claim.
    pub verified: bool,
}

/// Complete metadata-only compiler candidate.
#[derive(Clone, Eq, PartialEq)]
pub struct CompilerCandidate {
    /// Immutable catalog semantic version.
    pub version_id: VersionId,
    /// Stable logical identity used to collapse aliases/duplicates.
    pub logical_id: VersionId,
    /// Stable semantic lineage used to prove independent corroboration.
    pub lineage_id: LineageId,
    /// Canonical source URI for deterministic ties.
    pub canonical_uri: SourceUri,
    /// Destination authority/category lane.
    pub lane: LaneKind,
    /// Whether this candidate is mandatory independent of requirement coverage.
    pub mandatory: bool,
    /// Requirements covered by the candidate.
    pub requirement_indices: BTreeSet<usize>,
    /// Entities covered by the candidate.
    pub entity_coverage_bits: u64,
    /// Balanced-v1 retrieval features.
    pub features: CandidateFeatures,
    /// Current policy outcome fixed before protected content transformation.
    pub policy_outcome: PolicyOutcome,
    /// Stable hard-gate or canonicalization exclusion fixed before packing.
    pub pre_exclusion_reason: Option<cigar_protocol::DispositionReason>,
    /// Current information classification.
    pub classification: Classification,
    /// Instruction authority fixed from source/path policy.
    pub instruction_authority: InstructionAuthority,
    /// Direct dependency versions required by every representation.
    pub dependencies: BTreeSet<VersionId>,
    /// Mutually exclusive deterministic representations.
    pub representations: Vec<RepresentationVariant>,
    /// Optional typed claim.
    pub claim: Option<CandidateClaim>,
    /// Exact provenance digest recorded in the manifest.
    pub provenance_digest: ContentDigest,
}

impl fmt::Debug for CompilerCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompilerCandidate")
            .field("version_id", &self.version_id)
            .field("logical_id", &self.logical_id)
            .field("lane", &self.lane)
            .field("mandatory", &self.mandatory)
            .field("requirement_count", &self.requirement_indices.len())
            .field("policy_outcome", &self.policy_outcome)
            .field("has_pre_exclusion", &self.pre_exclusion_reason.is_some())
            .field("classification", &self.classification)
            .field("instruction_authority", &self.instruction_authority)
            .field("dependency_count", &self.dependencies.len())
            .field("representation_count", &self.representations.len())
            .field("has_claim", &self.claim.is_some())
            .finish_non_exhaustive()
    }
}

/// Full immutable input for deterministic planning and compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileRequest {
    /// User contract to normalize and validate.
    pub contract: ContextContract,
    /// Exact component pins.
    pub frozen: FrozenInputs,
    /// Deterministic profile.
    pub profile: CompilerProfile,
    /// Every authorized and denied considered candidate.
    pub candidates: Vec<CompilerCandidate>,
    /// H2-only deterministic pre-budget ranking explanation bound to the retrieval plan.
    pub ranking_evidence: Option<RequirementRankingEvidence>,
}

/// Invalidation roots registered for the sealed result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationRegistration {
    /// Selected and closure catalog versions.
    pub catalog_versions: BTreeSet<VersionId>,
    /// Policy snapshot dependency.
    pub policy_digest: ContentDigest,
    /// Index dependencies.
    pub index_fingerprints: BTreeSet<ContentDigest>,
    /// Retrieval-stage plan dependency.
    pub retrieval_plan_digest: ContentDigest,
    /// Compiler profile dependency.
    pub compiler_profile_digest: ContentDigest,
}

/// Protected content-equivalence accounting retained outside the frozen v1 protocol records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentEquivalenceDiagnostic {
    /// Stable representative used by the plan and selected block.
    pub representative_version: VersionId,
    /// Sorted source versions represented by the class, including the representative.
    pub member_versions: BTreeSet<VersionId>,
    /// Sorted exact provenance commitments retained for every member manifest entry.
    pub provenance_digests: BTreeSet<ContentDigest>,
    /// Selected shared block, or `None` when the class was not packed.
    pub selected_block_id: Option<VersionId>,
}

/// Exact protected citation resolution for one source version represented by a shared block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CitationResolution {
    /// Version cited by the caller.
    pub cited_version: VersionId,
    /// Exact source version whose lineage the citation retains.
    pub source_version: VersionId,
    /// Stable class representative named by the v1 plan.
    pub representative_version: VersionId,
    /// Shared selected block containing the source version in its provenance.
    pub block_id: VersionId,
}

/// Caller-safe explanation entry after disclosure filtering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestViewEntry {
    /// Authorized version.
    pub version_id: VersionId,
    /// Final disposition.
    pub disposition: CandidateDisposition,
}

/// Disclosure-filtered deterministic explanation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestView {
    /// Only entries authorized for explanation.
    pub entries: Vec<ManifestViewEntry>,
}

/// Content-free reason why a v4 root entered the selected dependency closure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackingDecisionBasis {
    /// Explicitly mandatory candidate.
    Mandatory,
    /// First admissible item for a blocking requirement.
    BlockingRequirement,
    /// Independent corroboration reserved for effect-adjacent evidence.
    IndependentCorroboration,
    /// Candidate needed to satisfy a configured lane minimum.
    LaneMinimum,
    /// Positive value-of-information admission.
    MarginalUtility,
}

/// Content-free reason why v4 stopped considering optional context.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackingStopReason {
    /// Every eligible non-dominated root was selected.
    Exhausted,
    /// No remaining feasible root had positive contextual marginal utility.
    NonPositiveMarginalUtility,
    /// Positive roots remained, but every one exceeded a lane token or item bound.
    CapacitySaturated,
}

/// One deterministic v4 root-admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackingDecision {
    /// One-based selection order.
    pub ordinal: usize,
    /// Root whose dependency closure was admitted.
    pub selected_version: VersionId,
    /// Policy reason for admission.
    pub basis: PackingDecisionBasis,
    /// Context-sensitive utility at admission time.
    pub marginal_utility: i64,
    /// Exact new physical tokens admitted by the root and its unselected closure.
    pub incremental_tokens: u32,
    /// Number of newly selected closure members.
    pub closure_items: usize,
    /// Requirements represented for the first time by the new closure.
    pub newly_covered_requirements: usize,
    /// Requirements gaining source-, lineage-, and content-independent evidence.
    pub independently_corroborated_requirements: usize,
    /// Entity bits introduced by the new closure.
    pub newly_covered_entities: u32,
    /// Whether the decision was adjacent to an external effect.
    pub effect_adjacent: bool,
}

/// Content-free reason why an optional v4 candidate was conservatively dominated.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackingDominanceReason {
    /// The winner has the same provenance and no weaker value or greater closure cost.
    SameProvenanceNoWeakerValue,
}

/// One conservative v4 dominance result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackingDominanceDecision {
    /// Optional candidate excluded from the competitive scan.
    pub dominated_version: VersionId,
    /// Candidate proving every admissible value dimension at no greater closure cost.
    pub dominating_version: VersionId,
    /// Content-free proof rule used to exclude the dominated candidate.
    pub reason: PackingDominanceReason,
}

/// Complete content-free v4 packing explanation sealed by its digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackingEvidence {
    /// Exact v4 compiler profile identifier.
    pub compiler_profile_id: String,
    /// Exact profile digest used by the compile.
    pub compiler_profile_digest: ContentDigest,
    /// Tokenizer fingerprint used for every exact representation count.
    pub tokenizer_fingerprint: ContentDigest,
    /// Digest over canonical candidates, chosen representations, and cached closures.
    pub workspace_fingerprint: ContentDigest,
    /// Ordered root admissions.
    pub decisions: Vec<PackingDecision>,
    /// Sorted conservative dominance explanations.
    pub dominance_decisions: Vec<PackingDominanceDecision>,
    /// Deterministic optional-packing stop reason.
    pub stop_reason: PackingStopReason,
    /// Digest over every preceding field and explanation entry.
    pub evidence_digest: ContentDigest,
}

/// Sealed plan, manifest, bundle, and invalidation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileOutput {
    /// Normalized validated contract.
    pub normalized_contract: ContextContract,
    /// Protocol plan.
    pub plan: cigar_protocol::ContextPlan,
    /// Complete protected manifest.
    pub manifest: SelectionManifest,
    /// Deterministic packed semantic bundle.
    pub bundle: ContextBundle,
    /// Dependency roots for invalidation.
    pub invalidation: InvalidationRegistration,
    /// Protected non-wire accounting for content-equivalent candidates and citations.
    pub content_equivalence: Vec<ContentEquivalenceDiagnostic>,
    /// H2-only explanation whose digest and decisions are sealed into manifest extensions.
    pub ranking_evidence: Option<RequirementRankingEvidence>,
    /// V4-only value-of-information packing explanation sealed into manifest extensions.
    pub packing_evidence: Option<PackingEvidence>,
}

impl CompileOutput {
    /// Applies disclosure policy to a manifest explanation.
    #[must_use]
    pub fn explain(&self, authorized_versions: &BTreeSet<VersionId>) -> ManifestView {
        ManifestView {
            entries: self
                .manifest
                .entries
                .iter()
                .filter(|entry| authorized_versions.contains(&entry.version_id))
                .map(|entry| ManifestViewEntry {
                    version_id: entry.version_id.clone(),
                    disposition: entry.disposition.clone(),
                })
                .collect(),
        }
    }

    /// Resolves an authorized source-version citation to its exact lineage and shared block.
    ///
    /// The caller must apply the same disclosure authorization used for manifest explanations
    /// before invoking this protected lookup.
    #[must_use]
    pub fn resolve_citation(&self, cited_version: &VersionId) -> Option<CitationResolution> {
        self.content_equivalence.iter().find_map(|class| {
            let block_id = class.selected_block_id.as_ref()?;
            class
                .member_versions
                .contains(cited_version)
                .then(|| CitationResolution {
                    cited_version: cited_version.clone(),
                    source_version: cited_version.clone(),
                    representative_version: class.representative_version.clone(),
                    block_id: block_id.clone(),
                })
        })
    }
}

/// Internal selected representation used during packing and sealing.
#[derive(Clone, Debug)]
pub(crate) struct Selection {
    pub candidate: CompilerCandidate,
    pub representation: RepresentationVariant,
    pub utility: i64,
}

/// Internal final disposition and supplementary manifest reasons.
#[derive(Clone, Debug)]
pub(crate) struct DispositionRecord {
    pub disposition: CandidateDisposition,
    pub reasons: BTreeSet<cigar_protocol::DispositionReason>,
    pub provenance_digest: ContentDigest,
}

/// Converts final records to protocol manifest entries.
pub(crate) fn manifest_entries(
    records: &BTreeMap<VersionId, DispositionRecord>,
) -> Vec<ManifestEntry> {
    records
        .iter()
        .map(|(version, record)| ManifestEntry {
            version_id: version.clone(),
            disposition: record.disposition.clone(),
            reason_codes: record.reasons.iter().copied().collect(),
            provenance_digest: record.provenance_digest.clone(),
        })
        .collect()
}
