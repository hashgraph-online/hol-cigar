//! Claim review is a host trust boundary, not model self-certification.
use crate::{ContextError, ContextGraph, ContextRequest, EdgeKind, TokenCounter, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One factual claim proposed by a model. All displayed factual prose must be represented.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerClaim {
    /// Complete atomic claim, at most 8 KiB. Citation presence does not establish entailment.
    pub text: String,
    /// Selected node IDs, not arbitrary URLs or short prompt handles. Resolve handles first.
    pub citations: BTreeSet<String>,
    /// Elicited probability of correctness in basis points (0..=10000), or unavailable.
    /// This is telemetry only and never makes a claim eligible for release.
    pub confidence_bps: Option<u16>,
}

impl std::fmt::Debug for AnswerClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnswerClaim")
            .field("bytes", &self.text.len())
            .field("citations", &self.citations.len())
            .finish_non_exhaustive()
    }
}

impl AnswerClaim {
    /// Bind a review to this exact claim, citations, confidence and context snapshot.
    /// A digest binds bytes; it does not authenticate the reviewer.
    pub fn review_key(&self, snapshot_id: &str) -> Result<String, ContextError> {
        self.validate()?;
        if !valid_digest(snapshot_id) {
            return Err(ContextError::InvalidInput);
        }
        digest("cigar.claim-review.v1", &(snapshot_id, self))
    }

    fn validate(&self) -> Result<(), ContextError> {
        if self.text.trim().is_empty()
            || self.text.len() > 8192
            || self.citations.len() > 64
            || self.citations.iter().any(|id| !crate::graph::valid_id(id))
            || self.confidence_bps.is_some_and(|value| value > 10000)
        {
            return Err(ContextError::InvalidInput);
        }
        Ok(())
    }
}

/// A bounded proposed answer. Unchecked free-form prose is deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerDraft {
    /// Exact snapshot supplied to the generator.
    pub snapshot_id: String,
    /// At most 128 atomic claims, with no duplicate review keys.
    pub claims: Vec<AnswerClaim>,
    /// Explicit abstention must contain no claims.
    #[serde(default)]
    pub abstain: bool,
}

impl AnswerDraft {
    /// Return keys for a trusted reviewer to use; this performs no factual assessment.
    pub fn review_keys(&self) -> Result<Vec<String>, ContextError> {
        if !valid_digest(&self.snapshot_id)
            || self.claims.len() > 128
            || (self.abstain && !self.claims.is_empty())
        {
            return Err(ContextError::InvalidInput);
        }
        let keys = self
            .claims
            .iter()
            .map(|claim| claim.review_key(&self.snapshot_id))
            .collect::<Result<Vec<_>, _>>()?;
        if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
            return Err(ContextError::InvalidInput);
        }
        Ok(keys)
    }
}

/// Factual judgment supplied by the owning application through a trusted review path.
/// Never deserialize these verdicts from the same untrusted output as the draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    /// Every assertion is supported by the cited selected evidence, with conflicts resolved.
    Supported,
    /// The evidence does not establish the claim (including irrelevant or incomplete citations).
    Unsupported,
    /// The evidence establishes a conflicting claim.
    Contradicted,
    /// The reviewer could not decide. Unknown is never treated as supported.
    Unknown,
}

/// An independently supplied review. The caller authenticates and evaluates its reviewer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReview {
    /// Key produced by `AnswerClaim::review_key`; stale or unrelated keys are errors.
    pub claim_key: String,
    /// Semantic judgment of the entire cited claim, not just the existence of its citations.
    pub verdict: ClaimVerdict,
    /// Explicit counterclaim nodes considered by the reviewer. Acknowledgment is not resolution;
    /// a supported verdict additionally asserts the reviewer resolved the conflict.
    #[serde(default)]
    pub reviewed_counterevidence: BTreeSet<String>,
}

/// Host-owned answer release policy. Model confidence cannot relax it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnswerPolicy {
    /// Minimum distinct provenance groups per claim, from one to four. Shared locators or
    /// identical complete document text merge groups transitively. Independence beyond this
    /// conservative grouping is the trusted ingestion/reviewer's responsibility.
    pub min_sources: usize,
    /// Threshold for reporting a confident blocked claim, from zero to 10000 inclusive.
    pub high_confidence_bps: u16,
}

impl Default for AnswerPolicy {
    fn default() -> Self {
        Self {
            min_sources: 1,
            high_confidence_bps: 8000,
        }
    }
}

/// Why a claim cannot be released. Multiple failures can apply to one claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimIssue {
    /// No citation was proposed.
    Uncited,
    /// A cited node is absent from the current selected context.
    InvalidCitation,
    /// Too few distinct provenance groups remain after collapsing copies and shared sources.
    InsufficientSources,
    /// No trusted review exists for this exact claim and snapshot.
    Unreviewed,
    /// Trusted review found insufficient support.
    Unsupported,
    /// Trusted review found conflicting evidence.
    Contradicted,
    /// Trusted review could not determine support.
    Unknown,
    /// Declared counterevidence in the cited nodes' hard closure was not reviewed.
    UnreviewedCounterevidence,
}

/// Content-free per-claim result in draft order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimAssessment {
    /// Exact key assessed.
    pub claim_key: String,
    /// Number of distinct provenance groups, not a semantic support score.
    pub independent_sources: usize,
    /// Empty only when the complete review contract is satisfied.
    pub issues: Vec<ClaimIssue>,
}

/// All-or-nothing disposition; a single failed claim blocks the whole draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerDecision {
    /// Every claim passed the trusted review contract.
    Release,
    /// The application must abstain, gather evidence or revise and obtain a new review.
    Abstain,
}

/// Assessment against the graph's current authorization and source state.
/// This is a transient result, not a signed certificate. Recheck after any state/policy change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerAssessment {
    /// Exact context assessed.
    pub snapshot_id: String,
    /// Exact draft assessed, including explicit abstention.
    pub draft_id: String,
    /// All-or-nothing release decision.
    pub decision: AnswerDecision,
    /// Per-claim failures, without copying claim/source text into operational telemetry.
    pub claims: Vec<ClaimAssessment>,
    /// Failed claims whose supplied confidence reaches the policy threshold.
    /// This is a gate-failure count, not an independently measured hallucination count.
    pub confident_failures: usize,
    /// Claims without elicited confidence. Missing confidence is never imputed.
    pub missing_confidence: usize,
}

impl ContextGraph {
    /// Check a draft using independently supplied trusted reviews and current authorization.
    ///
    /// Recompiles `request` and requires the exact snapshot given to the model. Every citation
    /// must occur in that selected evidence; every claim needs a supported trusted review.
    /// Known hard dependencies/counterclaims are traversed without dropping conflicts. Raising
    /// or lowering confidence never bypasses a failed review. No semantic judge runs here.
    ///
    /// The application must keep `reviews`, `policy` and authorization outside model control,
    /// and display only the assessed claims on `Release`. The runtime cannot establish that a
    /// model decomposed every factual assertion or that a supplied judge is truthful/accurate.
    pub fn check_answer(
        &self,
        request: &ContextRequest,
        draft: &AnswerDraft,
        reviews: &[ClaimReview],
        policy: &AnswerPolicy,
        tokenizer: &impl TokenCounter,
    ) -> Result<AnswerAssessment, ContextError> {
        if !(1..=4).contains(&policy.min_sources)
            || policy.high_confidence_bps > 10000
            || reviews.len() > 128
        {
            return Err(ContextError::InvalidInput);
        }
        let keys = draft.review_keys()?;
        let mut review_map = BTreeMap::new();
        for review in reviews {
            if !keys.contains(&review.claim_key)
                || review.reviewed_counterevidence.len() > 4096
                || review
                    .reviewed_counterevidence
                    .iter()
                    .any(|id| !crate::graph::valid_id(id))
                || review_map.insert(&review.claim_key, review).is_some()
            {
                return Err(ContextError::InvalidInput);
            }
        }
        let snapshot = self.compile(request, tokenizer)?;
        if snapshot.id() != draft.snapshot_id {
            return Err(ContextError::BaseMismatch);
        }
        let selected = snapshot
            .blocks()
            .iter()
            .flat_map(|block| block.citations.iter().map(|citation| &citation.node_id))
            .collect::<BTreeSet<_>>();
        if reviews.iter().any(|review| {
            review
                .reviewed_counterevidence
                .iter()
                .any(|id| !selected.contains(id))
        }) {
            return Err(ContextError::InvalidInput);
        }
        let mut claims = Vec::new();
        let mut confident_failures = 0;
        let mut missing_confidence = 0;
        for (claim, key) in draft.claims.iter().zip(keys) {
            let mut issues = Vec::new();
            if claim.citations.is_empty() {
                issues.push(ClaimIssue::Uncited);
            }
            if claim.citations.iter().any(|id| !selected.contains(id)) {
                issues.push(ClaimIssue::InvalidCitation);
            }
            let cited = claim
                .citations
                .iter()
                .filter(|id| selected.contains(*id))
                .filter_map(|id| self.documents.get(id))
                .collect::<Vec<_>>();
            // Connected components prevent copies, chunks and transitive aliases from voting
            // repeatedly. At most 64 nodes; using exact complete-text digests costs no BPE work.
            let mut groups: Vec<BTreeSet<usize>> = Vec::new();
            for (index, node) in cited.iter().enumerate() {
                let mut group = BTreeSet::from([index]);
                groups.retain(|existing| {
                    if existing.iter().any(|i| {
                        cited.get(*i).is_some_and(|prior| {
                            prior.document.source == node.document.source
                                || prior.text_digest == node.text_digest
                        })
                    }) {
                        group.extend(existing);
                        false
                    } else {
                        true
                    }
                });
                groups.push(group);
            }
            let independent_sources = groups.len();
            if independent_sources < policy.min_sources {
                issues.push(ClaimIssue::InsufficientSources);
            }
            let counterevidence = self.answer_counterevidence(&claim.citations, &selected);
            match review_map.get(&key) {
                None => issues.push(ClaimIssue::Unreviewed),
                Some(review) => {
                    match review.verdict {
                        ClaimVerdict::Supported => {}
                        ClaimVerdict::Unsupported => issues.push(ClaimIssue::Unsupported),
                        ClaimVerdict::Contradicted => issues.push(ClaimIssue::Contradicted),
                        ClaimVerdict::Unknown => issues.push(ClaimIssue::Unknown),
                    }
                    if !counterevidence.is_subset(&review.reviewed_counterevidence) {
                        issues.push(ClaimIssue::UnreviewedCounterevidence);
                    }
                }
            }
            if !issues.is_empty()
                && claim
                    .confidence_bps
                    .is_some_and(|value| value >= policy.high_confidence_bps)
            {
                confident_failures += 1;
            }
            missing_confidence += usize::from(claim.confidence_bps.is_none());
            claims.push(ClaimAssessment {
                claim_key: key,
                independent_sources,
                issues,
            });
        }
        let decision = if !draft.abstain
            && !claims.is_empty()
            && claims.iter().all(|claim| claim.issues.is_empty())
        {
            AnswerDecision::Release
        } else {
            AnswerDecision::Abstain
        };
        Ok(AnswerAssessment {
            snapshot_id: snapshot.id().to_owned(),
            draft_id: digest("cigar.answer-draft.v1", draft)?,
            decision,
            claims,
            confident_failures,
            missing_confidence,
        })
    }

    fn answer_counterevidence(
        &self,
        citations: &BTreeSet<String>,
        selected: &BTreeSet<&String>,
    ) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut pending = citations
            .iter()
            .filter(|id| selected.contains(*id))
            .collect::<Vec<_>>();
        let mut counterevidence = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(edges) = self.edges.get(id) {
                for (kind, target) in edges {
                    if selected.contains(target)
                        && matches!(kind, EdgeKind::Requires | EdgeKind::Contradicts)
                    {
                        if *kind == EdgeKind::Contradicts && !citations.contains(target) {
                            counterevidence.insert(target.clone());
                        }
                        pending.push(target);
                    }
                }
            }
        }
        counterevidence
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
