//! Deadline-bound execution of independently capped retrieval stages.

use crate::{
    CandidateBatch, QueryPlan, RetrievalContext, RetrievalError, RetrievalErrorCode,
    RetrievalProfile, RetrievalStage, Retriever,
};
use cigar_protocol::ContentDigest;
use std::collections::BTreeSet;
use std::fmt;
use std::time::Instant;

/// One completed stage with its query identity and disclosure.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutedStage {
    /// Requirement that introduced the stage.
    pub requirement_index: usize,
    /// Whether absence from this stage contributes to a compile-blocking requirement failure.
    pub blocking: bool,
    /// Channel that ran.
    pub stage: RetrievalStage,
    /// Query fingerprint recorded by the planner.
    pub query_fingerprint: ContentDigest,
    /// Bounded metadata-only candidates and exact index disclosure.
    pub batch: CandidateBatch,
}

impl fmt::Debug for ExecutedStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutedStage")
            .field("requirement_index", &self.requirement_index)
            .field("blocking", &self.blocking)
            .field("stage", &self.stage)
            .field("query_fingerprint", &self.query_fingerprint)
            .field("candidate_count", &self.batch.candidates.len())
            .field("disclosure", &self.batch.disclosure)
            .finish()
    }
}

/// Complete deterministic stage transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedRetrievalResult {
    /// Plan identity executed without mutation.
    pub plan_fingerprint: ContentDigest,
    /// Results in exact planned order.
    pub stages: Vec<ExecutedStage>,
}

/// Stateless staged retrieval coordinator.
#[derive(Clone, Copy, Debug, Default)]
pub struct StagedRetrieval;

impl StagedRetrieval {
    /// Executes every independent stage under the lesser parent or per-stage deadline.
    pub fn execute(
        &self,
        plan: &QueryPlan,
        retriever: &dyn Retriever,
        context: &RetrievalContext,
    ) -> Result<StagedRetrievalResult, RetrievalError> {
        self.execute_with_profile(plan, retriever, context, RetrievalProfile::BalancedV1)
    }

    /// Executes a plan only when the retriever declares the exact bound score profile.
    pub fn execute_with_profile(
        &self,
        plan: &QueryPlan,
        retriever: &dyn Retriever,
        context: &RetrievalContext,
        retrieval_profile: RetrievalProfile,
    ) -> Result<StagedRetrievalResult, RetrievalError> {
        context.check()?;
        if retriever.retrieval_profile() != retrieval_profile {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        let mut stages = Vec::with_capacity(plan.stages.len());
        let mut blocking_requirements = BTreeSet::new();
        let mut satisfied_blocking_requirements = BTreeSet::new();
        for planned in &plan.stages {
            context.check()?;
            let stage_deadline = Instant::now()
                .checked_add(planned.timeout)
                .map_or(context.deadline, |deadline| deadline.min(context.deadline));
            let stage_context = RetrievalContext {
                cancellation: context.cancellation.clone(),
                deadline: stage_deadline,
            };
            let batch = retriever.retrieve(&planned.request, &stage_context)?;
            if batch.candidates.len() > planned.request.limit {
                return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
            }
            if planned.blocking {
                blocking_requirements.insert(planned.requirement_index);
                if !batch.candidates.is_empty() {
                    satisfied_blocking_requirements.insert(planned.requirement_index);
                }
            }
            stages.push(ExecutedStage {
                requirement_index: planned.requirement_index,
                blocking: planned.blocking,
                stage: planned.request.stage,
                query_fingerprint: planned.query_fingerprint.clone(),
                batch,
            });
        }
        if !blocking_requirements.is_subset(&satisfied_blocking_requirements) {
            return Err(RetrievalError::new(
                RetrievalErrorCode::RequiredCandidateMissing,
            ));
        }
        Ok(StagedRetrievalResult {
            plan_fingerprint: plan.plan_fingerprint.clone(),
            stages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StagedRetrieval;
    use crate::{
        AuthorizedPartition, CandidateBatch, CandidateFeatures, CandidateRef, MatchEvidence,
        QueryPlanner, RetrievalConsistency, RetrievalContext, RetrievalDisclosure, RetrievalError,
        RetrievalErrorCode, RetrievalProfile, RetrievalRequest, RetrievalStage, Retriever,
    };
    use cigar_protocol::{
        Classification, ContentDigest, ContextRequirement, InstructionAuthority, RecordId,
        SourceUri, UtcTimestamp, VersionId,
    };
    use cigar_store::{CancellationToken, StoreRevision};
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::time::{Duration, Instant};

    struct EmptyRetriever;

    impl Retriever for EmptyRetriever {
        fn retrieve(
            &self,
            request: &RetrievalRequest,
            context: &RetrievalContext,
        ) -> Result<CandidateBatch, RetrievalError> {
            context.check()?;
            Ok(CandidateBatch {
                candidates: Vec::new(),
                disclosure: RetrievalDisclosure {
                    generation_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7803").map_err(
                        |_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration),
                    )?,
                    index_fingerprint: digest('b')?,
                    built_through_revision: request.required_revision,
                    actual_revision_lag: 0,
                    fallback_used: false,
                    last_verified_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z").map_err(
                        |_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration),
                    )?,
                },
            })
        }
    }

    struct LexicalOnlyRetriever;

    impl Retriever for LexicalOnlyRetriever {
        fn retrieve(
            &self,
            request: &RetrievalRequest,
            context: &RetrievalContext,
        ) -> Result<CandidateBatch, RetrievalError> {
            let mut batch = EmptyRetriever.retrieve(request, context)?;
            if request.stage == RetrievalStage::Lexical {
                let version_id = VersionId::new(digest('c')?.as_str())
                    .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                batch.candidates.push(CandidateRef {
                    version_id,
                    lineage_id: cigar_protocol::LineageId::new(
                        "01890f47-8e7d-7b42-a1d2-3c4d5e6f7805",
                    )
                    .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
                    content_digest: digest('e')?,
                    atom_kind: cigar_protocol::AtomKind::Documentation,
                    canonical_uri: SourceUri::new("file:///authorized/document.md").map_err(
                        |_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration),
                    )?,
                    relative_path: None,
                    instruction_authority: InstructionAuthority::Data,
                    classification: Classification::Internal,
                    features: CandidateFeatures::default(),
                    total_score: 0,
                    evidence: BTreeSet::from([MatchEvidence::Lexical]),
                });
            }
            Ok(batch)
        }
    }

    fn digest(value: char) -> Result<ContentDigest, RetrievalError> {
        ContentDigest::new(format!("1220{}", value.to_string().repeat(64)))
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
    }

    fn partition() -> Result<AuthorizedPartition, Box<dyn Error>> {
        crate::test_support::authorized_partition(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?,
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7804")?,
            [RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7802")?]
                .into_iter()
                .collect(),
            "coding",
            "local",
            Classification::Internal,
            InstructionAuthority::Project,
            false,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:02Z")?,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:02Z")?,
        )
    }

    fn requirement(blocking: bool) -> Result<ContextRequirement, Box<dyn Error>> {
        Ok(serde_json::from_value(serde_json::json!({
            "semantic_type": "documentation",
            "selector": {"type":"query", "value":"cigar"},
            "minimum_authority": 1,
            "minimum_coverage": 0,
            "blocking": blocking
        }))?)
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    #[test]
    fn nonblocking_stages_preserve_plan_order_and_blocking_absence_fails()
    -> Result<(), Box<dyn Error>> {
        let nonblocking = QueryPlanner::default().plan(
            &[requirement(false)?],
            &partition()?,
            StoreRevision(4),
            RetrievalConsistency::Strong,
            false,
        )?;
        let result = StagedRetrieval.execute(&nonblocking, &EmptyRetriever, &context())?;
        assert_eq!(result.plan_fingerprint, nonblocking.plan_fingerprint);
        assert_eq!(result.stages.len(), 2);
        assert_eq!(
            StagedRetrieval
                .execute_with_profile(
                    &nonblocking,
                    &EmptyRetriever,
                    &context(),
                    RetrievalProfile::BalancedV2Candidate,
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::CorruptGeneration)
        );
        assert_eq!(
            result
                .stages
                .iter()
                .map(|stage| stage.stage)
                .collect::<Vec<_>>(),
            vec![
                crate::RetrievalStage::Metadata,
                crate::RetrievalStage::Lexical
            ]
        );

        let blocking = QueryPlanner::default().plan(
            &[requirement(true)?],
            &partition()?,
            StoreRevision(4),
            RetrievalConsistency::Strong,
            false,
        )?;
        assert_eq!(
            StagedRetrieval
                .execute(&blocking, &EmptyRetriever, &context())
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::RequiredCandidateMissing)
        );

        let lexical = StagedRetrieval.execute(&blocking, &LexicalOnlyRetriever, &context())?;
        let metadata_stage = lexical.stages.first().ok_or("missing metadata stage")?;
        let lexical_stage = lexical.stages.get(1).ok_or("missing lexical stage")?;
        assert!(metadata_stage.batch.candidates.is_empty());
        assert_eq!(lexical_stage.batch.candidates.len(), 1);
        Ok(())
    }
}
