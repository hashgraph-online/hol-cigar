//! A consumable context precondition for an independently authorized, exact effect intent.
//! This does not dispatch, approve, persist or retry an effect. Honey remains that authority.

use super::{BrokerError, ContextBroker, digest, measure, random_id, valid_label};
use crate::{AnswerDecision, AnswerPolicy, ClaimReview, ContextViewAssessment, TokenCounter};
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "cigar.context-execution-binding.v1";

/// Current trusted review input. Construct on the host, never from an agent draft.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReview {
    /// Host-owned reviewer/authorization policy revision; change it when review authority changes.
    pub authority_revision: String,
    /// Current independently supplied verdicts for the exact complete submission.
    pub reviews: Vec<ClaimReview>,
    /// Current host-owned release policy.
    pub policy: AnswerPolicy,
}

/// A retained context precondition for one exact external effect. All fields must match on take.
/// Serializable bytes are not a signature or effect permission; only the live host can consume it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    /// Closed schema identity.
    pub schema: String,
    /// Fresh random binding identity, replaced only by a new submission/ticket.
    pub id: String,
    /// Broker authority epoch; never restored.
    pub epoch: String,
    /// Live context ticket, available only on the private host port.
    pub ticket: String,
    /// Exact submitted claim-set identity.
    pub submission_id: String,
    /// Exact view and request identity.
    pub context_id: String,
    /// Exact selected evidence snapshot identity.
    pub snapshot_id: String,
    /// Commitment to current readable source versions and the broker epoch.
    pub source_authority_digest: String,
    /// Commitment to trusted verdicts, review authority revision and answer policy.
    pub review_digest: String,
    /// Opaque identity assigned by the execution authority, not by this broker.
    pub effect_id: String,
    /// Exact CIGAR semantic effect-intent multihash, including its existing preconditions.
    pub intent_digest: String,
}

impl std::fmt::Debug for ExecutionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionBinding").finish_non_exhaustive()
    }
}

/// Result of consuming one freshly revalidated context binding. This is an observation at take
/// time, not a lock spanning an external send, an approval, or a durable dispatch receipt.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionHandoff {
    /// Exact consumed identity; an execution adapter must preserve its effect ID and intent.
    pub binding: ExecutionBinding,
    /// Fresh complete claim assessment. Only Release can produce a handoff.
    pub checked: ContextViewAssessment,
}

#[derive(Serialize)]
pub(super) struct PendingExecution {
    binding: ExecutionBinding,
    taken: bool,
}

impl ContextBroker {
    /// Bind one reviewed submission to an already prepared external effect. One binding per
    /// submission; a second bind conflicts. It grants no approval/dispatch authority.
    pub fn host_bind_execution(
        &mut self,
        ticket_id: &str,
        submission_id: &str,
        effect_id: &str,
        intent_digest: &str,
        review: &ExecutionReview,
        tokenizer: &impl TokenCounter,
    ) -> Result<ExecutionBinding, BrokerError> {
        if !valid_label(effect_id)
            || intent_digest.len() != 68
            || !intent_digest.starts_with("1220")
            || !intent_digest
                .bytes()
                .skip(4)
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BrokerError::InvalidInput);
        }
        let review_digest = review_identity(review)?;
        let checked = self.host_check_answer(
            ticket_id,
            submission_id,
            &review.reviews,
            &review.policy,
            tokenizer,
        )?;
        if checked.assessment.decision != AnswerDecision::Release {
            return Err(BrokerError::AccessDenied);
        }
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or(BrokerError::AccessDenied)?;
        if ticket.execution.is_some() {
            return Err(BrokerError::Conflict);
        }
        let grant = self
            .grants
            .get(&ticket.owner)
            .ok_or(BrokerError::AccessDenied)?;
        let binding = ExecutionBinding {
            schema: SCHEMA.into(),
            id: random_id()?,
            epoch: self.epoch.clone(),
            ticket: ticket_id.into(),
            submission_id: submission_id.into(),
            context_id: checked.context_id,
            snapshot_id: checked.assessment.snapshot_id,
            source_authority_digest: digest(
                "cigar.broker-source-authority.v1",
                &(&self.epoch, &ticket.versions),
            )?,
            review_digest,
            effect_id: effect_id.into(),
            intent_digest: intent_digest.into(),
        };
        let pending = PendingExecution {
            binding: binding.clone(),
            taken: false,
        };
        let bytes = measure(
            &(
                &ticket.owner,
                &ticket.context,
                &ticket.versions,
                &ticket.submission,
                &pending,
            ),
            grant.spec.limits.max_retained_bytes,
        )?;
        self.check_retention(&ticket.owner, ticket.bytes, bytes)?;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or(BrokerError::AccessDenied)?;
        ticket.execution = Some(pending);
        ticket.bytes = bytes;
        Ok(binding)
    }

    /// Consume once immediately before handing the exact intent to its execution authority.
    /// Supply current host review authority/policy, not a cached agent-provided approval.
    /// Stale evidence, changed submission, revoked/expired grants and changed review policy fail.
    /// A lost reply is uncertain: do not repeat dispatch; reconcile with the effect authority.
    pub fn host_take_execution_handoff(
        &mut self,
        binding: &ExecutionBinding,
        review: &ExecutionReview,
        tokenizer: &impl TokenCounter,
    ) -> Result<ExecutionHandoff, BrokerError> {
        let ticket = self
            .tickets
            .get(&binding.ticket)
            .ok_or(BrokerError::AccessDenied)?;
        let pending = ticket.execution.as_ref().ok_or(BrokerError::Stale)?;
        if pending.binding != *binding || binding.epoch != self.epoch {
            return Err(BrokerError::Stale);
        }
        if pending.taken {
            return Err(BrokerError::Conflict);
        }
        if binding.review_digest != review_identity(review)? {
            return Err(BrokerError::Stale);
        }
        let checked = self.host_check_answer(
            &binding.ticket,
            &binding.submission_id,
            &review.reviews,
            &review.policy,
            tokenizer,
        )?;
        if checked.assessment.decision != AnswerDecision::Release {
            return Err(BrokerError::AccessDenied);
        }
        let pending = self
            .tickets
            .get_mut(&binding.ticket)
            .and_then(|ticket| ticket.execution.as_mut())
            .ok_or(BrokerError::Stale)?;
        // All fallible checks complete before consumption. Serialization/transport failure after
        // this point cannot make a second take safe, and restart never restores this permission.
        pending.taken = true;
        Ok(ExecutionHandoff {
            binding: binding.clone(),
            checked,
        })
    }
}

fn review_identity(review: &ExecutionReview) -> Result<String, BrokerError> {
    if !valid_label(&review.authority_revision) || review.reviews.len() > 128 {
        return Err(BrokerError::InvalidInput);
    }
    measure(review, 1024 * 1024)?;
    let mut reviews = review.reviews.clone();
    reviews.sort_by(|a, b| a.claim_key.cmp(&b.claim_key));
    // check_answer additionally rejects duplicate/unrelated keys and invalid policies.
    Ok(digest(
        "cigar.execution-review.v1",
        &(&review.authority_revision, &reviews, &review.policy),
    )?)
}

#[cfg(test)]
mod tests;
