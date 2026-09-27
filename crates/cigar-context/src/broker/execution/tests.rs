#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::broker::{AgentGrantSpec, AgentLimits, BrokerLimits, SourceOrigin, SourceProvenance};
use crate::{
    AnswerClaim, AnswerDraft, ClaimVerdict, ContextRequest, ContextViewSpec, GraphLimits,
    Utf8ByteCounter,
};
use std::collections::BTreeSet;
use std::time::Instant;

const EFFECT: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f789c";
fn intent() -> String {
    format!("1220{}", "a".repeat(64))
}

fn ingest(broker: &mut ContextBroker, source: &str, text: &str) {
    broker
        .host_replace_source(
            source,
            &broker.host_source_revision(source).unwrap(),
            vec![crate::Document::new(source, source, text)],
            SourceProvenance {
                authority: "host".into(),
                upstream_revision: text.into(),
                observed_at_ms: 1,
                valid_until_ms: None,
                origin: SourceOrigin::Host,
                derived_from: vec![],
            },
        )
        .unwrap();
}

fn fixture() -> (ContextBroker, String, String, ExecutionReview) {
    let mut broker =
        ContextBroker::new("handoff", GraphLimits::default(), BrokerLimits::default()).unwrap();
    ingest(&mut broker, "docs", "Retry at most three times.");
    let credential = broker
        .host_grant(AgentGrantSpec {
            view: ContextViewSpec {
                id: "agent".into(),
                allowed_sources: BTreeSet::from(["docs".into()]),
                writable_sources: BTreeSet::new(),
                policy_revision: "policy-one".into(),
            },
            limits: AgentLimits::default(),
            lease_ms: 60_000,
        })
        .unwrap();
    let context = broker
        .compile(
            &credential,
            &ContextRequest {
                query: "retry".into(),
                ..ContextRequest::default()
            },
            &Utf8ByteCounter,
        )
        .unwrap();
    let draft = AnswerDraft {
        snapshot_id: context.context.snapshot().id().into(),
        abstain: false,
        claims: vec![AnswerClaim {
            text: "Retry at most three times.".into(),
            citations: BTreeSet::from(["docs".into()]),
            confidence_bps: Some(9900),
        }],
    };
    let reviews = draft
        .review_keys()
        .unwrap()
        .into_iter()
        .map(|claim_key| ClaimReview {
            claim_key,
            verdict: ClaimVerdict::Supported,
            reviewed_counterevidence: BTreeSet::new(),
        })
        .collect();
    let submission = broker
        .submit_answer(&credential, &context.ticket, draft, &Utf8ByteCounter)
        .unwrap();
    (
        broker,
        context.ticket,
        submission,
        ExecutionReview {
            authority_revision: "trusted-reviewer-one".into(),
            reviews,
            policy: AnswerPolicy::default(),
        },
    )
}

fn bind(
    broker: &mut ContextBroker,
    ticket: &str,
    submission: &str,
    review: &ExecutionReview,
) -> ExecutionBinding {
    broker
        .host_bind_execution(
            ticket,
            submission,
            EFFECT,
            &intent(),
            review,
            &Utf8ByteCounter,
        )
        .unwrap()
}

#[test]
fn exact_handoff_is_consumed_once_and_unrelated_changes_preserve_it() {
    let (mut broker, ticket, submission, review) = fixture();
    let binding = bind(&mut broker, &ticket, &submission, &review);
    assert!(!format!("{binding:?}").contains(EFFECT));
    assert!(matches!(
        broker.host_bind_execution(
            &ticket,
            &submission,
            EFFECT,
            &intent(),
            &review,
            &Utf8ByteCounter
        ),
        Err(BrokerError::Conflict)
    ));
    ingest(&mut broker, "unrelated", "Private unrelated update.");
    let result = broker
        .host_take_execution_handoff(&binding, &review, &Utf8ByteCounter)
        .unwrap();
    assert_eq!(result.binding, binding);
    assert_eq!(result.checked.assessment.decision, AnswerDecision::Release);
    assert!(matches!(
        broker.host_take_execution_handoff(&binding, &review, &Utf8ByteCounter),
        Err(BrokerError::Conflict)
    ));
}

#[test]
fn substituted_intent_effect_context_or_binding_cannot_be_consumed() {
    let (mut broker, ticket, submission, review) = fixture();
    let binding = bind(&mut broker, &ticket, &submission, &review);
    for field in [
        "schema",
        "id",
        "epoch",
        "ticket",
        "submission_id",
        "context_id",
        "snapshot_id",
        "source_authority_digest",
        "review_digest",
        "effect_id",
        "intent_digest",
    ] {
        let mut changed = serde_json::to_value(&binding).unwrap();
        changed[field] = serde_json::Value::String("substitution".into());
        let changed: ExecutionBinding = serde_json::from_value(changed).unwrap();
        assert!(
            broker
                .host_take_execution_handoff(&changed, &review, &Utf8ByteCounter)
                .is_err(),
            "{field}"
        );
    }
    // Failed checks must not consume the legitimate handoff.
    assert!(
        broker
            .host_take_execution_handoff(&binding, &review, &Utf8ByteCounter)
            .is_ok()
    );
}

#[test]
fn source_provenance_policy_review_or_submission_changes_invalidate_pending_handoff() {
    for change in 0..8 {
        let (mut broker, ticket, submission, mut review) = fixture();
        let binding = bind(&mut broker, &ticket, &submission, &review);
        match change {
            0 => ingest(&mut broker, "docs", "Retry at most once."),
            1 => {
                let mut provenance = broker.host_provenance("docs").unwrap().clone();
                provenance.upstream_revision = "metadata-only".into();
                broker
                    .host_replace_source(
                        "docs",
                        &broker.host_source_revision("docs").unwrap(),
                        vec![crate::Document::new(
                            "docs",
                            "docs",
                            "Retry at most three times.",
                        )],
                        provenance,
                    )
                    .unwrap();
            }
            2 => {
                broker.host_revoke("agent");
            }
            3 => {
                review.authority_revision = "reviewer-revoked".into();
            }
            4 => {
                review.policy.min_sources = 2;
            }
            5 => {
                review.reviews[0].verdict = ClaimVerdict::Unknown;
            }
            6 => {
                broker.tickets.get_mut(&ticket).unwrap().expires = Instant::now();
            }
            7 => {
                broker
                    .tickets
                    .get_mut(&ticket)
                    .unwrap()
                    .submission
                    .as_mut()
                    .unwrap()
                    .submission_id = "new-submission".into();
            }
            _ => unreachable!(),
        }
        assert!(
            broker
                .host_take_execution_handoff(&binding, &review, &Utf8ByteCounter)
                .is_err(),
            "change {change}"
        );
    }
}

#[test]
fn unsupported_unreviewed_ambiguous_and_oversized_review_inputs_fail_before_binding() {
    let (mut broker, ticket, submission, review) = fixture();
    for verdict in [
        ClaimVerdict::Unknown,
        ClaimVerdict::Unsupported,
        ClaimVerdict::Contradicted,
    ] {
        let mut changed = review.clone();
        changed.reviews[0].verdict = verdict;
        assert!(matches!(
            broker.host_bind_execution(
                &ticket,
                &submission,
                EFFECT,
                &intent(),
                &changed,
                &Utf8ByteCounter
            ),
            Err(BrokerError::AccessDenied)
        ));
    }
    let mut changed = review.clone();
    changed.reviews.clear();
    assert!(
        broker
            .host_bind_execution(
                &ticket,
                &submission,
                EFFECT,
                &intent(),
                &changed,
                &Utf8ByteCounter
            )
            .is_err()
    );
    changed = review.clone();
    changed.reviews.push(changed.reviews[0].clone());
    assert!(
        broker
            .host_bind_execution(
                &ticket,
                &submission,
                EFFECT,
                &intent(),
                &changed,
                &Utf8ByteCounter
            )
            .is_err()
    );
    changed = review.clone();
    changed.reviews[0]
        .reviewed_counterevidence
        .insert("x".repeat(1024 * 1024));
    assert!(matches!(
        broker.host_bind_execution(
            &ticket,
            &submission,
            EFFECT,
            &intent(),
            &changed,
            &Utf8ByteCounter
        ),
        Err(BrokerError::Quota)
    ));
    for bad in ["".into(), "a".repeat(64), format!("1220{}", "G".repeat(64))] {
        assert!(
            broker
                .host_bind_execution(
                    &ticket,
                    &submission,
                    EFFECT,
                    &bad,
                    &review,
                    &Utf8ByteCounter
                )
                .is_err()
        );
    }
    assert!(broker.tickets[&ticket].execution.is_none());
    let _ = bind(&mut broker, &ticket, &submission, &review);
}

#[test]
fn execution_retention_is_bounded_and_checkpoint_restores_no_handoff_authority() {
    let (mut broker, ticket, submission, review) = fixture();
    let owner = broker.tickets[&ticket].owner.clone();
    let limit = broker.grants[&owner].spec.limits.max_retained_bytes;
    broker
        .grants
        .get_mut(&owner)
        .unwrap()
        .spec
        .limits
        .max_retained_bytes = broker.tickets[&ticket].bytes;
    assert!(matches!(
        broker.host_bind_execution(
            &ticket,
            &submission,
            EFFECT,
            &intent(),
            &review,
            &Utf8ByteCounter
        ),
        Err(BrokerError::Quota)
    ));
    assert!(broker.tickets[&ticket].execution.is_none());
    broker
        .grants
        .get_mut(&owner)
        .unwrap()
        .spec
        .limits
        .max_retained_bytes = limit;
    let binding = bind(&mut broker, &ticket, &submission, &review);
    let checkpoint = broker.host_checkpoint(1024 * 1024).unwrap();
    let bytes = String::from_utf8(checkpoint.encode(1024 * 1024).unwrap()).unwrap();
    assert!(!bytes.contains(&binding.id) && !bytes.contains(EFFECT));
    let mut restored = ContextBroker::from_checkpoint(
        "handoff",
        GraphLimits::default(),
        BrokerLimits::default(),
        &checkpoint,
    )
    .unwrap();
    assert!(
        restored
            .host_take_execution_handoff(&binding, &review, &Utf8ByteCounter)
            .is_err()
    );
}

#[test]
fn execution_commands_are_host_only_and_closed() {
    for command in [
        serde_json::json!({"op":"bind_execution","ticket":"t","submission_id":"s","effect_id":EFFECT,"intent_digest":intent(),"review":{"authority_revision":"one","reviews":[],"policy":{}}}),
        serde_json::json!({"op":"take_execution_handoff","binding":{},"review":{"authority_revision":"one","reviews":[],"policy":{}}}),
    ] {
        assert!(serde_json::from_value::<crate::broker::protocol::AgentCommand>(command).is_err());
    }
    let (mut broker, ticket, submission, review) = fixture();
    let binding = bind(&mut broker, &ticket, &submission, &review);
    let command =
        serde_json::json!({"op":"take_execution_handoff","binding":binding,"review":review});
    assert!(
        serde_json::from_value::<crate::broker::protocol::HostCommand>(command.clone()).is_ok()
    );
    let mut changed = command;
    changed["approved"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<crate::broker::protocol::HostCommand>(changed).is_err());
}
