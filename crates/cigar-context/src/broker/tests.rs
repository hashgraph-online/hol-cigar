#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::{
    AnswerClaim, AnswerDecision, ClaimIssue, ClaimVerdict, ContextViewSpec, Utf8ByteCounter,
};

fn broker() -> ContextBroker {
    ContextBroker::new(
        "test-private-domain",
        GraphLimits::default(),
        BrokerLimits::default(),
    )
    .unwrap()
}

fn spec(agent: &str, sources: &[&str], writable: &[&str]) -> AgentGrantSpec {
    AgentGrantSpec {
        view: ContextViewSpec {
            id: agent.into(),
            allowed_sources: sources.iter().map(|s| (*s).into()).collect(),
            writable_sources: writable.iter().map(|s| (*s).into()).collect(),
            policy_revision: "policy-1".into(),
        },
        limits: AgentLimits::default(),
        lease_ms: 60_000,
    }
}

fn provenance(version: &str) -> SourceProvenance {
    SourceProvenance {
        authority: "trusted-fixture-host".into(),
        upstream_revision: version.into(),
        observed_at_ms: 1,
        valid_until_ms: None,
        origin: SourceOrigin::Host,
        derived_from: Vec::new(),
    }
}

fn ingest(broker: &mut ContextBroker, source: &str, id: &str, text: &str) -> SourceReceipt {
    let revision = broker.host_source_revision(source).unwrap();
    broker
        .host_replace_source(
            source,
            &revision,
            vec![Document::new(id, source, text)],
            provenance("v1"),
        )
        .unwrap()
}

fn request() -> ContextRequest {
    ContextRequest {
        query: "meaningful evidence".into(),
        ..ContextRequest::default()
    }
}

fn compile(broker: &mut ContextBroker, credential: &BrokerCredential) -> BrokerContext {
    broker
        .compile(credential, &request(), &Utf8ByteCounter)
        .unwrap()
}

#[test]
fn five_and_twelve_agents_share_one_graph_without_sharing_scopes_or_tickets() {
    for agents in [5, 12] {
        let mut broker = broker();
        ingest(
            &mut broker,
            "shared",
            "common",
            "meaningful evidence shared by all agents",
        );
        let mut clients = Vec::new();
        for agent in 0..agents {
            let source = format!("private-{agent}");
            ingest(
                &mut broker,
                &source,
                &format!("doc-{agent}"),
                &format!("meaningful evidence SECRET_{agent}_"),
            );
            clients.push(
                broker
                    .host_grant(spec(
                        &format!("agent-{agent}"),
                        &["shared", &source],
                        &[&source],
                    ))
                    .unwrap(),
            );
        }
        let contexts = clients
            .iter()
            .enumerate()
            .map(|(agent, client)| {
                let request = ContextRequest {
                    required: BTreeSet::from(["common".into(), format!("doc-{agent}")]),
                    ..request()
                };
                broker.compile(client, &request, &Utf8ByteCounter).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(broker.graph.len(), agents + 1);
        for (agent, context) in contexts.iter().enumerate() {
            assert!(context.rendered.contains("shared by all"));
            assert!(context.rendered.contains(&format!("SECRET_{agent}_")));
            assert_eq!(context.context.snapshot().stats().documents, 2);
            for other in 0..agents {
                if agent == other {
                    continue;
                }
                assert!(!context.rendered.contains(&format!("SECRET_{other}_")));
                assert_eq!(
                    broker.revalidate(&clients[other], &context.ticket, &Utf8ByteCounter),
                    Err(BrokerError::AccessDenied)
                );
                assert_eq!(
                    broker.source_revision(&clients[agent], &format!("private-{other}")),
                    Err(BrokerError::AccessDenied)
                );
            }
        }
        ingest(
            &mut broker,
            "private-0",
            "doc-0",
            "meaningful evidence updated only for agent zero",
        );
        assert_eq!(
            broker.revalidate(&clients[0], &contexts[0].ticket, &Utf8ByteCounter),
            Err(BrokerError::Stale)
        );
        for other in 1..agents {
            broker
                .revalidate(&clients[other], &contexts[other].ticket, &Utf8ByteCounter)
                .unwrap();
        }
    }
}

#[test]
fn tickets_cannot_resolve_uncited_or_denied_nodes_and_request_cannot_widen_scope() {
    let mut broker = broker();
    ingest(
        &mut broker,
        "public",
        "visible",
        "meaningful evidence public",
    );
    ingest(
        &mut broker,
        "private",
        "hidden",
        "meaningful evidence private",
    );
    let client = broker.host_grant(spec("reader", &["public"], &[])).unwrap();
    let context = compile(&mut broker, &client);
    assert_eq!(
        broker
            .citations(&client, &context.ticket, "visible", &Utf8ByteCounter)
            .unwrap()[0]
            .source,
        "public"
    );
    assert_eq!(
        broker.citations(&client, &context.ticket, "hidden", &Utf8ByteCounter),
        Err(BrokerError::AccessDenied)
    );
    let narrowed = ContextRequest {
        allowed: Some(BTreeSet::from(["hidden".into()])),
        ..request()
    };
    assert!(
        broker
            .compile(&client, &narrowed, &Utf8ByteCounter)
            .unwrap()
            .context
            .snapshot()
            .blocks()
            .is_empty()
    );
    let required = ContextRequest {
        required: BTreeSet::from(["hidden".into()]),
        ..request()
    };
    assert!(matches!(
        broker.compile(&client, &required, &Utf8ByteCounter),
        Err(BrokerError::Context(
            crate::ContextError::RequiredUnavailable
        ))
    ));
}

#[test]
fn concurrent_revision_proposals_require_host_admission_and_only_one_can_win() {
    let mut broker = broker();
    let a = broker
        .host_grant(spec("a", &["shared"], &["shared"]))
        .unwrap();
    let b = broker
        .host_grant(spec("b", &["shared"], &["shared"]))
        .unwrap();
    let initial = broker.source_revision(&a, "shared").unwrap();
    let pa = broker
        .propose_source(
            &a,
            "request-a",
            "shared",
            &initial,
            vec![Document::new(
                "one",
                "shared",
                "meaningful evidence first proposal",
            )],
        )
        .unwrap();
    let pb = broker
        .propose_source(
            &b,
            "request-b",
            "shared",
            &initial,
            vec![Document::new(
                "two",
                "shared",
                "meaningful evidence competing proposal",
            )],
        )
        .unwrap();
    assert!(
        compile(&mut broker, &a)
            .context
            .snapshot()
            .blocks()
            .is_empty()
    );
    assert_eq!(broker.graph.len(), 0);
    assert_eq!(
        broker.host_proposal(&pa.proposal_id).unwrap().2[0].id,
        "one"
    );
    assert_eq!(
        broker.proposal_status(&b, "request-a"),
        Err(BrokerError::AccessDenied)
    );
    assert!(matches!(
        broker.propose_source(&a, "request-a", "shared", &initial, Vec::new()),
        Err(BrokerError::Conflict)
    ));
    assert_eq!(
        broker.host_admit_proposal(&pa.proposal_id, provenance("v1")),
        Err(BrokerError::InvalidInput)
    );
    let reviewed = SourceProvenance {
        origin: SourceOrigin::ReviewedProposal,
        ..provenance("review-a")
    };
    let receipt = broker
        .host_admit_proposal(&pa.proposal_id, reviewed.clone())
        .unwrap();
    assert_eq!(receipt.revision.version, 1);
    assert_eq!(
        broker.host_admit_proposal(&pb.proposal_id, reviewed.clone()),
        Err(BrokerError::Conflict)
    );
    assert_eq!(
        broker.host_admit_proposal(&pa.proposal_id, reviewed),
        Err(BrokerError::Conflict)
    );
    assert_eq!(
        broker.proposal_status(&a, "request-a").unwrap().outcome,
        ProposalOutcome::Admitted { receipt }
    );
    assert!(compile(&mut broker, &a).rendered.contains("first proposal"));
    assert!(
        !compile(&mut broker, &b)
            .rendered
            .contains("competing proposal")
    );
    broker.host_reject_proposal(&pb.proposal_id).unwrap();
    assert_eq!(
        broker.proposal_status(&b, "request-b").unwrap().outcome,
        ProposalOutcome::Rejected
    );
}

#[test]
fn withdrawal_and_change_back_never_reset_source_versions_or_revive_tickets() {
    let mut broker = broker();
    let v1 = ingest(&mut broker, "docs", "one", "meaningful evidence original");
    let client = broker
        .host_grant(spec("agent", &["docs"], &["docs"]))
        .unwrap();
    let context = compile(&mut broker, &client);
    let v2 = broker
        .host_replace_source("docs", &v1.revision, Vec::new(), provenance("v1"))
        .unwrap();
    assert_eq!(v2.revision.version, 2);
    let v3 = ingest(&mut broker, "docs", "one", "meaningful evidence original");
    assert_eq!(v3.revision.version, 3);
    assert_eq!(
        broker.revalidate(&client, &context.ticket, &Utf8ByteCounter),
        Err(BrokerError::Stale)
    );
    assert_eq!(
        broker.host_replace_source("docs", &v1.revision, Vec::new(), provenance("v1")),
        Err(BrokerError::Conflict)
    );
    let unchanged = ingest(&mut broker, "docs", "one", "meaningful evidence original");
    assert_eq!(unchanged.revision, v3.revision);
    assert_eq!(unchanged.unchanged, 1);
}

#[test]
fn metadata_only_change_invalidates_context_without_changing_legacy_graph_bytes() {
    let mut broker = broker();
    let before = ingest(&mut broker, "docs", "one", "meaningful evidence original");
    let client = broker.host_grant(spec("agent", &["docs"], &[])).unwrap();
    let context = compile(&mut broker, &client);
    let graph_revision = broker.graph.revision();
    let claim = AnswerClaim {
        text: "The original evidence is current.".into(),
        citations: BTreeSet::from(["one".into()]),
        confidence_bps: Some(10_000),
    };
    let old_review = ClaimReview {
        claim_key: claim.review_key(context.context.snapshot().id()).unwrap(),
        verdict: ClaimVerdict::Supported,
        reviewed_counterevidence: BTreeSet::new(),
    };
    let next = broker
        .host_replace_source(
            "docs",
            &before.revision,
            vec![Document::new("one", "docs", "meaningful evidence original")],
            provenance("independent-new-observation"),
        )
        .unwrap();
    assert_eq!(next.revision.version, 2);
    assert_eq!(broker.graph.revision(), graph_revision);
    assert_eq!(
        broker.revalidate(&client, &context.ticket, &Utf8ByteCounter),
        Err(BrokerError::Stale)
    );
    let fresh = compile(&mut broker, &client);
    assert_ne!(
        fresh.context.snapshot().id(),
        context.context.snapshot().id()
    );
    broker
        .revalidate(&client, &fresh.ticket, &Utf8ByteCounter)
        .unwrap();
    let fresh_draft = AnswerDraft {
        snapshot_id: fresh.context.snapshot().id().to_owned(),
        claims: vec![claim],
        abstain: false,
    };
    let submission = broker
        .submit_answer(&client, &fresh.ticket, fresh_draft, &Utf8ByteCounter)
        .unwrap();
    assert!(
        broker
            .host_check_answer(
                &fresh.ticket,
                &submission,
                &[old_review],
                &AnswerPolicy::default(),
                &Utf8ByteCounter
            )
            .is_err()
    );
}

#[test]
fn identical_evidence_in_a_new_authority_epoch_cannot_reuse_review_keys() {
    let mut before = broker();
    let mut after = broker();
    ingest(&mut before, "docs", "one", "meaningful evidence");
    ingest(&mut after, "docs", "one", "meaningful evidence");
    let previous = before.host_grant(spec("agent", &["docs"], &[])).unwrap();
    let current = after.host_grant(spec("agent", &["docs"], &[])).unwrap();
    let old = compile(&mut before, &previous);
    let new = compile(&mut after, &current);
    assert_eq!(old.rendered, new.rendered);
    assert_ne!(old.context.snapshot().id(), new.context.snapshot().id());
    let claim = AnswerClaim {
        text: "The evidence is meaningful.".into(),
        citations: BTreeSet::from(["one".into()]),
        confidence_bps: None,
    };
    assert_ne!(
        claim.review_key(old.context.snapshot().id()).unwrap(),
        claim.review_key(new.context.snapshot().id()).unwrap()
    );
}

#[test]
fn changed_or_withdrawn_transitive_input_blocks_derived_evidence_even_outside_read_scope() {
    for withdraw in [false, true] {
        let mut broker = broker();
        let root = ingest(
            &mut broker,
            "root",
            "root-id",
            "meaningful evidence from original observation",
        );
        let middle_meta = SourceProvenance {
            derived_from: vec![SourceDependency {
                source: "root".into(),
                revision: root.revision,
            }],
            ..provenance("derived-middle")
        };
        let empty = broker.host_source_revision("middle").unwrap();
        let middle = broker
            .host_replace_source(
                "middle",
                &empty,
                vec![Document::new(
                    "middle-id",
                    "middle",
                    "meaningful evidence middle",
                )],
                middle_meta,
            )
            .unwrap();
        let leaf_meta = SourceProvenance {
            derived_from: vec![SourceDependency {
                source: "middle".into(),
                revision: middle.revision,
            }],
            ..provenance("derived-leaf")
        };
        let empty = broker.host_source_revision("leaf").unwrap();
        broker
            .host_replace_source(
                "leaf",
                &empty,
                vec![Document::new("leaf-id", "leaf", "meaningful evidence leaf")],
                leaf_meta,
            )
            .unwrap();
        let client = broker
            .host_grant(spec("leaf-reader", &["leaf"], &[]))
            .unwrap();
        let context = compile(&mut broker, &client);
        assert!(!context.rendered.contains("root"));
        let expected = broker.host_source_revision("root").unwrap();
        let documents = if withdraw {
            Vec::new()
        } else {
            vec![Document::new(
                "root-id",
                "root",
                "meaningful evidence new fact",
            )]
        };
        broker
            .host_replace_source("root", &expected, documents, provenance("v2"))
            .unwrap();
        assert_eq!(
            broker.revalidate(&client, &context.ticket, &Utf8ByteCounter),
            Err(BrokerError::Stale)
        );
        assert!(matches!(
            broker.compile(&client, &request(), &Utf8ByteCounter),
            Err(BrokerError::Stale)
        ));
        ingest(
            &mut broker,
            "root",
            "root-id",
            "meaningful evidence from original observation",
        );
        assert!(matches!(
            broker.compile(&client, &request(), &Utf8ByteCounter),
            Err(BrokerError::Stale)
        ));
    }
}

#[test]
fn derivation_cycles_and_duplicate_inputs_are_rejected_without_mutation() {
    let mut broker = broker();
    let root = ingest(&mut broker, "a", "a-id", "meaningful evidence a");
    let dep = SourceDependency {
        source: "a".into(),
        revision: root.revision.clone(),
    };
    let empty = broker.host_source_revision("b").unwrap();
    let duplicate = SourceProvenance {
        derived_from: vec![dep.clone(), dep.clone()],
        ..provenance("duplicate")
    };
    assert_eq!(
        broker.host_replace_source(
            "b",
            &empty,
            vec![Document::new("b-id", "b", "meaningful evidence b")],
            duplicate
        ),
        Err(BrokerError::InvalidInput)
    );
    assert_eq!(broker.graph.len(), 1);
    let b = broker
        .host_replace_source(
            "b",
            &empty,
            vec![Document::new("b-id", "b", "meaningful evidence b")],
            SourceProvenance {
                derived_from: vec![dep],
                ..provenance("b")
            },
        )
        .unwrap();
    let cycle = SourceProvenance {
        derived_from: vec![SourceDependency {
            source: "b".into(),
            revision: b.revision,
        }],
        ..provenance("cycle")
    };
    assert_eq!(
        broker.host_replace_source(
            "a",
            &root.revision,
            vec![Document::new("a-id", "a", "changed")],
            cycle
        ),
        Err(BrokerError::Stale)
    );
    assert_eq!(broker.host_source_revision("a").unwrap(), root.revision);
}

#[test]
fn failed_graph_validation_is_atomic_for_graph_provenance_and_source_authority() {
    let mut broker = broker();
    let v1 = ingest(&mut broker, "a", "a-id", "meaningful evidence a");
    ingest(&mut broker, "b", "b-id", "meaningful evidence b");
    let before = broker.graph.revision();
    let invalid = vec![
        Document::new("fresh", "a", "staged first"),
        Document::new("b-id", "a", "collision"),
    ];
    assert!(
        broker
            .host_replace_source("a", &v1.revision, invalid, provenance("changed"))
            .is_err()
    );
    assert_eq!(broker.host_source_revision("a").unwrap(), v1.revision);
    assert_eq!(broker.host_provenance("a").unwrap().upstream_revision, "v1");
    assert_eq!(broker.graph.revision(), before);
    assert_eq!(broker.graph.len(), 2);
}

#[test]
fn redefinition_revocation_epoch_and_expiry_reject_inherited_authority() {
    let mut broker = broker();
    ingest(&mut broker, "docs", "one", "meaningful evidence");
    let first = broker
        .host_grant(spec("agent", &["docs"], &["docs"]))
        .unwrap();
    let context = compile(&mut broker, &first);
    let expected = broker.source_revision(&first, "docs").unwrap();
    let proposal = broker
        .propose_source(&first, "old", "docs", &expected, Vec::new())
        .unwrap();
    let mut invalid = spec("agent", &["docs"], &["denied"]);
    assert!(broker.host_grant(invalid.clone()).is_err());
    broker
        .revalidate(&first, &context.ticket, &Utf8ByteCounter)
        .unwrap();
    invalid.view.writable_sources.clear();
    let second = broker.host_grant(invalid).unwrap();
    assert_ne!(first.secret, second.secret);
    assert_eq!(
        broker.revalidate(&first, &context.ticket, &Utf8ByteCounter),
        Err(BrokerError::AccessDenied)
    );
    assert_eq!(
        broker.revalidate(&second, &context.ticket, &Utf8ByteCounter),
        Err(BrokerError::AccessDenied)
    );
    assert!(matches!(
        broker.host_proposal(&proposal.proposal_id),
        Err(BrokerError::AccessDenied)
    ));
    assert!(broker.host_revoke("agent"));
    assert!(!broker.host_revoke("agent"));
    assert_eq!(
        broker.source_revision(&second, "docs"),
        Err(BrokerError::AccessDenied)
    );
    let live = broker.host_grant(spec("agent", &["docs"], &[])).unwrap();
    let wrong_epoch = BrokerCredential {
        epoch: "0".repeat(64),
        secret: live.secret.clone(),
    };
    assert_eq!(
        broker.source_revision(&wrong_epoch, "docs"),
        Err(BrokerError::AccessDenied)
    );
    let other = ContextBroker::new(
        "same-domain",
        GraphLimits::default(),
        BrokerLimits::default(),
    )
    .unwrap();
    assert_ne!(other.epoch(), broker.epoch());
    assert_eq!(
        other.source_revision(&live, "docs"),
        Err(BrokerError::AccessDenied)
    );
    broker
        .grants
        .get_mut(&secret_key(&live.secret))
        .unwrap()
        .expires = Instant::now();
    assert_eq!(
        broker.source_revision(&live, "docs"),
        Err(BrokerError::AccessDenied)
    );
}

#[test]
fn per_agent_saturation_does_not_exhaust_another_grant_and_expiry_reclaims_slots() {
    let mut broker = broker();
    ingest(&mut broker, "docs", "one", "meaningful evidence");
    let mut limited = spec("limited", &["docs"], &["docs"]);
    limited.limits.max_tickets = 1;
    limited.limits.max_proposals = 1;
    let a = broker.host_grant(limited).unwrap();
    let b = broker.host_grant(spec("other", &["docs"], &[])).unwrap();
    let first = compile(&mut broker, &a);
    assert!(matches!(
        broker.compile(&a, &request(), &Utf8ByteCounter),
        Err(BrokerError::Quota)
    ));
    let other = compile(&mut broker, &b);
    assert_eq!(
        broker.forget_ticket(&a, &other.ticket),
        Err(BrokerError::AccessDenied)
    );
    broker.tickets.get_mut(&first.ticket).unwrap().expires = Instant::now();
    assert_eq!(
        broker.revalidate(&a, &first.ticket, &Utf8ByteCounter),
        Err(BrokerError::AccessDenied)
    );
    compile(&mut broker, &a);
    let expected = broker.source_revision(&a, "docs").unwrap();
    let pending = broker
        .propose_source(&a, "first", "docs", &expected, Vec::new())
        .unwrap();
    assert!(matches!(
        broker.propose_source(&a, "second", "docs", &expected, Vec::new()),
        Err(BrokerError::Quota)
    ));
    broker
        .proposals
        .get_mut(&pending.proposal_id)
        .unwrap()
        .expires = Instant::now();
    assert!(matches!(
        broker.host_proposal(&pending.proposal_id),
        Err(BrokerError::AccessDenied)
    ));
    broker
        .propose_source(&a, "second", "docs", &expected, Vec::new())
        .unwrap();
    broker
        .revalidate(&b, &other.ticket, &Utf8ByteCounter)
        .unwrap();
}

#[test]
fn retention_bounds_count_escaped_bytes_and_source_tombstones() {
    let mut broker = ContextBroker::new(
        "bounded",
        GraphLimits::default(),
        BrokerLimits {
            max_sources: 1,
            ..BrokerLimits::default()
        },
    )
    .unwrap();
    let v1 = ingest(&mut broker, "a", "a-id", "meaningful evidence");
    broker
        .host_replace_source("a", &v1.revision, Vec::new(), provenance("withdrawal"))
        .unwrap();
    let zero = broker.host_source_revision("b").unwrap();
    assert_eq!(
        broker.host_replace_source("b", &zero, Vec::new(), provenance("first")),
        Err(BrokerError::Quota)
    );
    let mut limited = spec("agent", &["a"], &["a"]);
    limited.limits.max_proposal_bytes = RECORD_ALLOWANCE + 1024;
    let client = broker.host_grant(limited).unwrap();
    let current = broker.source_revision(&client, "a").unwrap();
    let huge_wire = Document::new("new", "a", format!("prefix {}", "\0".repeat(400)));
    assert!(matches!(
        broker.propose_source(&client, "huge", "a", &current, vec![huge_wire]),
        Err(BrokerError::Quota)
    ));
    assert!(broker.proposals.is_empty());
    assert_eq!(broker.host_source_revision("a").unwrap(), current);
    broker
        .propose_source(
            &client,
            "valid",
            "a",
            &current,
            vec![Document::new("new", "a", "small")],
        )
        .unwrap();
}

#[test]
fn source_expiration_blocks_new_and_retained_context_without_clock_sleep() {
    let mut broker = broker();
    let empty = broker.host_source_revision("live").unwrap();
    let now = unix_ms().unwrap();
    let metadata = SourceProvenance {
        observed_at_ms: now,
        valid_until_ms: Some(now + 60_000),
        ..provenance("ttl")
    };
    broker
        .host_replace_source(
            "live",
            &empty,
            vec![Document::new("one", "live", "meaningful evidence")],
            metadata,
        )
        .unwrap();
    let client = broker.host_grant(spec("reader", &["live"], &[])).unwrap();
    let context = compile(&mut broker, &client);
    // The monotonic deadline prevents a backwards wall-clock adjustment from reviving evidence.
    broker.sources.get_mut("live").unwrap().expires = Some(Instant::now());
    assert_eq!(
        broker.revalidate(&client, &context.ticket, &Utf8ByteCounter),
        Err(BrokerError::Stale)
    );
    assert!(matches!(
        broker.compile(&client, &request(), &Utf8ByteCounter),
        Err(BrokerError::Stale)
    ));
}

#[test]
fn exact_complete_answer_needs_host_reviews_and_substitution_invalidates_submission_id() {
    let mut broker = broker();
    ingest(
        &mut broker,
        "docs",
        "one",
        "meaningful evidence the configured port is 8080",
    );
    let client = broker.host_grant(spec("agent", &["docs"], &[])).unwrap();
    let context = compile(&mut broker, &client);
    let draft = AnswerDraft {
        snapshot_id: context.context.snapshot().id().to_owned(),
        claims: vec![AnswerClaim {
            text: "The configured port is 8080.".into(),
            citations: BTreeSet::from(["one".into()]),
            confidence_bps: Some(10_000),
        }],
        abstain: false,
    };
    let original = broker
        .submit_answer(&client, &context.ticket, draft.clone(), &Utf8ByteCounter)
        .unwrap();
    let unreviewed = broker
        .host_check_answer(
            &context.ticket,
            &original,
            &[],
            &AnswerPolicy::default(),
            &Utf8ByteCounter,
        )
        .unwrap();
    assert_eq!(unreviewed.assessment.decision, AnswerDecision::Abstain);
    assert_eq!(unreviewed.assessment.confident_failures, 1);
    assert!(
        unreviewed.assessment.claims[0]
            .issues
            .contains(&ClaimIssue::Unreviewed)
    );
    let review = ClaimReview {
        claim_key: draft.review_keys().unwrap()[0].clone(),
        verdict: ClaimVerdict::Supported,
        reviewed_counterevidence: BTreeSet::new(),
    };
    let released = broker
        .host_check_answer(
            &context.ticket,
            &original,
            std::slice::from_ref(&review),
            &AnswerPolicy::default(),
            &Utf8ByteCounter,
        )
        .unwrap();
    assert_eq!(released.assessment.decision, AnswerDecision::Release);
    let mut changed = draft;
    changed.claims.push(AnswerClaim {
        text: "This proves every server uses that port.".into(),
        citations: BTreeSet::from(["one".into()]),
        confidence_bps: Some(10_000),
    });
    let next = broker
        .submit_answer(&client, &context.ticket, changed, &Utf8ByteCounter)
        .unwrap();
    assert_ne!(original, next);
    assert_eq!(
        broker
            .host_submission(&context.ticket, &Utf8ByteCounter)
            .unwrap()
            .submission_id,
        next
    );
    assert!(matches!(
        broker.host_check_answer(
            &context.ticket,
            &original,
            std::slice::from_ref(&review),
            &AnswerPolicy::default(),
            &Utf8ByteCounter
        ),
        Err(BrokerError::Stale)
    ));
    let incomplete = broker
        .host_check_answer(
            &context.ticket,
            &next,
            &[review],
            &AnswerPolicy::default(),
            &Utf8ByteCounter,
        )
        .unwrap();
    assert_eq!(incomplete.assessment.decision, AnswerDecision::Abstain);
    ingest(
        &mut broker,
        "docs",
        "one",
        "meaningful evidence port is now 9090",
    );
    assert!(matches!(
        broker.host_check_answer(
            &context.ticket,
            &next,
            &[],
            &AnswerPolicy::default(),
            &Utf8ByteCounter
        ),
        Err(BrokerError::Stale)
    ));
}

#[test]
fn credentials_errors_and_closed_data_shapes_do_not_echo_or_accept_authority_overrides() {
    let mut broker = broker();
    let client = broker.host_grant(spec("agent", &["docs"], &[])).unwrap();
    assert!(!format!("{client:?}").contains(&client.secret));
    assert!(!format!("{client:?}").contains(&client.epoch));
    let hostile = BrokerCredential {
        epoch: broker.epoch().into(),
        secret: "PRIVATE_QUERY_TOKEN".into(),
    };
    let error = broker.source_revision(&hostile, "SECRET_PATH").unwrap_err();
    assert_eq!(error, BrokerError::AccessDenied);
    assert!(!error.to_string().contains("PRIVATE"));
    let mut value = serde_json::to_value(client).unwrap();
    value["view"] = serde_json::json!("administrator");
    assert!(serde_json::from_value::<BrokerCredential>(value).is_err());
    assert!(serde_json::from_value::<AnswerSubmission>(serde_json::json!({
        "submission_id": "forged", "draft": {"snapshot_id": "0".repeat(64), "claims": [], "abstain": true},
        "reviews": [{"verdict": "supported"}]
    })).is_err());
}

#[test]
fn host_relationships_use_cas_and_change_back_does_not_revive_context() {
    let mut broker = broker();
    ingest(&mut broker, "a", "a-id", "meaningful evidence a");
    ingest(&mut broker, "b", "b-id", "meaningful evidence b");
    ingest(
        &mut broker,
        "other",
        "other-id",
        "meaningful evidence independent",
    );
    let client = broker.host_grant(spec("reader", &["a", "b"], &[])).unwrap();
    let unaffected = broker
        .host_grant(spec("other-reader", &["other"], &[]))
        .unwrap();
    let before = compile(&mut broker, &client);
    let stable = compile(&mut broker, &unaffected);
    let expected = BTreeMap::from([("a".into(), broker.host_source_revision("a").unwrap())]);
    let linked = broker
        .host_set_edge("a-id", "b-id", EdgeKind::Requires, true, &expected)
        .unwrap();
    assert_eq!(linked["a"].version, expected["a"].version + 1);
    assert_eq!(
        broker.host_set_edge("a-id", "b-id", EdgeKind::Requires, false, &expected),
        Err(BrokerError::Conflict)
    );
    let unchanged = broker
        .host_set_edge("a-id", "b-id", EdgeKind::Requires, true, &linked)
        .unwrap();
    assert_eq!(unchanged, linked);
    let removed = broker
        .host_set_edge("a-id", "b-id", EdgeKind::Requires, false, &linked)
        .unwrap();
    assert_eq!(removed["a"].version, expected["a"].version + 2);
    assert_eq!(
        broker.revalidate(&client, &before.ticket, &Utf8ByteCounter),
        Err(BrokerError::Stale)
    );
    broker
        .revalidate(&unaffected, &stable.ticket, &Utf8ByteCounter)
        .unwrap();
    assert!(broker.edge_nodes.is_empty());
    let both = BTreeMap::from([
        ("a".into(), broker.host_source_revision("a").unwrap()),
        ("b".into(), broker.host_source_revision("b").unwrap()),
    ]);
    assert_eq!(
        broker.host_set_edge("a-id", "b-id", EdgeKind::Contradicts, true, &removed),
        Err(BrokerError::InvalidInput)
    );
    let conflict = broker
        .host_set_edge("a-id", "b-id", EdgeKind::Contradicts, true, &both)
        .unwrap();
    assert_eq!(conflict["a"].version, both["a"].version + 1);
    assert_eq!(conflict["b"].version, both["b"].version + 1);
    let request = ContextRequest {
        required: BTreeSet::from(["a-id".into()]),
        ..request()
    };
    let with_counterevidence = broker.compile(&client, &request, &Utf8ByteCounter).unwrap();
    assert_eq!(with_counterevidence.context.snapshot().blocks().len(), 2);
    let narrow = broker.host_grant(spec("narrow", &["a"], &[])).unwrap();
    assert!(matches!(
        broker.compile(&narrow, &request, &Utf8ByteCounter),
        Err(BrokerError::Context(
            crate::ContextError::RequiredUnavailable
        ))
    ));
}

#[test]
fn dangling_edge_identity_cannot_be_rebound_through_another_source() {
    let mut broker = broker();
    ingest(&mut broker, "a", "a-id", "meaningful evidence a");
    let original_b = ingest(&mut broker, "b", "b-id", "meaningful evidence b");
    let expected = BTreeMap::from([("a".into(), broker.host_source_revision("a").unwrap())]);
    let linked = broker
        .host_set_edge("a-id", "b-id", EdgeKind::Requires, true, &expected)
        .unwrap();
    broker
        .host_replace_source(
            "b",
            &original_b.revision,
            Vec::new(),
            provenance("withdrawn"),
        )
        .unwrap();
    let writer = broker.host_grant(spec("writer", &["c"], &["c"])).unwrap();
    let empty = broker.source_revision(&writer, "c").unwrap();
    let substitute = vec![Document::new(
        "b-id",
        "c",
        "meaningful evidence substituted by another source",
    )];
    assert!(matches!(
        broker.propose_source(&writer, "substitution", "c", &empty, substitute.clone()),
        Err(BrokerError::AccessDenied)
    ));
    assert_eq!(
        broker.host_replace_source("c", &empty, substitute.clone(), provenance("substitution")),
        Err(BrokerError::AccessDenied)
    );
    assert_eq!(broker.edge_nodes["b-id"].source, "b");
    broker
        .host_set_edge("a-id", "b-id", EdgeKind::Requires, false, &linked)
        .unwrap();
    assert!(broker.edge_nodes.is_empty());
    // Once the host explicitly removes the old relation, the unused ID has no dangling meaning.
    broker
        .propose_source(&writer, "after-explicit-unlink", "c", &empty, substitute)
        .unwrap();
    assert_eq!(broker.graph.len(), 1);
}

#[test]
fn relation_identity_budget_rejects_before_graph_or_source_mutation() {
    let mut broker = ContextBroker::new(
        "bounded",
        GraphLimits::default(),
        BrokerLimits {
            max_relation_bytes: RECORD_ALLOWANCE,
            ..BrokerLimits::default()
        },
    )
    .unwrap();
    ingest(&mut broker, "a", "a-id", "meaningful evidence a");
    ingest(&mut broker, "b", "b-id", "meaningful evidence b");
    let expected = BTreeMap::from([("a".into(), broker.host_source_revision("a").unwrap())]);
    let revision = broker.graph.revision();
    assert_eq!(
        broker.host_set_edge("a-id", "b-id", EdgeKind::Requires, true, &expected),
        Err(BrokerError::Quota)
    );
    assert_eq!(broker.graph.revision(), revision);
    assert_eq!(broker.host_source_revision("a").unwrap(), expected["a"]);
    assert!(broker.edge_nodes.is_empty());
    assert!(broker.graph.edges.is_empty());
}
