//! Shared-view isolation, freshness and review compatibility regressions.
// Fixture construction and deliberately forged JSON must fail loudly on missing fields.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use cigar_context::{
    AnswerClaim, AnswerDecision, AnswerDraft, AnswerPolicy, ClaimReview, ClaimVerdict,
    ContextError, ContextGraph, ContextRequest, ContextView, ContextViewHandle, ContextViewSpec,
    ContextViews, Document, EdgeKind, GraphLimits, Utf8ByteCounter,
};
use std::collections::BTreeSet;

fn spec(id: &str) -> ContextViewSpec {
    ContextViewSpec {
        id: id.into(),
        allowed_sources: BTreeSet::from([id.into(), "shared".into()]),
        writable_sources: BTreeSet::from([id.into()]),
        policy_revision: "policy-1".into(),
    }
}

fn fixture() -> (ContextGraph, ContextViews, Vec<ContextViewHandle>) {
    let mut graph = ContextGraph::new("one-workspace", GraphLimits::default()).unwrap();
    graph
        .upsert(Document::new(
            "policy",
            "shared",
            "Every action needs review.",
        ))
        .unwrap();
    let mut views = ContextViews::default();
    let mut handles = Vec::new();
    for i in 0..5 {
        let id = format!("agent-{i}");
        graph
            .upsert(Document::new(&id, &id, format!("{id} owns task {i}.")))
            .unwrap();
        graph.link(&id, "policy", EdgeKind::Requires).unwrap();
        handles.push(views.define(spec(&id)).unwrap());
    }
    (graph, views, handles)
}

fn request(id: &str) -> ContextRequest {
    ContextRequest {
        query: "task".into(),
        required: BTreeSet::from([id.into()]),
        max_tokens: 20_000,
        ..ContextRequest::default()
    }
}

fn reviewed(context: &ContextView, id: &str) -> (AnswerDraft, Vec<ClaimReview>) {
    let draft = AnswerDraft {
        snapshot_id: context.snapshot().id().into(),
        abstain: false,
        claims: vec![AnswerClaim {
            text: "A task is assigned.".into(),
            citations: BTreeSet::from([id.into()]),
            confidence_bps: Some(9999),
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
    (draft, reviews)
}

#[test]
fn five_views_share_one_index_and_narrow_access() {
    let (graph, views, handles) = fixture();
    assert_eq!(graph.len(), 6);
    for handle in &handles {
        let context = views
            .compile(&graph, handle, &request(&handle.id), &Utf8ByteCounter)
            .unwrap();
        assert_eq!(context.snapshot().stats().documents, 2);
        assert!(
            context
                .snapshot()
                .blocks()
                .iter()
                .flat_map(|b| &b.citations)
                .all(|c| c.node_id == handle.id || c.node_id == "policy")
        );
        let mut foreign = request("agent-4");
        if handle.id == "agent-4" {
            foreign = request("agent-0");
        }
        foreign.allowed = Some(BTreeSet::from([
            "agent-0".into(),
            "agent-4".into(),
            "policy".into(),
        ]));
        assert_eq!(
            views
                .compile(&graph, handle, &foreign, &Utf8ByteCounter)
                .unwrap_err(),
            ContextError::RequiredUnavailable
        );
        let mut empty = request(&handle.id);
        empty.allowed = Some(BTreeSet::new());
        assert_eq!(
            views
                .compile(&graph, handle, &empty, &Utf8ByteCounter)
                .unwrap_err(),
            ContextError::RequiredUnavailable
        );
    }
}

#[test]
fn unrelated_updates_insertions_and_removals_preserve_original_reviews() {
    let (mut graph, views, handles) = fixture();
    let handle = &handles[0];
    let context = views
        .compile(&graph, handle, &request(&handle.id), &Utf8ByteCounter)
        .unwrap();
    let (draft, reviews) = reviewed(&context, &handle.id);
    for i in 0..30 {
        let docs = if i % 3 == 0 {
            vec![]
        } else {
            vec![
                Document::new("agent-4", "agent-4", format!("Other task version {i}")),
                Document::new("other", "agent-4", "A new unrelated task"),
            ]
        };
        views
            .replace_source(&mut graph, &handles[4], "agent-4", docs)
            .unwrap();
        let checked = views
            .check_answer(
                &graph,
                handle,
                &context,
                &draft,
                &reviews,
                &AnswerPolicy::default(),
                &Utf8ByteCounter,
            )
            .unwrap();
        assert_eq!(checked.assessment.decision, AnswerDecision::Release);
        assert_eq!(checked.assessment.snapshot_id, context.snapshot().id());
        assert_eq!(checked.checked_graph_revision, graph.revision());
    }
}

#[test]
fn legacy_exact_snapshot_check_remains_conservative() {
    let (mut graph, _, _) = fixture();
    let mut query = request("agent-0");
    query.allowed = Some(BTreeSet::from(["agent-0".into(), "policy".into()]));
    let snapshot = graph.compile(&query, &Utf8ByteCounter).unwrap();
    let draft = AnswerDraft {
        snapshot_id: snapshot.id().into(),
        claims: vec![],
        abstain: true,
    };
    graph
        .upsert(Document::new("agent-4", "agent-4", "An unrelated change"))
        .unwrap();
    assert_eq!(
        graph
            .check_answer(
                &query,
                &draft,
                &[],
                &AnswerPolicy::default(),
                &Utf8ByteCounter
            )
            .unwrap_err(),
        ContextError::BaseMismatch
    );
}

#[test]
fn authorized_unselected_evidence_and_edges_invalidate() {
    for change in 0..5 {
        let (mut graph, views, handles) = fixture();
        let handle = &handles[0];
        let context = views
            .compile(&graph, handle, &request(&handle.id), &Utf8ByteCounter)
            .unwrap();
        let (draft, reviews) = reviewed(&context, &handle.id);
        match change {
            0 => {
                graph
                    .upsert(Document::new("agent-0", "agent-0", "The task changed"))
                    .unwrap();
            }
            1 => {
                graph
                    .upsert(Document::new(
                        "new",
                        "shared",
                        "Newly available counterevidence",
                    ))
                    .unwrap();
            }
            2 => {
                graph
                    .unlink("agent-0", "policy", EdgeKind::Requires)
                    .unwrap();
            }
            3 => {
                graph
                    .link("agent-0", "policy", EdgeKind::Contradicts)
                    .unwrap();
            }
            _ => {
                graph
                    .upsert(Document::new(
                        "policy",
                        "shared",
                        "The shared policy changed",
                    ))
                    .unwrap();
            }
        }
        assert_eq!(
            views
                .check_answer(
                    &graph,
                    handle,
                    &context,
                    &draft,
                    &reviews,
                    &AnswerPolicy::default(),
                    &Utf8ByteCounter
                )
                .unwrap_err(),
            ContextError::BaseMismatch
        );
    }
}

#[test]
fn missing_required_evidence_stays_fail_closed() {
    let (mut graph, views, handles) = fixture();
    let handle = &handles[0];
    let context = views
        .compile(&graph, handle, &request(&handle.id), &Utf8ByteCounter)
        .unwrap();
    let (draft, reviews) = reviewed(&context, &handle.id);
    graph.remove("policy").unwrap();
    assert_eq!(
        views
            .check_answer(
                &graph,
                handle,
                &context,
                &draft,
                &reviews,
                &AnswerPolicy::default(),
                &Utf8ByteCounter
            )
            .unwrap_err(),
        ContextError::RequiredUnavailable
    );
}

#[test]
fn revoked_and_redefined_handles_cannot_reuse_reviews() {
    let (graph, mut views, handles) = fixture();
    let handle = &handles[0];
    let context = views
        .compile(&graph, handle, &request(&handle.id), &Utf8ByteCounter)
        .unwrap();
    let (draft, reviews) = reviewed(&context, &handle.id);
    assert!(views.revoke(&handle.id));
    let new = views.define(spec(&handle.id)).unwrap();
    assert!(new.generation > handle.generation);
    assert_eq!(
        views
            .check_answer(
                &graph,
                handle,
                &context,
                &draft,
                &reviews,
                &AnswerPolicy::default(),
                &Utf8ByteCounter
            )
            .unwrap_err(),
        ContextError::RequiredUnavailable
    );
    assert_eq!(
        views
            .check_answer(
                &graph,
                &new,
                &context,
                &draft,
                &reviews,
                &AnswerPolicy::default(),
                &Utf8ByteCounter
            )
            .unwrap_err(),
        ContextError::BaseMismatch
    );
}

#[test]
fn denied_writes_and_cross_source_id_collisions_are_atomic() {
    let (mut graph, views, handles) = fixture();
    let revision = graph.revision();
    for (source, docs) in [
        (
            "shared",
            vec![Document::new("policy", "shared", "Override")],
        ),
        (
            "agent-0",
            vec![Document::new("policy", "agent-0", "Steal shared ID")],
        ),
        (
            "agent-0",
            vec![Document::new("new", "agent-4", "Wrong source")],
        ),
        ("agent-4", vec![]),
    ] {
        assert_eq!(
            views
                .replace_source(&mut graph, &handles[0], source, docs)
                .unwrap_err(),
            ContextError::RequiredUnavailable
        );
        assert_eq!(graph.revision(), revision);
    }
}

#[test]
fn confidence_and_untrusted_missing_reviews_never_grant_release() {
    let (graph, views, handles) = fixture();
    let context = views
        .compile(&graph, &handles[0], &request("agent-0"), &Utf8ByteCounter)
        .unwrap();
    let (draft, mut reviews) = reviewed(&context, "agent-0");
    let unchecked = views
        .check_answer(
            &graph,
            &handles[0],
            &context,
            &draft,
            &[],
            &AnswerPolicy::default(),
            &Utf8ByteCounter,
        )
        .unwrap();
    assert_eq!(unchecked.assessment.decision, AnswerDecision::Abstain);
    reviews[0].verdict = ClaimVerdict::Contradicted;
    let checked = views
        .check_answer(
            &graph,
            &handles[0],
            &context,
            &draft,
            &reviews,
            &AnswerPolicy::default(),
            &Utf8ByteCounter,
        )
        .unwrap();
    assert_eq!(checked.assessment.decision, AnswerDecision::Abstain);
    assert_eq!(checked.assessment.confident_failures, 1);
}

#[test]
fn public_envelope_rehash_cannot_rebind_an_old_review_to_new_scope() {
    use sha2::{Digest, Sha256};
    let (mut graph, views, handles) = fixture();
    let old = views
        .compile(&graph, &handles[0], &request("agent-0"), &Utf8ByteCounter)
        .unwrap();
    let (draft, reviews) = reviewed(&old, "agent-0");
    // Selected evidence can stay the same while another authorized document is inserted.
    graph
        .upsert(Document::new("unused", "shared", "zzzzzz unrelated words"))
        .unwrap();
    let current = views
        .compile(&graph, &handles[0], &request("agent-0"), &Utf8ByteCounter)
        .unwrap();
    let mut forged = serde_json::to_value(&old).unwrap();
    forged["scope_id"] = serde_json::to_value(&current).unwrap()["scope_id"].clone();
    let body = serde_json::json!([
        forged["view"],
        forged["request"],
        forged["scope_id"],
        forged["snapshot"]["id"]
    ]);
    // Reserialize request in its canonical Rust field order, just like the kernel.
    let typed_request: ContextRequest = serde_json::from_value(body[1].clone()).unwrap();
    let bytes = serde_json::to_vec(&(
        handles[0].clone(),
        typed_request,
        body[2].as_str().unwrap(),
        draft.snapshot_id.clone(),
    ))
    .unwrap();
    let mut hash = Sha256::new();
    hash.update(b"cigar.context-view.v1\0");
    hash.update(bytes);
    forged["id"] = serde_json::json!(
        hash.finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let forged: ContextView = serde_json::from_value(forged).unwrap();
    assert_eq!(
        views
            .check_answer(
                &graph,
                &handles[0],
                &forged,
                &draft,
                &reviews,
                &AnswerPolicy::default(),
                &Utf8ByteCounter
            )
            .unwrap_err(),
        ContextError::BaseMismatch
    );
}

#[test]
fn bounded_definitions_and_readonly_views() {
    let (mut graph, mut views, handles) = fixture();
    let mut readonly = spec("readonly");
    readonly.writable_sources.clear();
    let readonly = views.define(readonly).unwrap();
    assert_eq!(
        views
            .replace_source(&mut graph, &readonly, "readonly", vec![])
            .unwrap_err(),
        ContextError::RequiredUnavailable
    );
    let mut invalid = spec("invalid");
    invalid.writable_sources.insert("foreign".into());
    assert_eq!(
        views.define(invalid).unwrap_err(),
        ContextError::InvalidInput
    );
    for i in 6..128 {
        views.define(spec(&format!("view-{i}"))).unwrap();
    }
    assert_eq!(
        views.define(spec("overflow")).unwrap_err(),
        ContextError::LimitExceeded
    );
    assert!(views.revoke(&handles[0].id));
    views.define(spec("replacement")).unwrap();
}
