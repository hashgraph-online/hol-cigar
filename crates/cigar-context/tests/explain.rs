//! Selection observation must preserve exact legacy results and current disclosure boundaries.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use cigar_context::{
    ContextError, ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits,
    SelectionExplanation, SelectionSignal, Utf8ByteCounter,
};
use std::collections::BTreeSet;

fn ids(explanation: &SelectionExplanation) -> Vec<String> {
    explanation
        .steps
        .iter()
        .flat_map(|step| step.added_ids.clone())
        .collect()
}

#[test]
fn trace_records_actual_selection_signals_and_full_closure_without_changing_snapshot() {
    let mut graph = ContextGraph::new("private-domain", GraphLimits::default()).unwrap();
    for (id, text) in [
        ("lex", "pub fn authorize_user() {}\n"),
        ("counter", "Reject requests without permission."),
        ("support", "Keep an audit trail."),
        ("semantic", "A separate retrieval lead."),
        ("req", "Required contract."),
        ("alias", "Required contract."),
        ("DENIED_ID", "authorize_user SECRET_TEXT"),
    ] {
        graph
            .upsert(Document::new(id, format!("source-{id}"), text))
            .unwrap();
    }
    graph.link("lex", "counter", EdgeKind::Requires).unwrap();
    graph.link("lex", "support", EdgeKind::Supports).unwrap();
    let request = ContextRequest {
        query: "authorize_user".into(),
        max_tokens: 20_000,
        required: BTreeSet::from(["alias".into(), "req".into()]),
        semantic_candidates: vec!["semantic".into(), "DENIED_ID".into(), "ABSENT_ID".into()],
        allowed: Some(
            ["lex", "counter", "support", "semantic", "req", "alias"]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ..ContextRequest::default()
    };
    let snapshot = graph.compile(&request, &Utf8ByteCounter).unwrap();
    let before = serde_json::to_vec(&snapshot).unwrap();
    let explanation = graph
        .explain(&request, &snapshot, &Utf8ByteCounter)
        .unwrap();
    assert_eq!(explanation.schema, "cigar.context-selection-explanation.v1");
    assert_eq!(explanation.snapshot_id, snapshot.id());
    assert_eq!(explanation.tokenizer, "cigar.utf8-bytes.v1");
    assert_eq!(explanation.checked_graph_revision, graph.revision());
    assert_eq!(explanation.request_id.len(), 64);
    let selected = snapshot
        .blocks()
        .iter()
        .flat_map(|block| block.citations.iter().map(|c| c.node_id.clone()))
        .collect::<BTreeSet<_>>();
    let traced = ids(&explanation);
    assert_eq!(traced.len(), selected.len());
    assert_eq!(traced.into_iter().collect::<BTreeSet<_>>(), selected);
    for step in &explanation.steps {
        assert!(step.added_ids.contains(&step.root_id));
        assert!(step.added_ids.windows(2).all(|pair| pair[0] < pair[1]));
    }
    let lex = explanation
        .steps
        .iter()
        .find(|step| step.root_id == "lex")
        .unwrap();
    assert_eq!(lex.added_ids, ["counter", "lex"]);
    assert_eq!(
        lex.signals,
        [
            SelectionSignal::LexicalMatch,
            SelectionSignal::DeclarationMatch
        ]
    );
    assert_eq!(
        explanation
            .steps
            .iter()
            .find(|step| step.root_id == "semantic")
            .unwrap()
            .signals,
        [SelectionSignal::SemanticCandidate]
    );
    assert_eq!(
        explanation
            .steps
            .iter()
            .find(|step| step.root_id == "support")
            .unwrap()
            .signals,
        [SelectionSignal::GraphExpansion]
    );
    assert_eq!(explanation.steps[0].signals, [SelectionSignal::Required]);
    assert!(
        snapshot
            .blocks()
            .iter()
            .any(|block| block.citations.len() == 2)
    );
    let wire = serde_json::to_string(&explanation).unwrap();
    for secret in [
        "DENIED_ID",
        "ABSENT_ID",
        "SECRET_TEXT",
        "private-domain",
        "source-",
        "authorize_user",
    ] {
        assert!(!wire.contains(secret));
        assert!(!format!("{explanation:?}").contains(secret));
    }
    assert_eq!(
        before,
        serde_json::to_vec(&graph.compile(&request, &Utf8ByteCounter).unwrap()).unwrap()
    );
    assert_eq!(
        explanation,
        graph
            .explain(&request, &snapshot, &Utf8ByteCounter)
            .unwrap()
    );
}

#[test]
fn rejected_candidates_never_appear_and_forged_or_stale_snapshots_never_get_a_trace() {
    let mut graph = ContextGraph::new("domain", GraphLimits::default()).unwrap();
    graph
        .upsert(Document::new("small", "one", "evidence"))
        .unwrap();
    graph
        .upsert(Document::new("REJECTED_BIG", "two", "large ".repeat(1000)))
        .unwrap();
    let request = ContextRequest {
        query: "evidence".into(),
        max_tokens: 1000,
        required: BTreeSet::from(["small".into()]),
        semantic_candidates: vec!["REJECTED_BIG".into()],
        ..ContextRequest::default()
    };
    let snapshot = graph.compile(&request, &Utf8ByteCounter).unwrap();
    assert_eq!(snapshot.stats().budget_rejected_roots, 1);
    let explanation = graph
        .explain(&request, &snapshot, &Utf8ByteCounter)
        .unwrap();
    assert_eq!(ids(&explanation), ["small"]);
    assert!(
        !serde_json::to_string(&explanation)
            .unwrap()
            .contains("REJECTED_BIG")
    );
    let mut forged = serde_json::to_value(&snapshot).unwrap();
    forged["blocks"][0]["text"] = "FORGED".into();
    assert_eq!(
        graph.explain(
            &request,
            &serde_json::from_value(forged).unwrap(),
            &Utf8ByteCounter
        ),
        Err(ContextError::BaseMismatch)
    );
    let changed_request = ContextRequest {
        allowed: Some(BTreeSet::new()),
        required: BTreeSet::new(),
        ..request.clone()
    };
    assert_eq!(
        graph.explain(&changed_request, &snapshot, &Utf8ByteCounter),
        Err(ContextError::BaseMismatch)
    );
    graph
        .upsert(Document::new("REJECTED_BIG", "two", "new unselected text"))
        .unwrap();
    assert_eq!(
        graph.explain(&request, &snapshot, &Utf8ByteCounter),
        Err(ContextError::BaseMismatch)
    );
}

#[test]
fn empty_and_required_already_in_closure_have_no_spurious_steps() {
    let mut graph = ContextGraph::new("domain", GraphLimits::default()).unwrap();
    let mut request = ContextRequest {
        query: "absent".into(),
        ..ContextRequest::default()
    };
    let empty = graph.compile(&request, &Utf8ByteCounter).unwrap();
    assert!(
        graph
            .explain(&request, &empty, &Utf8ByteCounter)
            .unwrap()
            .steps
            .is_empty()
    );
    graph.upsert(Document::new("a", "a", "first")).unwrap();
    graph.upsert(Document::new("b", "b", "second")).unwrap();
    graph.link("a", "b", EdgeKind::Requires).unwrap();
    request.required = BTreeSet::from(["a".into(), "b".into()]);
    let snapshot = graph.compile(&request, &Utf8ByteCounter).unwrap();
    let explanation = graph
        .explain(&request, &snapshot, &Utf8ByteCounter)
        .unwrap();
    assert_eq!(explanation.steps.len(), 1);
    assert_eq!(explanation.steps[0].added_ids, ["a", "b"]);
}

#[test]
fn symmetric_counterevidence_keeps_the_actual_selected_root_and_both_documents() {
    let mut graph = ContextGraph::new("domain", GraphLimits::default()).unwrap();
    graph
        .upsert(Document::new("a", "a", "retry is allowed"))
        .unwrap();
    graph
        .upsert(Document::new("b", "b", "counterevidence"))
        .unwrap();
    graph.link("a", "b", EdgeKind::Contradicts).unwrap();
    let request = ContextRequest {
        query: "retry".into(),
        ..ContextRequest::default()
    };
    let snapshot = graph.compile(&request, &Utf8ByteCounter).unwrap();
    let explanation = graph
        .explain(&request, &snapshot, &Utf8ByteCounter)
        .unwrap();
    assert_eq!(explanation.steps.len(), 1);
    assert_eq!(explanation.steps[0].added_ids, ["a", "b"]);
    let expected = if explanation.steps[0].root_id == "a" {
        SelectionSignal::LexicalMatch
    } else {
        assert_eq!(explanation.steps[0].root_id, "b");
        SelectionSignal::GraphExpansion
    };
    assert_eq!(explanation.steps[0].signals, [expected]);
}
