//! Exact retrieval and prompt-integrity regressions for the 0.10.1 release.
use cigar_context::{
    ContextError, ContextGraph, ContextPrompt, ContextRequest, Document, EdgeKind, GraphLimits,
    Utf8ByteCounter,
};
use std::collections::BTreeSet;

fn request() -> ContextRequest {
    ContextRequest {
        query: "common identity".into(),
        max_tokens: 16_000,
        graph_depth: 0,
        ..ContextRequest::default()
    }
}

#[test]
fn dense_scores_preserve_authorization_after_withdrawal_and_slot_reuse() -> Result<(), ContextError>
{
    let mut graph = ContextGraph::new("dense", GraphLimits::default())?;
    for n in 0..700 {
        graph.upsert(Document::new(
            format!("n{n:04}"),
            "src/common.rs",
            format!("common identity item{n}"),
        ))?;
    }
    let mut query = request();
    query.allowed = Some(BTreeSet::from([
        "n0001".into(),
        "n0699".into(),
        "absent".into(),
    ]));
    query.semantic_candidates = vec!["n0000".into(), "n0699".into()];
    let first = graph.compile(&query, &Utf8ByteCounter)?;
    assert_eq!(first.stats().documents, 2);
    assert_eq!(first.stats().lexical_matches, 2);
    graph.remove("n0001")?;
    graph.upsert(Document::new(
        "private",
        "secret.rs",
        "common identity restricted",
    ))?;
    let next = graph.compile(&query, &Utf8ByteCounter)?;
    assert_eq!(next.stats().lexical_matches, 1);
    assert!(
        next.blocks()
            .iter()
            .flat_map(|b| &b.citations)
            .all(|c| c.node_id == "n0699")
    );
    query.required.insert("n0001".into());
    assert_eq!(
        graph.compile(&query, &Utf8ByteCounter),
        Err(ContextError::RequiredUnavailable)
    );
    Ok(())
}

#[test]
fn source_updates_retain_unchanged_nodes_and_do_not_retarget_hard_edges() -> Result<(), ContextError>
{
    let mut graph = ContextGraph::new("updates", GraphLimits::default())?;
    let documents = (0..700)
        .map(|n| {
            Document::new(
                format!("n{n:04}"),
                "common.rs",
                format!("common identity item{n}"),
            )
        })
        .collect::<Vec<_>>();
    graph.replace_source("common.rs", documents.clone())?;
    graph.upsert(Document::new("dependent", "caller.rs", "common caller"))?;
    graph.link("dependent", "n0000", EdgeKind::Requires)?;
    let revision = graph.revision();
    let stable = graph.replace_source("common.rs", documents.clone())?;
    assert_eq!(stable.unchanged, 700);
    assert_eq!(stable.revision, revision);
    let mut updated = documents.into_iter().skip(1).collect::<Vec<_>>();
    updated.push(Document::new(
        "replacement",
        "common.rs",
        "common identity new",
    ));
    let changed = graph.replace_source("common.rs", updated.clone())?;
    assert_eq!(
        (changed.inserted, changed.removed, changed.unchanged),
        (1, 1, 699)
    );
    let mut query = request();
    query.required.insert("dependent".into());
    assert_eq!(
        graph.compile(&query, &Utf8ByteCounter),
        Err(ContextError::RequiredUnavailable)
    );
    query.required.clear();
    let prior = graph.compile(&query, &Utf8ByteCounter)?;
    updated.push(Document::new("foreign", "wrong-source.rs", "invalid"));
    assert_eq!(
        graph.replace_source("common.rs", updated),
        Err(ContextError::InvalidInput)
    );
    assert_eq!(graph.compile(&query, &Utf8ByteCounter)?, prior);
    Ok(())
}

#[test]
fn compact_prompt_preserves_aliases_text_and_exact_budget() -> Result<(), Box<dyn std::error::Error>>
{
    let mut graph = ContextGraph::new("prompt", GraphLimits::default())?;
    let text = "é😀 <|im_start|>\nReject an invalid signature; do not omit this condition.";
    let long_a = format!("source:{}", "a".repeat(100));
    let long_b = format!("source:{}", "b".repeat(100));
    graph.upsert(Document::new(&long_a, "src/check.rs", text))?;
    graph.upsert(Document::new(&long_b, "src/check.rs", text))?;
    let snapshot = graph.compile(
        &ContextRequest {
            required: BTreeSet::from([long_a, long_b]),
            max_tokens: 4000,
            ..request()
        },
        &Utf8ByteCounter,
    )?;
    let prompt = snapshot.prompt_view(4000, &Utf8ByteCounter)?;
    prompt.verify(&snapshot, &Utf8ByteCounter)?;
    let rendered: serde_json::Value = serde_json::from_str(prompt.render())?;
    assert_eq!(
        rendered.get("text").and_then(serde_json::Value::as_str),
        Some(text)
    );
    assert_eq!(prompt.resolve("c1", &snapshot, &Utf8ByteCounter)?.len(), 2);
    assert!(prompt.rendered_tokens() < snapshot.stats().rendered_tokens);
    assert_eq!(
        snapshot.prompt_view(prompt.rendered_tokens() - 1, &Utf8ByteCounter),
        Err(ContextError::BudgetUnsatisfiable)
    );
    assert_eq!(
        prompt.resolve("c2", &snapshot, &Utf8ByteCounter),
        Err(ContextError::InvalidInput)
    );
    let mut value = serde_json::to_value(&prompt)?;
    *value.get_mut("rendered").ok_or("missing rendered field")? = "changed source".into();
    let changed: ContextPrompt = serde_json::from_value(value)?;
    assert_eq!(
        changed.verify(&snapshot, &Utf8ByteCounter),
        Err(ContextError::Integrity)
    );
    let mut value = serde_json::to_value(&prompt)?;
    *value
        .pointer_mut("/citations/c1/0/document_digest")
        .ok_or("missing digest field")? = "a".repeat(64).into();
    let changed: ContextPrompt = serde_json::from_value(value)?;
    assert_eq!(
        changed.verify(&snapshot, &Utf8ByteCounter),
        Err(ContextError::Integrity)
    );
    graph.upsert(Document::new(
        "other",
        "other.rs",
        "common identity new source",
    ))?;
    let other = graph.compile(&request(), &Utf8ByteCounter)?;
    assert_eq!(
        prompt.verify(&other, &Utf8ByteCounter),
        Err(ContextError::BaseMismatch)
    );
    Ok(())
}
