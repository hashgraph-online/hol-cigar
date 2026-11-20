//! Distinct requested records must not collapse into one incidental word witness.

use hol_cigar::{
    ContextError, ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, TokenCounter,
    Utf8ByteCounter,
};
use std::collections::BTreeSet;

fn graph() -> Result<ContextGraph, ContextError> {
    let mut graph = ContextGraph::new("record-witnesses", GraphLimits::default())?;
    for (id, source, text) in [
        (
            "primary",
            "deployment/image",
            "The Atlas deployment image is app-42.",
        ),
        (
            "rollback",
            "deployment/rollback",
            "The Atlas deployment rollback image is app-39.",
        ),
        (
            "window",
            "deployment/window",
            "The Atlas deployment window starts at 17:00 UTC.",
        ),
        (
            "region",
            "deployment/region",
            "The Atlas deployment region is west-3.",
        ),
    ] {
        graph.upsert(Document::new(id, source, text))?;
    }
    Ok(graph)
}

fn request(max_tokens: usize) -> ContextRequest {
    ContextRequest {
        query: "Provide the current Atlas deployment records for image, rollback, window.".into(),
        max_tokens,
        graph_depth: 0,
        ..ContextRequest::default()
    }
}

fn ids(snapshot: &hol_cigar::ContextSnapshot) -> BTreeSet<String> {
    snapshot
        .blocks()
        .iter()
        .flat_map(|block| {
            block
                .citations
                .iter()
                .map(|citation| citation.node_id.clone())
        })
        .collect()
}

fn check_complete_records(counter: &impl TokenCounter) -> Result<(), ContextError> {
    let graph = graph()?;
    for budget in [512, 2048, 4096] {
        let snapshot = graph.compile(&request(budget), counter)?;
        assert_eq!(
            ids(&snapshot),
            BTreeSet::from(["primary".into(), "rollback".into(), "window".into()]),
            "an incidental image mention must not replace the separately requested image record"
        );
        assert!(snapshot.render().contains("app-42"));
        assert!(snapshot.render().contains("app-39"));
        assert_eq!(
            snapshot.stats().rendered_tokens,
            counter.count(&snapshot.render())?
        );
        assert!(snapshot.stats().rendered_tokens <= budget);
        snapshot.verify(counter)?;
    }
    Ok(())
}

#[test]
fn distinct_source_records_survive_overlapping_query_words() -> Result<(), ContextError> {
    check_complete_records(&Utf8ByteCounter)
}

#[cfg(feature = "bpe")]
#[test]
fn distinct_source_records_fit_unchanged_exact_token_budgets() -> Result<(), ContextError> {
    check_complete_records(&hol_cigar::O200kTokenizer::new()?)
}

#[test]
fn a_single_record_query_does_not_collect_unrequested_records() -> Result<(), ContextError> {
    let graph = graph()?;
    let snapshot = graph.compile(
        &ContextRequest {
            query: "Atlas deployment window".into(),
            ..request(4096)
        },
        &Utf8ByteCounter,
    )?;
    assert_eq!(ids(&snapshot), BTreeSet::from(["window".into()]));
    Ok(())
}

#[test]
fn a_compound_record_name_does_not_request_its_component_record() -> Result<(), ContextError> {
    let graph = graph()?;
    for budget in [512, 2048, 4096] {
        let snapshot = graph.compile(
            &ContextRequest {
                query: "What is the Atlas deployment rollback image?".into(),
                ..request(budget)
            },
            &Utf8ByteCounter,
        )?;
        assert_eq!(ids(&snapshot), BTreeSet::from(["rollback".into()]));
    }
    Ok(())
}

#[test]
fn conjoined_record_names_keep_their_separate_witnesses() -> Result<(), ContextError> {
    let graph = graph()?;
    for query in [
        "Provide the Atlas deployment image and rollback records.",
        "Provide the Atlas deployment image AND rollback records.",
        "Provide the Atlas deployment image; rollback records.",
    ] {
        for budget in [512, 2048, 4096] {
            let snapshot = graph.compile(
                &ContextRequest {
                    query: query.into(),
                    ..request(budget)
                },
                &Utf8ByteCounter,
            )?;
            assert_eq!(
                ids(&snapshot),
                BTreeSet::from(["primary".into(), "rollback".into()])
            );
        }
    }
    Ok(())
}

#[test]
fn copied_text_does_not_gain_a_second_witness_from_its_locator() -> Result<(), ContextError> {
    let mut graph = ContextGraph::new("copied-record", GraphLimits::default())?;
    let text = "The deployment image is app-42.";
    graph.upsert(Document::new("first", "records/current", text))?;
    graph.upsert(Document::new("copy", "records/image", text))?;
    let snapshot = graph.compile(
        &ContextRequest {
            query: "image".into(),
            required: BTreeSet::from(["first".into()]),
            ..request(4096)
        },
        &Utf8ByteCounter,
    )?;
    assert_eq!(ids(&snapshot), BTreeSet::from(["first".into()]));
    Ok(())
}

#[test]
fn source_witnesses_cannot_bypass_scope_or_withdrawn_hard_dependencies() -> Result<(), ContextError>
{
    let mut graph = graph()?;
    let mut query = request(4096);
    query.allowed = Some(BTreeSet::from(["rollback".into(), "window".into()]));
    let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
    assert!(!ids(&snapshot).contains("primary"));
    query.required.insert("primary".into());
    assert_eq!(
        graph.compile(&query, &Utf8ByteCounter),
        Err(ContextError::RequiredUnavailable)
    );

    graph.upsert(Document::new(
        "approval",
        "deployment/approval",
        "Approval is required.",
    ))?;
    graph.link("primary", "approval", EdgeKind::Requires)?;
    graph.remove("approval")?;
    let snapshot = graph.compile(&request(4096), &Utf8ByteCounter)?;
    assert!(!ids(&snapshot).contains("primary"));
    assert_eq!(snapshot.stats().unavailable_roots, 1);
    Ok(())
}

#[test]
fn source_witnesses_preserve_block_limits_and_complete_hard_closures() -> Result<(), ContextError> {
    let mut graph = graph()?;
    graph.upsert(Document::new(
        "approval",
        "deployment/approval",
        "Approval is required.",
    ))?;
    graph.link("primary", "approval", EdgeKind::Requires)?;
    let snapshot = graph.compile(
        &ContextRequest {
            max_blocks: 2,
            ..request(4096)
        },
        &Utf8ByteCounter,
    )?;
    let selected = ids(&snapshot);
    assert!(snapshot.blocks().len() <= 2);
    assert!(!selected.contains("primary") || selected.contains("approval"));

    assert_eq!(
        graph.compile(
            &ContextRequest {
                required: BTreeSet::from(["primary".into()]),
                max_blocks: 1,
                ..request(4096)
            },
            &Utf8ByteCounter,
        ),
        Err(ContextError::BudgetUnsatisfiable)
    );
    Ok(())
}
