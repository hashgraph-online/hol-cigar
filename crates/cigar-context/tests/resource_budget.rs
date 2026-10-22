//! Small output budgets must not permit unbounded preparation of overlapping closures.
use cigar_context::{
    ContextError, ContextGraph, ContextRequest, Document, EdgeKind, ExcerptMode, GraphLimits,
    Utf8ByteCounter,
};

fn chain(count: usize, bytes: usize, kind: EdgeKind) -> Result<ContextGraph, ContextError> {
    let mut graph = ContextGraph::new("preparation-budget", GraphLimits::default())?;
    for index in 0..count {
        graph.upsert(Document::new(
            format!("n{index:04}"),
            format!("source-{index}"),
            format!("common {index} {}", "x".repeat(bytes)),
        ))?;
        if index > 0 {
            graph.link(&format!("n{:04}", index - 1), &format!("n{index:04}"), kind)?;
        }
    }
    Ok(graph)
}

#[test]
fn tiny_output_cannot_amplify_overlapping_closure_preparation() -> Result<(), ContextError> {
    for kind in [EdgeKind::Requires, EdgeKind::Contradicts] {
        let graph = chain(128, 8192, kind)?;
        for excerpt_mode in [ExcerptMode::Full, ExcerptMode::QueryWindows] {
            let request = ContextRequest {
                query: "common".into(),
                max_tokens: 1,
                max_blocks: 1,
                max_candidates: 128,
                graph_depth: 0,
                excerpt_mode,
                ..ContextRequest::default()
            };
            assert_eq!(
                graph.compile(&request, &Utf8ByteCounter),
                Err(ContextError::LimitExceeded)
            );
        }
    }
    Ok(())
}

#[test]
fn bounded_queries_and_explanations_keep_complete_dependencies() -> Result<(), ContextError> {
    let graph = chain(8, 32, EdgeKind::Requires)?;
    let request = ContextRequest {
        query: "common".into(),
        required: ["n0000".into()].into(),
        max_tokens: 8192,
        graph_depth: 0,
        ..ContextRequest::default()
    };
    let snapshot = graph.compile(&request, &Utf8ByteCounter)?;
    assert_eq!(snapshot.stats().selected_sources, 8);
    snapshot.verify(&Utf8ByteCounter)?;
    graph.explain(&request, &snapshot, &Utf8ByteCounter)?;
    // Exhaustion is per call and cannot poison an otherwise usable graph.
    let tiny = ContextRequest {
        required: Default::default(),
        max_tokens: 1,
        ..request
    };
    assert!(graph.compile(&tiny, &Utf8ByteCounter)?.blocks().is_empty());
    Ok(())
}

#[test]
fn disjoint_excerpt_citations_are_charged_before_copying_source_locators()
-> Result<(), ContextError> {
    let mut graph = ContextGraph::new("excerpt-budget", GraphLimits::default())?;
    graph.upsert(Document::new(
        "windows",
        "s".repeat(2048),
        "aa\n\n\n\n".repeat(43_690),
    ))?;
    let request = ContextRequest {
        query: "aa".into(),
        max_tokens: 1,
        excerpt_mode: ExcerptMode::QueryWindows,
        graph_depth: 0,
        ..ContextRequest::default()
    };
    assert_eq!(
        graph.compile(&request, &Utf8ByteCounter),
        Err(ContextError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn required_coalescing_charges_comparisons_before_rejecting_small_output()
-> Result<(), ContextError> {
    let mut graph = ContextGraph::new("coalescing-budget", GraphLimits::default())?;
    // Only 4 MiB of input; equal-length bodies differ at their final bytes.
    for index in 0..512 {
        graph.upsert(Document::new(
            format!("n{index:04}"),
            "source",
            format!("{} {index:04}", "x".repeat(8192)),
        ))?;
        if index > 0 {
            graph.link(
                &format!("n{:04}", index - 1),
                &format!("n{index:04}"),
                EdgeKind::Requires,
            )?;
        }
    }
    let request = ContextRequest {
        required: ["n0000".into()].into(),
        max_candidates: 512,
        max_blocks: 1,
        max_tokens: 1,
        ..ContextRequest::default()
    };
    assert_eq!(
        graph.compile(&request, &Utf8ByteCounter),
        Err(ContextError::LimitExceeded)
    );
    Ok(())
}
