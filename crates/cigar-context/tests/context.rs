//! Local graph behavior, budget, update, and integrity acceptance tests.
#[cfg(feature = "bpe")]
use cigar_context::TokenCounter;
use cigar_context::{
    ContextDelta, ContextError, ContextGraph, ContextRequest, ContextSnapshot, Document, EdgeKind,
    ExcerptMode, GraphLimits, Utf8ByteCounter,
};
use std::collections::BTreeSet;
use std::error::Error;

fn graph() -> Result<ContextGraph, ContextError> {
    ContextGraph::new("test-domain", GraphLimits::default())
}

fn request(query: &str) -> ContextRequest {
    ContextRequest {
        query: query.into(),
        max_tokens: 8192,
        ..ContextRequest::default()
    }
}

fn ids(snapshot: &ContextSnapshot) -> BTreeSet<String> {
    snapshot
        .blocks()
        .iter()
        .flat_map(|b| b.citations.iter().map(|c| c.node_id.clone()))
        .collect()
}

#[test]
fn graph_recovers_transitive_evidence_and_counterclaims() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    for (id, text) in [
        ("retry", "The retry handler uses operation keys."),
        (
            "contract",
            "An operation key MUST be stable across attempts.",
        ),
        ("database", "Operation keys are scoped to a tenant."),
        (
            "incident",
            "The old handler creates a NEW key and may duplicate writes.",
        ),
    ] {
        graph.upsert(Document::new(id, format!("docs/{id}"), text))?;
    }
    graph.link("retry", "contract", EdgeKind::Requires)?;
    graph.link("contract", "database", EdgeKind::Requires)?;
    graph.link("retry", "incident", EdgeKind::Contradicts)?;
    let context = graph.compile(&request("retry"), &Utf8ByteCounter)?;
    assert_eq!(
        ids(&context),
        BTreeSet::from([
            "retry".into(),
            "contract".into(),
            "database".into(),
            "incident".into()
        ])
    );
    assert!(context.render().contains("NEW key"));
    context.verify(&Utf8ByteCounter)?;
    Ok(())
}

#[test]
fn access_is_checked_on_every_graph_hop() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("public", "public.md", "retry"))?;
    graph.upsert(Document::new("private", "private.md", "SECRET_CANARY_ABC"))?;
    graph.link("public", "private", EdgeKind::Supports)?;
    let mut request = request("retry");
    request.allowed = Some(BTreeSet::from(["public".into()]));
    let context = graph.compile(&request, &Utf8ByteCounter)?;
    assert!(!context.render().contains("SECRET_CANARY"));
    graph.link("public", "private", EdgeKind::Requires)?;
    let context = graph.compile(&request, &Utf8ByteCounter)?;
    assert!(context.blocks().is_empty());
    request.required.insert("public".into());
    assert_eq!(
        graph.compile(&request, &Utf8ByteCounter).err(),
        Some(ContextError::RequiredUnavailable)
    );
    Ok(())
}

#[test]
fn withdrawing_dependency_cannot_silently_validate_its_dependent() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("root", "a", "retry"))?;
    graph.upsert(Document::new("dependency", "b", "must retain identity"))?;
    graph.link("root", "dependency", EdgeKind::Requires)?;
    graph.remove("dependency")?;
    let mut request = request("retry");
    request.required.insert("root".into());
    assert_eq!(
        graph.compile(&request, &Utf8ByteCounter).err(),
        Some(ContextError::RequiredUnavailable)
    );
    graph.unlink("root", "dependency", EdgeKind::Requires)?;
    assert_eq!(graph.compile(&request, &Utf8ByteCounter)?.blocks().len(), 1);
    Ok(())
}

#[test]
fn cycles_are_jointly_required_and_bounded() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("a", "a", "alpha"))?;
    graph.upsert(Document::new("b", "b", "beta"))?;
    graph.link("a", "b", EdgeKind::Requires)?;
    graph.link("b", "a", EdgeKind::Requires)?;
    let mut request = request("alpha");
    request.required.insert("a".into());
    assert_eq!(ids(&graph.compile(&request, &Utf8ByteCounter)?).len(), 2);
    request.max_tokens = 10;
    assert_eq!(
        graph.compile(&request, &Utf8ByteCounter).err(),
        Some(ContextError::BudgetUnsatisfiable)
    );
    Ok(())
}

#[test]
fn increments_match_a_fresh_rebuild_and_noop_is_stable() -> Result<(), Box<dyn Error>> {
    let mut incremental = graph()?;
    incremental.upsert(Document::new("a", "src/a", "old obsolete reference"))?;
    incremental.upsert(Document::new("b", "src/b", "retry idempotent"))?;
    let updated = Document::new("a", "src/a", "retry operation identity");
    incremental.upsert(updated.clone())?;
    let revision = incremental.revision();
    assert!(!incremental.upsert(updated.clone())?);
    assert_eq!(revision, incremental.revision());
    let mut rebuilt = graph()?;
    rebuilt.upsert(Document::new("b", "src/b", "retry idempotent"))?;
    rebuilt.upsert(updated)?;
    let query = request("retry operation identity");
    assert_eq!(
        incremental.compile(&query, &Utf8ByteCounter)?.render(),
        rebuilt.compile(&query, &Utf8ByteCounter)?.render()
    );
    assert!(
        incremental
            .compile(&request("obsolete"), &Utf8ByteCounter)?
            .blocks()
            .is_empty()
    );
    Ok(())
}

#[test]
fn insertion_order_does_not_change_context() -> Result<(), Box<dyn Error>> {
    let docs = (0..32)
        .map(|id| {
            Document::new(
                format!("n{id:02}"),
                format!("src/{id}"),
                format!("retry tenant boundary {id}"),
            )
        })
        .collect::<Vec<_>>();
    let mut first = graph()?;
    let mut second = graph()?;
    for doc in &docs {
        first.upsert(doc.clone())?;
    }
    for doc in docs.iter().rev() {
        second.upsert(doc.clone())?;
    }
    assert_eq!(
        first.compile(&request("retry tenant"), &Utf8ByteCounter)?,
        second.compile(&request("retry tenant"), &Utf8ByteCounter)?
    );
    Ok(())
}

#[test]
fn extraction_retains_neighbor_lines_and_exact_provenance() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("a","src/file","heading\nnoise\nbackground\nprior condition\nretry MUST keep identity\nexception detail\nnoise\nfooter"))?;
    let mut query = request("retry");
    query.excerpt_mode = ExcerptMode::QueryWindows;
    let context = graph.compile(&query, &Utf8ByteCounter)?;
    let block = context.blocks().first().ok_or("missing block")?;
    assert_eq!(
        block.text,
        "prior condition\nretry MUST keep identity\nexception detail"
    );
    let citation = block.citations.first().ok_or("missing citation")?;
    assert_eq!((citation.start_line, citation.end_line), (4, 6));
    let mut full = request("retry");
    full.excerpt_mode = ExcerptMode::Full;
    assert!(
        graph
            .compile(&full, &Utf8ByteCounter)?
            .render()
            .contains("footer")
    );
    Ok(())
}

#[test]
fn hard_targets_are_never_left_as_previous_excerpts() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new(
        "a",
        "a",
        "header\nnoise\nnoise\nretry\nnoise\nnoise\nCRITICAL_END",
    ))?;
    graph.upsert(Document::new("b", "b", "boundary operation"))?;
    graph.link("b", "a", EdgeKind::Requires)?;
    let mut query = request("retry boundary");
    query.excerpt_mode = ExcerptMode::QueryWindows;
    let context = graph.compile(&query, &Utf8ByteCounter)?;
    assert!(context.render().contains("CRITICAL_END"));
    Ok(())
}

#[test]
fn exact_duplicate_text_keeps_both_required_citations() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    for id in ["a", "b"] {
        graph.upsert(Document::new(id, format!("src/{id}"), "same evidence"))?;
    }
    let mut request = request("evidence");
    request.required = BTreeSet::from(["a".into(), "b".into()]);
    let context = graph.compile(&request, &Utf8ByteCounter)?;
    assert_eq!(context.blocks().len(), 1);
    assert_eq!(ids(&context).len(), 2);
    context.verify(&Utf8ByteCounter)?;
    Ok(())
}

#[test]
fn deltas_reconstruct_withdrawals_and_reject_wrong_bases_and_policy_changes()
-> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("a", "a", "retry operation"))?;
    graph.upsert(Document::new("b", "b", "tenant boundary"))?;
    let request = request("retry operation tenant boundary");
    let first = graph.compile(&request, &Utf8ByteCounter)?;
    graph.remove("a")?;
    graph.upsert(Document::new("c", "c", "retry new implementation"))?;
    let second = graph.compile(&request, &Utf8ByteCounter)?;
    let delta = second.delta_from(&first, &Utf8ByteCounter)?;
    assert_eq!(delta.apply(&first, &Utf8ByteCounter)?, second);
    assert!(!ids(&second).contains("a"));
    assert_eq!(
        delta.apply(&second, &Utf8ByteCounter).err(),
        Some(ContextError::BaseMismatch)
    );
    let mut changed = request;
    changed.policy_revision = "policy2".into();
    let next = graph.compile(&changed, &Utf8ByteCounter)?;
    assert_eq!(
        next.delta_from(&second, &Utf8ByteCounter).err(),
        Some(ContextError::BaseMismatch)
    );
    Ok(())
}

#[test]
fn corrupted_text_and_extra_delta_blocks_are_rejected() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("a", "a", "retry"))?;
    let first = graph.compile(&request("retry"), &Utf8ByteCounter)?;
    let mut serialized = serde_json::to_string(&first)?;
    serialized = serialized.replace("retry", "CORRUPTED");
    let corrupt: ContextSnapshot = serde_json::from_str(&serialized)?;
    assert_eq!(
        corrupt.verify(&Utf8ByteCounter),
        Err(ContextError::Integrity)
    );
    let unchanged = first.delta_from(&first, &Utf8ByteCounter)?;
    assert_eq!(unchanged.added_blocks(), 0);
    assert_eq!(unchanged.apply(&first, &Utf8ByteCounter)?, first);
    let mut value = serde_json::to_value(&unchanged)?;
    *value.get_mut("added").ok_or("missing added")? = serde_json::to_value(first.blocks())?;
    let extra: ContextDelta = serde_json::from_value(value)?;
    assert_eq!(
        extra.apply(&first, &Utf8ByteCounter).err(),
        Some(ContextError::Integrity)
    );
    Ok(())
}

#[test]
fn semantic_seeds_recover_nonlexical_evidence_but_never_grant_access() -> Result<(), Box<dyn Error>>
{
    let mut graph = graph()?;
    graph.upsert(Document::new(
        "a",
        "design",
        "The custodian renews its lease every twenty seconds.",
    ))?;
    let mut query = request("leader heartbeat frequency");
    assert!(graph.compile(&query, &Utf8ByteCounter)?.blocks().is_empty());
    query.semantic_candidates.push("a".into());
    assert_eq!(
        ids(&graph.compile(&query, &Utf8ByteCounter)?),
        BTreeSet::from(["a".into()])
    );
    query.allowed = Some(BTreeSet::new());
    assert!(graph.compile(&query, &Utf8ByteCounter)?.blocks().is_empty());
    query.semantic_candidates.push("a".into());
    assert_eq!(
        graph.compile(&query, &Utf8ByteCounter).err(),
        Some(ContextError::InvalidInput)
    );
    Ok(())
}

#[test]
fn symbol_queries_prefer_definitions_over_short_mentions_and_keep_full_text_by_default()
-> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new(
        "mention",
        "notes",
        "resolve_reference_tokenizer_target fingerprint",
    ))?;
    graph.upsert(Document::new("definition", "src/tokenizer.rs",
        "pub fn resolve_reference_tokenizer_target(target: &Target) {\n    // Validate both the provider and fingerprint.\n    reject_mismatch(target);\n}\n"))?;
    let query = request("resolve_reference_tokenizer_target fingerprint");
    let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
    assert!(ids(&snapshot).contains("definition"));
    assert!(snapshot.render().contains("reject_mismatch(target)"));
    assert_eq!(ContextRequest::default().excerpt_mode, ExcerptMode::Full);
    Ok(())
}

#[test]
fn copied_text_does_not_count_as_independent_corroboration() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    graph.upsert(Document::new("a", "src/a", "retry identity"))?;
    graph.upsert(Document::new("b", "src/b", "retry identity"))?;
    graph.upsert(Document::new(
        "c",
        "src/c",
        "retry identity is asserted by a separate integration test",
    ))?;
    let mut query = request("retry identity");
    query.evidence_per_term = 2;
    let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
    assert_eq!(ids(&snapshot), BTreeSet::from(["a".into(), "c".into()]));
    Ok(())
}

#[test]
fn oversized_optional_closures_do_not_hide_other_usable_evidence() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    for id in ["a", "b", "c", "d", "z"] {
        graph.upsert(Document::new(id, id, "retry"))?;
    }
    graph.link("a", "b", EdgeKind::Requires)?;
    graph.link("b", "c", EdgeKind::Requires)?;
    graph.link("c", "d", EdgeKind::Requires)?;
    let mut query = request("retry");
    query.max_candidates = 2;
    query.max_blocks = 2;
    query.graph_depth = 0;
    let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
    assert!(snapshot.blocks().is_empty());
    assert_eq!(snapshot.stats().limit_rejected_roots, 2);
    query.allowed = Some(BTreeSet::from([
        "a".into(),
        "b".into(),
        "c".into(),
        "d".into(),
        "z".into(),
    ]));
    query.semantic_candidates.push("z".into());
    let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
    assert!(ids(&snapshot).contains("z"));
    query.required.insert("a".into());
    assert_eq!(
        graph.compile(&query, &Utf8ByteCounter).err(),
        Some(ContextError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn whitespace_only_documents_are_rejected_before_index_mutation() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    for text in ["", "\n", " \t\r\n"] {
        assert_eq!(
            graph.upsert(Document::new("a", "retry", text)),
            Err(ContextError::InvalidInput)
        );
    }
    assert_eq!(graph.revision(), 0);
    assert!(graph.is_empty());
    Ok(())
}

#[test]
fn chunked_sources_preserve_unicode_line_terminators_and_original_offsets()
-> Result<(), Box<dyn Error>> {
    let document = Document::new(
        "file",
        "src/retry.rs",
        "header\r\nprior\r\nretry café\r\nexception 日本語\r\nfooter\r\n",
    );
    let chunks = document.chunks(3, 1)?;
    assert_eq!(chunks.len(), 2);
    assert_eq!(
        chunks.first().ok_or("first chunk")?.text,
        "header\r\nprior\r\nretry café\r\n"
    );
    assert_eq!(chunks.get(1).ok_or("second chunk")?.start_line, 3);
    let mut graph = graph()?;
    for doc in &chunks {
        graph.upsert(doc.clone())?;
    }
    let mut query = request("日本語");
    query.excerpt_mode = ExcerptMode::Full;
    let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
    let block = snapshot.blocks().first().ok_or("block")?;
    let citation = block.citations.first().ok_or("citation")?;
    assert_eq!((citation.start_line, citation.end_line), (3, 5));
    assert_eq!(block.text, "retry café\r\nexception 日本語\r\nfooter\r\n");
    assert_eq!(
        document.chunks(1, 1).err(),
        Some(ContextError::InvalidInput)
    );
    let mut overflowing = Document::new("overflow", "source", "first\nsecond");
    overflowing.start_line = usize::MAX;
    assert_eq!(graph.upsert(overflowing), Err(ContextError::LimitExceeded));
    Ok(())
}

#[test]
fn generated_graphs_preserve_order_budget_authorization_and_hard_closure()
-> Result<(), Box<dyn Error>> {
    for seed in 0_usize..128 {
        let mut first = graph()?;
        let mut second = graph()?;
        let docs = (0..24).map(|i| Document::new(format!("n{i:02}"), format!("source/{i}"),
            format!("concept{}\nprior condition\nidentity MUST remain stable for {i}\nexception {seed}", (i+seed)%7)))
            .collect::<Vec<_>>();
        for doc in &docs {
            first.upsert(doc.clone())?;
        }
        for doc in docs.iter().rev() {
            second.upsert(doc.clone())?;
        }
        let edges = (0..24)
            .filter_map(|i| {
                let target = (i * 7 + seed) % 24;
                (target != i).then(|| {
                    (
                        format!("n{i:02}"),
                        format!("n{target:02}"),
                        if i % 3 == 0 {
                            EdgeKind::Requires
                        } else {
                            EdgeKind::Supports
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        for (a, b, kind) in &edges {
            first.link(a, b, *kind)?;
        }
        for (a, b, kind) in edges.iter().rev() {
            second.link(a, b, *kind)?;
        }
        let query = ContextRequest {
            max_tokens: 100 + seed * 17,
            query: format!("concept{} identity", seed % 7),
            allowed: Some(
                docs.iter()
                    .enumerate()
                    .filter(|(i, _)| (i + seed) % 5 != 0)
                    .map(|(_, d)| d.id.clone())
                    .collect(),
            ),
            ..ContextRequest::default()
        };
        let snapshot = first.compile(&query, &Utf8ByteCounter)?;
        assert_eq!(snapshot, second.compile(&query, &Utf8ByteCounter)?);
        snapshot.verify(&Utf8ByteCounter)?;
        let selected = ids(&snapshot);
        assert!(
            query
                .allowed
                .as_ref()
                .is_some_and(|allowed| selected.is_subset(allowed))
        );
        for (from, to, kind) in &edges {
            if *kind == EdgeKind::Requires && selected.contains(from) {
                assert!(selected.contains(to));
                let doc = docs
                    .iter()
                    .find(|doc| &doc.id == to)
                    .ok_or("missing target")?;
                assert!(snapshot.blocks().iter().any(|block| block.text == doc.text));
            }
        }
    }
    Ok(())
}

#[test]
fn withdrawn_edge_retention_is_globally_bounded_and_explicitly_reclaimable()
-> Result<(), Box<dyn Error>> {
    let mut graph = ContextGraph::new(
        "churn",
        GraphLimits {
            max_edges: 2,
            ..GraphLimits::default()
        },
    )?;
    for id in ["a", "b", "c"] {
        graph.upsert(Document::new(id, id, "retry"))?;
    }
    graph.link("a", "b", EdgeKind::Contradicts)?;
    graph.remove("b")?;
    let revision = graph.revision();
    assert_eq!(
        graph.link("a", "c", EdgeKind::Requires),
        Err(ContextError::LimitExceeded)
    );
    assert_eq!(graph.revision(), revision);
    assert!(graph.unlink("a", "b", EdgeKind::Contradicts)?);
    assert!(graph.link("a", "c", EdgeKind::Contradicts)?);
    Ok(())
}

#[test]
fn failed_mutations_are_atomic() -> Result<(), Box<dyn Error>> {
    let mut graph = ContextGraph::new(
        "local",
        GraphLimits {
            max_document_bytes: 20,
            max_edges_per_document: 1,
            ..GraphLimits::default()
        },
    )?;
    for id in ["a", "b", "c"] {
        graph.upsert(Document::new(id, id, "retry"))?;
    }
    graph.link("a", "b", EdgeKind::Requires)?;
    let revision = graph.revision();
    assert_eq!(
        graph.link("c", "a", EdgeKind::Contradicts),
        Err(ContextError::LimitExceeded)
    );
    assert_eq!(
        graph.upsert(Document::new("a", "a", "this string exceeds twenty bytes")),
        Err(ContextError::LimitExceeded)
    );
    assert_eq!(revision, graph.revision());
    assert!(!graph.unlink("c", "a", EdgeKind::Contradicts)?);
    Ok(())
}

#[test]
fn special_text_is_quoted_and_debug_does_not_dump_documents() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    let doc = Document::new(
        "a",
        "source\"quote",
        "retry <|endoftext|> \"SECRET_CONTENT\" \\ boundary",
    );
    assert!(!format!("{doc:?}").contains("SECRET_CONTENT"));
    graph.upsert(doc)?;
    let context = graph.compile(&request("retry"), &Utf8ByteCounter)?;
    let line: serde_json::Value = serde_json::from_str(&context.render())?;
    assert!(
        line.get("text")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| text.contains("SECRET_CONTENT"))
    );
    assert!(!format!("{context:?}").contains("SECRET_CONTENT"));
    Ok(())
}

#[test]
fn budgets_include_framing_and_reserve_for_every_success() -> Result<(), Box<dyn Error>> {
    let mut graph = graph()?;
    for id in 0..20 {
        graph.upsert(Document::new(
            format!("d{id}"),
            format!("file{id}"),
            format!("retry boundary evidence {id}"),
        ))?;
    }
    for budget in 1..512 {
        let mut query = request("retry boundary evidence");
        query.max_tokens = budget + 5;
        query.reserve_tokens = 5;
        let snapshot = graph.compile(&query, &Utf8ByteCounter)?;
        assert!(snapshot.render().len() <= budget);
        snapshot.verify(&Utf8ByteCounter)?;
    }
    Ok(())
}

#[cfg(feature = "bpe")]
#[test]
fn bpe_counts_actual_rendered_text_and_treats_special_tokens_as_data() -> Result<(), Box<dyn Error>>
{
    let tokenizer = cigar_context::O200kTokenizer::new()?;
    let mut graph = graph()?;
    graph.upsert(Document::new("a", "a", "retry café 日本語 <|endoftext|>"))?;
    for max_tokens in 1..80 {
        let query = ContextRequest {
            max_tokens,
            ..request("retry")
        };
        let snapshot = graph.compile(&query, &tokenizer)?;
        assert_eq!(
            snapshot.stats().rendered_tokens,
            tokenizer.count(&snapshot.render())?
        );
        assert!(snapshot.stats().rendered_tokens <= max_tokens);
        snapshot.verify(&tokenizer)?;
    }
    Ok(())
}
