//! Authored-corpus comparison with independent full-context and BM25 baselines.
use cigar_context::{
    ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, O200kTokenizer, TokenCounter,
};
use serde::Deserialize;
use std::collections::BTreeSet;
mod support;
use std::error::Error;
use std::time::Instant;
use support::{Bm25Index, bm25, render, words};

#[derive(Deserialize)]
struct Case {
    id: String,
    query: String,
    facts: Vec<String>,
    documents: Vec<(String, String, String)>,
    edges: Vec<(String, String, EdgeKind)>,
    evidence_per_term: Option<usize>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cases: Vec<Case> = serde_json::from_str(include_str!("../fixtures/quality.json"))?;
    let tokenizer = O200kTokenizer::new()?;
    let mut observations = Vec::new();
    let mut legacy_inputs = Vec::new();
    for case in cases {
        let mut docs = case
            .documents
            .iter()
            .map(|(id, source, text)| Document::new(id, source, text))
            .collect::<Vec<_>>();
        for id in 0..24 {
            docs.push(Document::new(format!("noise-{id:02}"),format!("archive/note-{id:02}.md"),
                format!("Archived note {id}.\n{}", "Display panels use muted colors. Screens resize smoothly. Historical release notes list past events.\n".repeat(12))));
        }
        let mut graph = ContextGraph::new("evaluation", GraphLimits::default())?;
        for doc in &docs {
            graph.upsert(doc.clone())?;
        }
        for (from, to, kind) in &case.edges {
            graph.link(from, to, *kind)?;
        }
        let bm25_index = Bm25Index::new(&docs, false);
        let request = ContextRequest {
            query: case.query.clone(),
            max_tokens: 512,
            evidence_per_term: case.evidence_per_term.unwrap_or(1),
            ..ContextRequest::default()
        };
        let relevant = docs
            .iter()
            .filter(|doc| {
                case.facts
                    .iter()
                    .any(|fact| doc.text.to_lowercase().contains(&fact.to_lowercase()))
            })
            .map(|doc| doc.id.clone())
            .collect::<BTreeSet<_>>();
        let query_words = words(&case.query).into_iter().collect::<BTreeSet<_>>();
        let legacy_docs = docs.iter().map(|doc| {
            let tokens = tokenizer.count(&render(&[doc])?)?;
            let matches = words(&format!("{} {}",doc.source,doc.text)).into_iter().collect::<BTreeSet<_>>();
            let bits = query_words.iter().enumerate().fold(0_u64, |bits,(index,word)|
                if matches.contains(word) { bits | (1_u64 << index) } else { bits });
            Ok(serde_json::json!({"id":doc.id,"tokens":tokens,"bits":bits,"source":doc.source,"text":doc.text}))
        }).collect::<Result<Vec<_>,Box<dyn Error>>>()?;
        legacy_inputs.push(
            serde_json::json!({"id":case.id,"query":case.query,"budget":512,
            "documents":legacy_docs,"edges":case.edges,"facts":case.facts}),
        );
        for trial in 0..35 {
            for offset in 0..3 {
                let treatment = (trial + offset) % 3;
                let start = Instant::now();
                let (name, text, selected) = match treatment {
                    0 => {
                        let selected = docs.iter().collect::<Vec<_>>();
                        (
                            "no_cigar_full",
                            render(&selected)?,
                            selected
                                .iter()
                                .map(|d| d.id.clone())
                                .collect::<BTreeSet<_>>(),
                        )
                    }
                    1 => {
                        let selected = bm25(&bm25_index, &docs, &case.query, &tokenizer, 512)?;
                        (
                            "no_cigar_bm25",
                            render(&selected)?,
                            selected
                                .iter()
                                .map(|d| d.id.clone())
                                .collect::<BTreeSet<_>>(),
                        )
                    }
                    _ => {
                        let snapshot = graph.compile(&request, &tokenizer)?;
                        (
                            "cigar_context_0.10.0",
                            snapshot.render(),
                            snapshot
                                .blocks()
                                .iter()
                                .flat_map(|b| b.citations.iter().map(|c| c.node_id.clone()))
                                .collect(),
                        )
                    }
                };
                let elapsed = start.elapsed().as_nanos();
                let tokens = tokenizer.count(&text)?;
                let (bytes, delta_bytes) = if treatment == 2 {
                    let snapshot = graph.compile(&request, &tokenizer)?;
                    let delta = snapshot.delta_from(&snapshot, &tokenizer)?;
                    assert_eq!(delta.apply(&snapshot, &tokenizer)?, snapshot);
                    (
                        serde_json::to_vec(&snapshot)?.len(),
                        serde_json::to_vec(&delta)?.len(),
                    )
                } else {
                    (0, 0)
                };
                let found = case
                    .facts
                    .iter()
                    .filter(|fact| text.to_lowercase().contains(&fact.to_lowercase()))
                    .count();
                if trial >= 5 {
                    observations.push(serde_json::json!({"case":case.id,"treatment":name,"trial":trial-5,
                    "tokens":tokens,"latency_ns":elapsed,"facts_found":found,"facts_required":case.facts.len(),
                    "answerable":found==case.facts.len(),"budget_fits":tokens<=512,
                    "selected_documents":selected.len(),"relevant_documents":relevant.len(),
                    "selected_relevant_documents":selected.intersection(&relevant).count(),
                    "snapshot_bytes":bytes,"unchanged_delta_bytes":delta_bytes}));
                }
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({"schema":"cigar.context-evaluation.v1",
        "tokenizer":tokenizer.identity(),"warmups":5,"trials":30,"budget":512,
        "corpus":"authored quality.json plus 24 fixed distractors per case; not held-out or live-model evidence",
        "observations":observations,"legacy_inputs":legacy_inputs}))?
    );
    Ok(())
}
