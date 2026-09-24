//! Identical-input 0.10.0/0.10.1 qualification. Timers exclude input cloning and verification.
use cigar_context::{ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, O200kTokenizer, TokenCacheLimits};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::time::Instant;

#[derive(Deserialize)]
struct Case {
    name: String,
    documents: Vec<Document>,
    #[serde(default)] edges: Vec<(String, String, EdgeKind)>,
    #[serde(default)] withdrawals: Vec<String>,
    #[serde(default)] upserts: Vec<Document>,
    #[serde(default)] source_updates: Vec<(String, Vec<Document>)>,
    requests: Vec<ContextRequest>,
    #[serde(default)] warmups: usize,
    #[serde(default = "one")] trials: usize,
}
fn one() -> usize { 1 }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "warm".into());
    let tokenizer = if mode == "uncached" {
        O200kTokenizer::with_cache_limits(TokenCacheLimits { max_entries: 0, max_text_bytes: 0 })?
    } else { O200kTokenizer::new()? };
    let mut output = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let case: Case = serde_json::from_str(&line?)?;
        if matches!(mode.as_str(), "rotating" | "updates" | "prompt") && case.name != "real-source" { continue; }
        let started = Instant::now();
        let mut graph = ContextGraph::new("pass2-oracle", GraphLimits::default())?;
        for document in case.documents.iter().cloned() { graph.upsert(document)?; }
        for (from, to, kind) in &case.edges { graph.link(from, to, *kind)?; }
        for id in &case.withdrawals { graph.remove(id)?; }
        for document in case.upserts { graph.upsert(document)?; }
        let mut updates = Vec::new();
        for (source, documents) in case.source_updates {
            updates.push(match graph.replace_source(&source, documents) {
                Ok(value) => json!({"ok":value}), Err(error) => json!({"error":format!("{error:?}")}),
            });
        }
        let build_ns = started.elapsed().as_nanos();
        if mode == "updates" {
            let documents = case.documents.into_iter().map(|mut doc| { doc.source = "ingested.rs".into(); doc }).collect::<Vec<_>>();
            let mut graph = ContextGraph::new("updates-oracle", GraphLimits::default())?;
            graph.replace_source("ingested.rs", documents.clone())?;
            for cycle in 0..40 {
                let mut incoming = documents.clone();
                if cycle >= 20 && cycle % 2 == 0 { incoming[0].text.push_str("\n// changed source\n"); }
                let started = Instant::now();
                let update = graph.replace_source("ingested.rs", incoming)?;
                let ns = started.elapsed().as_nanos();
                let snapshot = graph.compile(&case.requests[0], &tokenizer)?;
                snapshot.verify(&tokenizer)?;
                writeln!(output, "{}", json!({"kind":if cycle<20 {"unchanged"}else{"one-changed"},
                    "cycle":cycle,"latency_ns":ns,"update":update,"snapshot_id":snapshot.id()}))?;
            }
            continue;
        }
        if mode == "rotating" {
            for cycle in 0..12 {
                for (index, request) in case.requests.iter().enumerate() {
                    let before = tokenizer.cache_stats()?;
                    let started = Instant::now();
                    let snapshot = graph.compile(request, &tokenizer)?;
                    let ns = started.elapsed().as_nanos();
                    let after = tokenizer.cache_stats()?;
                    snapshot.verify(&tokenizer)?;
                    if cycle >= 2 { writeln!(output, "{}", json!({"cycle":cycle,"request":index,
                        "latency_ns":ns,"hits":after.hits-before.hits,"misses":after.misses-before.misses,
                        "retained_entries":after.entries,"retained_text_bytes":after.text_bytes,
                        "snapshot_id":snapshot.id(),"rendered_tokens":snapshot.stats().rendered_tokens}))?; }
                }
            }
            continue;
        }
        for (index, request) in case.requests.iter().enumerate() {
            #[cfg(feature = "candidate")]
            if mode == "prompt" {
                let snapshot = graph.compile(request, &tokenizer)?;
                let prompt = snapshot.prompt_view(request.max_tokens, &tokenizer)?;
                prompt.verify(&snapshot, &tokenizer)?;
                writeln!(output, "{}", json!({"request":index,"full_tokens":snapshot.stats().rendered_tokens,
                    "prompt_tokens":prompt.rendered_tokens(),"snapshot_id":snapshot.id(),"prompt":prompt}))?;
                continue;
            }
            let mut samples = Vec::new();
            let mut prior: Option<Value> = None;
            for trial in 0..case.trials + case.warmups {
                if mode == "cold" { tokenizer.clear_cache()?; }
                let started = Instant::now();
                let result = graph.compile(request, &tokenizer);
                let ns = started.elapsed().as_nanos();
                let value = match result {
                    Ok(snapshot) => { snapshot.verify(&tokenizer)?; json!({"ok":snapshot}) },
                    Err(error) => json!({"error":format!("{error:?}")}),
                };
                if let Some(expected) = &prior { assert_eq!(&value, expected); }
                prior = Some(value);
                if trial >= case.warmups { samples.push(ns); }
            }
            writeln!(output, "{}", json!({"case":case.name,"request":index,"mode":mode,
                "build_ns":build_ns,"updates":updates,"latency_ns":samples,"output":prior}))?;
        }
    }
    Ok(())
}
