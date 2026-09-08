//! Identical-input snapshot and timing adapter for the first and second 0.10.0 candidates.
use cigar_context::{ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, O200kTokenizer};
use serde::Deserialize;
use std::io::{BufRead, Write};
use std::time::Instant;

#[derive(Deserialize)]
struct Case {
    name: String,
    documents: Vec<Document>,
    #[serde(default)] edges: Vec<(String, String, EdgeKind)>,
    #[serde(default)] withdrawals: Vec<String>,
    #[serde(default)] upserts: Vec<Document>,
    requests: Vec<ContextRequest>,
    #[serde(default)] warmups: usize,
    #[serde(default = "one")] trials: usize,
}
fn one() -> usize { 1 }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "warm".into());
    #[cfg(feature = "pass2")]
    let tokenizer = if mode == "uncached" {
        O200kTokenizer::with_cache_limits(cigar_context::TokenCacheLimits { max_entries: 0, max_text_bytes: 0 })?
    } else { O200kTokenizer::new()? };
    #[cfg(not(feature = "pass2"))]
    let tokenizer = O200kTokenizer::new()?;
    let mut output = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let case: Case = serde_json::from_str(&line?)?;
        let started = Instant::now();
        let mut graph = ContextGraph::new("pass2-oracle", GraphLimits::default())?;
        for document in case.documents { graph.upsert(document)?; }
        for (from, to, kind) in case.edges { graph.link(&from, &to, kind)?; }
        for id in case.withdrawals { graph.remove(&id)?; }
        for document in case.upserts { graph.upsert(document)?; }
        let build_ns = started.elapsed().as_nanos();
        for (index, request) in case.requests.iter().enumerate() {
            let mut samples = Vec::new();
            let mut prior = None;
            for trial in 0..case.trials + case.warmups {
                #[cfg(feature = "pass2")]
                if mode == "cold" { tokenizer.clear_cache()?; }
                let started = Instant::now();
                let result = graph.compile(request, &tokenizer);
                let latency = started.elapsed().as_nanos();
                let value = match result {
                    Ok(snapshot) => {
                        snapshot.verify(&tokenizer)?;
                        serde_json::json!({"ok":snapshot})
                    },
                    Err(error) => serde_json::json!({"error":format!("{error:?}")}),
                };
                if let Some(expected) = &prior { assert_eq!(&value, expected); }
                prior = Some(value);
                if trial >= case.warmups { samples.push(latency); }
            }
            writeln!(output, "{}", serde_json::json!({"case":case.name,"request":index,
                "mode":mode,"build_ns":build_ns,"latency_ns":samples,"output":prior}))?;
        }
    }
    Ok(())
}
