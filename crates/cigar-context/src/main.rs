//! JSON-in/JSON-out local context compilation; no network or implicit filesystem ingestion.
use cigar_context::{
    ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, O200kTokenizer,
};
use serde::Deserialize;
use std::error::Error;
use std::io::{Read, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    domain: String,
    documents: Vec<Document>,
    #[serde(default)]
    edges: Vec<(String, String, EdgeKind)>,
    request: ContextRequest,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--version"] {
        println!("cigar-context {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if arguments.as_slice() == ["--help"] {
        println!(
            "cigar-context: read one JSON object from stdin; write a verified context snapshot.\nFields: domain, documents [id/source/text], edges [[from,to,kind]], request [query/max_tokens/...].\nTokenizer: o200k_base; all input is ordinary data. Maximum input: 32 MiB."
        );
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err("use --help, --version, or JSON on stdin".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("input exceeds 32 MiB".into());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| "invalid context input JSON")?;
    let mut graph = ContextGraph::new(input.domain, GraphLimits::default())?;
    let mut ids = std::collections::BTreeSet::new();
    for document in input.documents {
        if !ids.insert(document.id.clone()) {
            return Err("duplicate document ID in input".into());
        }
        graph.upsert(document)?;
    }
    for (from, to, kind) in input.edges {
        graph.link(&from, &to, kind)?;
    }
    let tokenizer = O200kTokenizer::new()?;
    let snapshot = graph.compile(&input.request, &tokenizer)?;
    snapshot.verify(&tokenizer)?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &snapshot)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
