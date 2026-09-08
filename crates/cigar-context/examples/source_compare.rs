//! Real-source symbol retrieval and synthetic index-size diagnostics. No model or remote service.
use cigar_context::{
    ContextGraph, ContextRequest, Document, ExcerptMode, GraphLimits, O200kTokenizer, TokenCounter,
};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Instant;
mod support;
use support::{Bm25Index, bm25, render};

fn source_files(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            source_files(&entry.path(), paths)?;
        } else if kind.is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            if paths.len() >= 2048 {
                return Err("source file limit".into());
            }
            paths.push(entry.path());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let smoke = std::env::args().any(|arg| arg == "--smoke");
    let (trials, warmups) = if smoke { (1, 0) } else { (25, 5) };
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("pass the exact baseline repository path")?,
    )
    .canonicalize()?;
    let mut paths = Vec::new();
    for package in [
        "cigar-compiler",
        "cigar-policy",
        "cigar-retrieval",
        "cigar-protocol",
    ] {
        source_files(&root.join("crates").join(package).join("src"), &mut paths)?;
    }
    paths.sort();
    let mut docs = Vec::new();
    let mut source_bindings = Vec::new();
    use sha2::{Digest, Sha256};
    for (id, path) in paths.iter().enumerate() {
        let text = std::fs::read_to_string(path)?;
        let source = path.strip_prefix(&root)?.to_str().ok_or("UTF-8 path")?;
        let checksum = Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        source_bindings
            .push(serde_json::json!({"source":source,"sha256":checksum,"bytes":text.len()}));
        let document = Document::new(format!("file{id:03}"), source, text);
        docs.extend(document.chunks(80, 8)?);
    }
    let started = Instant::now();
    let tokenizer = O200kTokenizer::new()?;
    let tokenizer_init_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let mut graph = ContextGraph::new("frozen-source", GraphLimits::default())?;
    for doc in &docs {
        graph.upsert(doc.clone())?;
    }
    let graph_index_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let lexical = Bm25Index::new(&docs, false);
    let bm25_index_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let identifier_lexical = Bm25Index::new(&docs, true);
    let bm25_identifier_index_ns = started.elapsed().as_nanos();
    let all = render(&docs.iter().collect::<Vec<_>>())?;
    let full_tokens = tokenizer.count(&all)?;
    // Symbol discovery probes, not task-answer accuracy labels. No graph edge is derived from gold.
    let cases = [
        (
            "cache isolation",
            "invalidate_scope tenant disclosure domain cache",
            "pub fn invalidate_scope",
        ),
        (
            "tokenizer binding",
            "resolve_reference_tokenizer_target provider fingerprint",
            "pub fn resolve_reference_tokenizer_target",
        ),
        (
            "delta verification",
            "apply_delta_verified target bundle digest",
            "pub fn apply_delta_verified",
        ),
        (
            "capability chain",
            "verify_chain capability parent attenuation",
            "pub fn verify_chain",
        ),
        (
            "redaction pointers",
            "redact parse_pointer invalid pointer",
            "fn parse_pointer",
        ),
        (
            "vector neighbors",
            "neighbors cosine vector partition",
            "fn neighbors",
        ),
        (
            "exact counting",
            "count_exact UTF8 tokenizer fingerprint",
            "fn count_exact",
        ),
        (
            "packing closures",
            "pack_positive_marginal closure utility",
            "fn pack_positive_marginal",
        ),
    ];
    let mut rows = Vec::new();
    for (case, query, fact) in cases {
        if !all.contains(fact) {
            return Err("probe symbol missing from frozen corpus".into());
        }
        for trial in 0..trials {
            for offset in 0..4 {
                let treatment = (trial + offset) % 4;
                let started = Instant::now();
                let (label, text) = if treatment == 0 {
                    (
                        "no_cigar_bm25",
                        render(&bm25(&lexical, &docs, query, &tokenizer, 2048)?)?,
                    )
                } else if treatment == 3 {
                    (
                        "no_cigar_bm25_identifiers",
                        render(&bm25(&identifier_lexical, &docs, query, &tokenizer, 2048)?)?,
                    )
                } else {
                    let request = ContextRequest {
                        query: query.into(),
                        max_tokens: 2048,
                        excerpt_mode: if treatment == 1 {
                            ExcerptMode::QueryWindows
                        } else {
                            ExcerptMode::Full
                        },
                        ..ContextRequest::default()
                    };
                    (
                        if treatment == 1 {
                            "cigar_windows"
                        } else {
                            "cigar_full_chunks"
                        },
                        graph.compile(&request, &tokenizer)?.render(),
                    )
                };
                let latency = started.elapsed().as_nanos();
                let tokens = tokenizer.count(&text)?;
                if trial >= warmups {
                    rows.push(serde_json::json!({"case":case,"treatment":label,"trial":trial-warmups,
                    "tokens":tokens,"latency_ns":latency,"symbol_found":text.contains(fact),"budget_fits":tokens<=2048}));
                }
            }
        }
    }
    let mut scale = Vec::new();
    for size in [1000, 10_000, 50_000].into_iter().filter(|_| !smoke) {
        let mut graph = ContextGraph::new("scale", GraphLimits::default())?;
        let started = Instant::now();
        for id in 0..size {
            graph.upsert(Document::new(
                format!("n{id}"),
                format!("source/{id}"),
                format!("shared concept evidence item{id} identity boundary"),
            ))?;
        }
        let build = started.elapsed().as_nanos();
        for query in [
            format!("item{}", size / 2),
            "shared concept identity".into(),
        ] {
            for trial in 0..25 {
                let request = ContextRequest {
                    query: query.clone(),
                    max_tokens: 512,
                    ..ContextRequest::default()
                };
                let started = Instant::now();
                let snapshot = graph.compile(&request, &tokenizer)?;
                let elapsed = started.elapsed().as_nanos();
                if trial >= 5 {
                    scale.push(
                        serde_json::json!({"documents":size,"build_ns":build,"query":query,
                    "trial":trial-5,"latency_ns":elapsed,"tokens":snapshot.stats().rendered_tokens,
                    "candidates":snapshot.stats().candidates}),
                    );
                }
            }
        }
        let before = graph.compile(
            &ContextRequest {
                query: "item0".into(),
                ..ContextRequest::default()
            },
            &tokenizer,
        )?;
        let started = Instant::now();
        graph.upsert(Document::new(
            "n0",
            "source/0",
            "item0 CHANGED boundary contract",
        ))?;
        let update = started.elapsed().as_nanos();
        let after = graph.compile(
            &ContextRequest {
                query: "item0".into(),
                ..ContextRequest::default()
            },
            &tokenizer,
        )?;
        let delta = after.delta_from(&before, &tokenizer)?;
        assert_eq!(delta.apply(&before, &tokenizer)?, after);
        assert!(after.render().contains("CHANGED"));
        scale.push(
            serde_json::json!({"documents":size,"update_ns":update,"changed_delta_verified":true}),
        );
    }
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({"schema":"cigar.source-evaluation.v1",
        "tokenizer":tokenizer.identity(),"source_bindings":source_bindings,"files":paths.len(),"chunks":docs.len(),
        "full_context_tokens":full_tokens,"tokenizer_init_ns":tokenizer_init_ns,"graph_index_ns":graph_index_ns,
        "bm25_index_ns":bm25_index_ns,"bm25_identifier_index_ns":bm25_identifier_index_ns,"observations":rows,"scale":scale,
        "limitations":"Symbol discovery probes on real source; no task-answer or model quality inference. No explicit graph edges in this corpus. Shared text/chunks for both retrievers."}))?
    );
    Ok(())
}
