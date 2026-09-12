//! Versioned, bounded stdio bridge. One caller-owned graph/cache per process.
use cigar_context::{
    ContextDelta, ContextError, ContextGraph, ContextPrompt, ContextRequest, ContextSnapshot,
    Document, EdgeKind, GraphLimits, O200kTokenizer, TokenCacheLimits, TokenCounter,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};

const PROTOCOL: &str = "cigar.context-worker.v1";
const MAX_FRAME: usize = 32 * 1024 * 1024;
const MAX_RESPONSE: usize = 64 * 1024 * 1024;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Limits {
    max_documents: Option<usize>,
    max_document_bytes: Option<usize>,
    max_total_bytes: Option<usize>,
    max_edges_per_document: Option<usize>,
    max_edges: Option<usize>,
    cache_entries: Option<usize>,
    cache_text_bytes: Option<usize>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Init {
        domain: String,
        #[serde(default)]
        limits: Limits,
    },
    Upsert {
        document: Document,
    },
    ReplaceSource {
        source: String,
        documents: Vec<Document>,
    },
    Remove {
        node_id: String,
    },
    Link {
        from: String,
        to: String,
        kind: EdgeKind,
    },
    Unlink {
        from: String,
        to: String,
        kind: EdgeKind,
    },
    Compile {
        request: ContextRequest,
    },
    Chunks {
        document: Document,
        max_lines: usize,
        overlap_lines: usize,
    },
    Verify {
        snapshot: ContextSnapshot,
    },
    PromptView {
        snapshot: ContextSnapshot,
        max_tokens: usize,
    },
    VerifyPrompt {
        snapshot: ContextSnapshot,
        prompt: ContextPrompt,
    },
    ResolveCitation {
        snapshot: ContextSnapshot,
        prompt: ContextPrompt,
        reference: String,
    },
    Delta {
        base: ContextSnapshot,
        target: ContextSnapshot,
    },
    ApplyDelta {
        base: ContextSnapshot,
        delta: ContextDelta,
    },
    Stats {},
    ClearCache {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u32,
    command: Command,
}

struct Session {
    graph: ContextGraph,
    tokenizer: O200kTokenizer,
}

impl Session {
    fn new(domain: String, limits: Limits) -> Result<Self, ContextError> {
        let defaults = GraphLimits::default();
        let cache = TokenCacheLimits::default();
        let graph = ContextGraph::new(
            domain,
            GraphLimits {
                max_documents: limits.max_documents.unwrap_or(defaults.max_documents),
                max_document_bytes: limits
                    .max_document_bytes
                    .unwrap_or(defaults.max_document_bytes),
                max_total_bytes: limits.max_total_bytes.unwrap_or(defaults.max_total_bytes),
                max_edges_per_document: limits
                    .max_edges_per_document
                    .unwrap_or(defaults.max_edges_per_document),
                max_edges: limits.max_edges.unwrap_or(defaults.max_edges),
            },
        )?;
        let tokenizer = O200kTokenizer::with_cache_limits(TokenCacheLimits {
            max_entries: limits.cache_entries.unwrap_or(cache.max_entries),
            max_text_bytes: limits.cache_text_bytes.unwrap_or(cache.max_text_bytes),
        })?;
        Ok(Self { graph, tokenizer })
    }

    fn rendered(&self, snapshot: ContextSnapshot) -> Result<Value, ContextError> {
        snapshot.verify(&self.tokenizer)?;
        Ok(json!({"rendered": snapshot.render(), "snapshot": snapshot}))
    }

    fn execute(&mut self, command: Command) -> Result<Value, ContextError> {
        match command {
            Command::Init { .. } => Err(ContextError::InvalidInput),
            Command::Upsert { document } => Ok(json!(self.graph.upsert(document)?)),
            Command::ReplaceSource { source, documents } => {
                Ok(json!(self.graph.replace_source(&source, documents)?))
            }
            Command::Remove { node_id } => Ok(json!(self.graph.remove(&node_id)?)),
            Command::Link { from, to, kind } => Ok(json!(self.graph.link(&from, &to, kind)?)),
            Command::Unlink { from, to, kind } => Ok(json!(self.graph.unlink(&from, &to, kind)?)),
            Command::Compile { request } => {
                self.rendered(self.graph.compile(&request, &self.tokenizer)?)
            }
            Command::Chunks {
                document,
                max_lines,
                overlap_lines,
            } => Ok(json!(document.chunks(max_lines, overlap_lines)?)),
            Command::Verify { snapshot } => self.rendered(snapshot),
            Command::PromptView {
                snapshot,
                max_tokens,
            } => Ok(json!(snapshot.prompt_view(max_tokens, &self.tokenizer)?)),
            Command::VerifyPrompt { snapshot, prompt } => {
                prompt.verify(&snapshot, &self.tokenizer)?;
                Ok(json!(prompt))
            }
            Command::ResolveCitation {
                snapshot,
                prompt,
                reference,
            } => Ok(json!(prompt.resolve(
                &reference,
                &snapshot,
                &self.tokenizer
            )?)),
            Command::Delta { base, target } => {
                Ok(json!(target.delta_from(&base, &self.tokenizer)?))
            }
            Command::ApplyDelta { base, delta } => {
                self.rendered(delta.apply(&base, &self.tokenizer)?)
            }
            Command::Stats {} => {
                let cache = self.tokenizer.cache_stats()?;
                Ok(
                    json!({"documents": self.graph.len(), "revision": self.graph.revision(),
                    "cache": {"hits": cache.hits, "misses": cache.misses,
                        "entries": cache.entries, "text_bytes": cache.text_bytes}}),
                )
            }
            Command::ClearCache {} => {
                self.tokenizer.clear_cache()?;
                Ok(Value::Null)
            }
        }
    }
}

fn handle(session: &mut Option<Session>, command: Command) -> Result<Value, ContextError> {
    if let Some(session) = session {
        return session.execute(command);
    }
    if let Command::Init { domain, limits } = command {
        let value = Session::new(domain, limits)?;
        let reply = json!({"protocol": PROTOCOL, "core_version": env!("CARGO_PKG_VERSION"),
            "tokenizer": value.tokenizer.identity(), "max_frame_bytes": MAX_FRAME,
            "max_response_bytes": MAX_RESPONSE});
        *session = Some(value);
        Ok(reply)
    } else {
        Err(ContextError::InvalidInput)
    }
}

fn run(input: &mut impl BufRead, output: &mut impl Write) -> std::io::Result<()> {
    let mut session = None;
    loop {
        let mut frame = Vec::new();
        let bytes = input
            .take((MAX_FRAME + 1) as u64)
            .read_until(b'\n', &mut frame)?;
        if bytes == 0 {
            return Ok(());
        }
        // Over-limit or unterminated frames invalidate the transport; do not resynchronize.
        if bytes > MAX_FRAME || frame.last() != Some(&b'\n') {
            return Ok(());
        }
        let reply = match serde_json::from_slice::<Request>(&frame) {
            Ok(request) => match handle(&mut session, request.command) {
                Ok(value) => json!({"id": request.id, "ok": true, "result": value}),
                Err(error) => json!({"id": request.id, "ok": false, "error": format!("{error:?}")}),
            },
            // Malformed commands cannot be safely correlated. Close after a content-free error.
            Err(_) => {
                output.write_all(b"{\"id\":null,\"ok\":false,\"error\":\"InvalidInput\"}\n")?;
                output.flush()?;
                return Ok(());
            }
        };
        let mut encoded = serde_json::to_vec(&reply)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_RESPONSE {
            return Ok(());
        }
        output.write_all(&encoded)?;
        output.flush()?;
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--version"] {
        println!(
            "cigar-context-worker {} {PROTOCOL}",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if !args.is_empty() {
        return Err(std::io::Error::other("worker accepts JSONL on stdin only"));
    }
    run(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_fields_without_echoing_input() -> Result<(), Box<dyn std::error::Error>> {
        let input = b"{\"id\":1,\"command\":{\"op\":\"stats\",\"secret\":\"PRIVATE\"}}\n";
        let mut out = Vec::new();
        run(&mut &input[..], &mut out)?;
        assert_eq!(
            out,
            b"{\"id\":null,\"ok\":false,\"error\":\"InvalidInput\"}\n"
        );
        Ok(())
    }
    #[test]
    fn rejects_partial_and_oversized_frames() -> Result<(), Box<dyn std::error::Error>> {
        for input in [b"{}".to_vec(), vec![b' '; MAX_FRAME + 1]] {
            let mut out = Vec::new();
            run(&mut &input[..], &mut out)?;
            assert!(out.is_empty());
        }
        Ok(())
    }
    #[test]
    fn initialization_is_once_and_required() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = None;
        assert_eq!(
            handle(&mut session, Command::Stats {}),
            Err(ContextError::InvalidInput)
        );
        let init = || Command::Init {
            domain: "test".into(),
            limits: Limits::default(),
        };
        assert_eq!(
            handle(&mut session, init())?.get("protocol"),
            Some(&json!(PROTOCOL))
        );
        assert_eq!(
            handle(&mut session, init()),
            Err(ContextError::InvalidInput)
        );
        assert_eq!(
            handle(&mut session, Command::Stats {})?.get("documents"),
            Some(&json!(0))
        );
        Ok(())
    }
}
