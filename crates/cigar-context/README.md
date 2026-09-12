# cigar-context 0.10.1

A small offline Rust library for incremental context graphs, bounded retrieval, exact rendered
token budgets, source citations, and verified context deltas. No daemon, database, model service,
or external graph builder is required. Version 0.10.1 improves common-term scoring and
incremental source updates. The source crate is prepared separately from registry publication.

```rust
use cigar_context::{ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, Utf8ByteCounter};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut graph = ContextGraph::new("my-local-project", GraphLimits::default())?;
graph.upsert(Document::new("retry", "src/retry.rs", "Retry only idempotent operations."))?;
graph.upsert(Document::new("contract", "docs/api.md", "A retry must keep the original operation ID."))?;
graph.link("retry", "contract", EdgeKind::Requires)?;
let request = ContextRequest { query: "idempotent retry".into(), max_tokens: 2000,
    ..ContextRequest::default() };
let snapshot = graph.compile(&request, &Utf8ByteCounter)?;
snapshot.verify(&Utf8ByteCounter)?;
println!("{}", snapshot.render());
# Ok(())
# }
```

`Utf8ByteCounter` measures bytes, not model tokens. Enable feature `bpe` and use
`O200kTokenizer::new()` for actual o200k_base text tokens; reuse the tokenizer between requests.
Other tokenizers implement the two-method `TokenCounter` trait. The final rendered context,
including source references and JSON escaping, must fit `max_tokens - reserve_tokens`. Reserve
space for the caller's system prompt, chat envelope, previous turns, and desired model output.

`Requires` edges retain complete dependency text. `Contradicts` is symmetric and retains both
sides, including their dependencies. Optional `Supports` and `Related` edges expand search within
the depth/candidate limit. Hard cycles form one jointly required closure; missing or unauthorized
hard dependencies make an optional root unavailable and cause required roots to return an error.
Removing a document keeps incoming edges so withdrawn evidence cannot silently disappear from a
dependent proof. Use `unlink` explicitly when the application changes the dependency contract.

Full source text is the default. Optional `ExcerptMode::QueryWindows` is extractive and retains neighboring source lines, with omission markers
and exact source ranges. They are not guaranteed to preserve every implication of the full source.
Use `ExcerptMode::Full` or mark the source required for code that must remain syntactically complete,
critical instructions, or evidence that cannot tolerate extraction. Identical selected text is
coalesced while all selected provenance references remain available.

`snapshot.prompt_view(max_tokens, &tokenizer)` optionally renders the same selected text
with short handles (`c1`, `c2`, …) and source ranges. Keep the full snapshot and returned
`ContextPrompt` together. `prompt.verify(&snapshot, &tokenizer)` reconstructs and checks the
entire view; `prompt.resolve("c1", &snapshot, &tokenizer)` returns the original citations.
The expected snapshot must come from the application's current authorized compilation.
This separate rendering never changes the original snapshot, silently truncates source text,
or omits hard dependencies. Its own exact budget excludes provider framing. Token savings
depend on citation overhead and are not guaranteed for every input.

Applications with an embedding index can pass ranked node IDs in `semantic_candidates`. This
extends retrieval to synonyms and paraphrases without coupling the library to a model, vector
database, similarity scale, or paid API. IDs still pass the authorization filter and hard-closure
checks. Lexical coverage statistics are not semantic confidence scores. Set `evidence_per_term`
to 2–4 when independent corroboration matters; exact copied text is not counted as a second witness.
Graph edges and semantic leads must come from your application's trusted ingestion/retrieval path;
the library does not discover factual contradictions automatically.

The lexical index retains complete snake_case/camelCase identifiers alongside their components.
Named code declarations receive priority over mere mentions when the query names them. This is
a lexical relevance hint, not a syntax parser or a grant of authority; declarations, like all
other evidence, must pass the caller's access filter and complete dependency checks.

`document.chunks(80, 8)` splits supplied source text into overlapping line chunks with original
file offsets in every citation. For existing symbol-aware ingestion, set `Document::start_line`
directly. No file is implicitly opened. Line chunks are not syntactically complete AST nodes;
retain full symbols and attach `Requires` links when code correctness needs complete definitions.
After edits, withdraw obsolete chunk IDs before compiling new snapshots to avoid stale evidence.

Use `graph.replace_source("src/file.rs", document.chunks(80, 8)?)` to do that atomically. It
replaces exactly that locator's documents, retains identical IDs, and withdraws obsolete chunks.
An empty vector withdraws the source. Invalid input, ID collisions with another source, or final
capacity violations leave the graph untouched. A changed batch advances revision once; identical
batches do not. Hard edges to removed chunks deliberately remain unavailable until repaired.
Staging needs additional memory proportional to the replacement source, not a clone of the graph.

### Exact counting and repeated requests

`O200kTokenizer` uses an instance-local exact-text cache by default: at most 2,048 entries and
8 MiB of retained text, plus bounded entry/allocator overhead. Final complete renderings are still
counted exactly; counts are never estimated or added across blocks. This helps both repeated
requests and repeated checks within one request. Cold requests still perform BPE work.

`O200kTokenizer::with_cache_limits(TokenCacheLimits { max_entries: 0, max_text_bytes: 0 })`
disables caching. `cache_stats()` reports hits, misses, entries and retained text bytes;
`clear_cache()` drops retained strings and resets counters. Keep one tokenizer/cache per privacy
boundary, clear it when retention policy requires, and do not treat deallocation as zeroization.
`CachedTokenCounter::new(custom_counter, limits)` provides the same bounded cache for a custom
immutable tokenizer. Concurrent misses may compute twice; expensive counting does not hold the
cache lock. There is no global cache or additional dependency.

Each graph is local and caller-owned. `allowed` must contain the currently authorized IDs when
access varies within the graph. A graph relation never authorizes its target. Update
`policy_revision` whenever the application's access policy changes. Do not expose this API directly
to an untrusted remote caller or infer authority from a document's text or relevance score.

`next.delta_from(&previous, &tokenizer)` produces a transport delta. Applying it requires exactly
the acknowledged previous snapshot; the reconstructed result is hashed and counted again. Deltas
save transport/storage bytes. An ordinary stateless model still needs the complete reconstructed
context; delta reuse alone does not save model prompt tokens. Snapshots/deltas contain source text
and require the same handling as the source documents. Digests detect corruption, not forgery by
an adversary able to rewrite and rehash the entire object.

Run `cargo test --locked -p cigar-context --features bpe` and
`cargo run --locked -p cigar-context --features bpe --example compare` for verification.
The optional `cigar-context` JSON CLI reads explicit documents from stdin; `--help` describes its
input. The existing Honey daemon/SDK ABI and release artifacts remain separate from this library.

From this source checkout:

```sh
python3 scripts/dev.py context
cargo run --locked -p cigar-context --features bpe --bin cigar-context -- --help
```

Example stdin (one object, not a path to be implicitly ingested):

```json
{"domain":"my-project","documents":[{"id":"retry","source":"src/retry.rs","text":"Retry only idempotent operations."},{"id":"contract","source":"docs/api.md","text":"Retain the original operation ID."}],"edges":[["retry","contract","requires"]],"request":{"query":"retry","max_tokens":512,"reserve_tokens":64}}
```

The CLI rejects duplicate document IDs. For intentional replacements, use `graph.upsert` in the
Rust API. Reuse an in-memory graph and tokenizer across requests; starting the CLI rebuilds both.
`SelectionStats` reports missing/unauthorized, oversized-closure, and budget-rejected optional
roots. A small or empty result is not evidence that the query is answerable.
