# hol-cigar: Context Graphs and Exact Token Budgets for AI Agents in Rust

[![crates.io](https://img.shields.io/crates/v/hol-cigar.svg?logo=rust&logoColor=white&label=crates.io)](https://crates.io/crates/hol-cigar)
[![docs.rs](https://img.shields.io/docsrs/hol-cigar?logo=docsdotrs&label=docs.rs)](https://docs.rs/hol-cigar)
[![crates.io downloads](https://img.shields.io/crates/d/hol-cigar.svg?logo=rust&logoColor=white)](https://crates.io/crates/hol-cigar)
[![PyPI](https://img.shields.io/pypi/v/hol-cigar.svg?logo=pypi&logoColor=white&cacheSeconds=300)](https://pypi.org/project/hol-cigar/)
[![npm](https://img.shields.io/npm/v/@hol-org/cigar.svg?logo=npm&logoColor=white)](https://www.npmjs.com/package/@hol-org/cigar)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/hashgraph-online/hol-cigar/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/hashgraph-online/hol-cigar?style=social)](https://github.com/hashgraph-online/hol-cigar/stargazers)

| ![HOL whole dark logo](https://hol.org/brand/Logo_Whole_Dark.png) | **Give AI agents the right context, with citations, inside an exact token budget.** `hol-cigar` is the Rust library behind CIGAR (Context Intelligence Graph Agentic Runtime), the open-source context engineering protocol for AI agents from [HOL](https://hol.org).<br><br>[CIGAR on hol.org](https://hol.org/cigar)<br>[API docs on docs.rs](https://docs.rs/hol-cigar)<br>[Source on GitHub](https://github.com/hashgraph-online/hol-cigar)<br>[Report an Issue](https://github.com/hashgraph-online/hol-cigar/issues) |
| :--- | :--- |

A small offline Rust library for incremental context graphs, bounded retrieval, exact rendered
token budgets, source citations, and verified context deltas. No daemon, database, model service,
or external graph builder is required. `ContextViews` provides scoped sharing over one
`ContextGraph`: a trusted host defines readable/writable source scopes, compiles
scope-bound snapshots and checks reviews without invalidation from outside-scope
writes. All existing root methods and their exact freshness semantics remain.
Version 0.14 also adds an opt-in `broker` feature for authenticated independent processes,
host-owned provenance/admission, bounded scheduling and optional durable recovery.

The same engine powers the [Python](https://pypi.org/project/hol-cigar/) and
[npm](https://www.npmjs.com/package/@hol-org/cigar) CIGAR SDKs.

[Install](#install) · [Quick start](#quick-start) · [Features](#features) · [Token budgets](#token-budgets-and-tokenizers) ·
[Check answers](#check-answers-before-display) · [Worker](#hosting-the-worker-in-your-own-process) ·
[FAQ](#frequently-asked-questions)

## Install

Install it from crates.io as `hol-cigar` and import it as `hol_cigar`:

```toml
[dependencies]
hol-cigar = { version = "0.14.2", features = ["bpe"] }
```

| Feature | Adds |
| --- | --- |
| `bpe` | Exact o200k_base token counting (`O200kTokenizer`) and the context worker. |
| `broker` | Authenticated local broker for independent agent processes. |
| `broker-persistence` | Optional SQLite recovery for broker state. |

## Quick start

```rust
use hol_cigar::{ContextGraph, ContextRequest, Document, EdgeKind, GraphLimits, Utf8ByteCounter};

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

## Features

- **Exact token budgets.** The final rendered context, citations included, is counted with the real tokenizer and never exceeds your budget.
- **Citations on every line.** Each selected block keeps its source locator and line range.
- **Complete dependencies.** `Requires` edges keep dependency text whole; `Contradicts` keeps both sides.
- **Scoped views.** One graph, many agents, each limited to the sources the host allows.
- **Answer review.** Claims must cite selected evidence and carry a trusted review before release.
- **Verified deltas.** Send only what changed between snapshots; the result is re-hashed and re-counted.
- **Local.** No model service, vector database, hosted service or daemon required.

## Scoped views

Views are logical host scopes, not authentication or an OS sandbox. Keep root graph,
scope definitions and review authority outside agent control. Any readable document
or edge change, even unselected evidence, requires a fresh review. Revocation and
redefinition invalidate handles. Views have no durable restart/resume contract;
use fresh run domains and reviews. The SDK worker still serializes calls. Scheduling,
durable handoffs and effect execution remain application/HUMIDOR responsibilities.

## Token budgets and tokenizers

`Utf8ByteCounter` measures bytes, not model tokens. Enable feature `bpe` and use
`O200kTokenizer::new()` for actual o200k_base text tokens; reuse the tokenizer between requests.
Other tokenizers implement the two-method `TokenCounter` trait. The final rendered context,
including source references and JSON escaping, must fit `max_tokens - reserve_tokens`. Reserve
space for the caller's system prompt, chat envelope, previous turns, and desired model output.

`O200kTokenizer` uses an instance-local exact-text cache by default: at most 2,048 entries and
8 MiB of retained text, plus bounded entry/allocator overhead. Final complete renderings are still
counted exactly; counts are never estimated or added across blocks. This helps both repeated
requests and repeated checks within one request. Cold requests still perform BPE work.

Entirely ASCII input uses a small precompiled segmentation table. Unicode input loads the
complete precompiled Unicode table on first use. Both tables use checked loading before
search; exact ordinary boundaries, vocabulary, token counts and tokenizer identity are the
same. These immutable tables retain no caller text and do not widen the cache limits.

`O200kTokenizer::with_cache_limits(TokenCacheLimits { max_entries: 0, max_text_bytes: 0 })`
disables caching. `cache_stats()` reports hits, misses, entries and retained text bytes;
`clear_cache()` drops retained strings and resets counters. Keep one tokenizer/cache per privacy
boundary, clear it when retention policy requires, and do not treat deallocation as zeroization.
`CachedTokenCounter::new(custom_counter, limits)` provides the same bounded cache for a custom
immutable tokenizer. Concurrent misses may compute twice; expensive counting does not hold the
cache lock. There is no global cache or additional dependency.

## Graph edges and dependencies

`Requires` edges retain complete dependency text. `Contradicts` is symmetric and retains both
sides, including their dependencies. Optional `Supports` and `Related` edges expand search within
the depth/candidate limit. Hard cycles form one jointly required closure; missing or unauthorized
hard dependencies make an optional root unavailable and cause required roots to return an error.
Removing a document keeps incoming edges so withdrawn evidence cannot silently disappear from a
dependent proof. Use `unlink` explicitly when the application changes the dependency contract.

## Excerpts and prompt views

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

## Relevance and semantic candidates

Applications with an embedding index can pass ranked node IDs in `semantic_candidates`. This
extends retrieval to synonyms and paraphrases without coupling the library to a model, vector
database, similarity scale, or paid API. IDs still pass the authorization filter and hard-closure
checks. Lexical coverage statistics are not semantic confidence scores. Set `evidence_per_term`
to 2–4 when independent corroboration matters; exact copied text is not counted as a second witness.
Explicitly listed or conjoined query subjects receive separate source-locator coverage witnesses:
a word mentioned in another document does not automatically suppress a distinct matching source.
For example, a rollback-image record does not replace the primary-image record in a request for
both, while asking only for the rollback image does not request a second primary-image record.
This remains a lexical relevance hint; it does not establish factual support. Copied text,
access checks, complete hard closures and
exact output budgets retain their existing rules. Unrequested source topics are not added merely
to fill the available budget.
Graph edges and semantic leads must come from your application's trusted ingestion/retrieval path;
the library does not discover factual contradictions automatically.

The lexical index retains complete snake_case/camelCase identifiers alongside their components.
Named code declarations receive priority over mere mentions when the query names them. This is
a lexical relevance hint, not a syntax parser or a grant of authority; declarations, like all
other evidence, must pass the caller's access filter and complete dependency checks.

## Check answers before display

`ContextGraph::check_answer` recompiles the request with current authorization and compares
the resulting snapshot ID to `AnswerDraft::snapshot_id`. Each proposed atomic claim must have
selected node citations and a separate, trusted `ClaimReview` with a `ClaimVerdict::Supported` verdict bound with
`AnswerDraft::review_keys()`. The reviewer must assess whether the entire claim is supported,
including quantities, qualifiers, negation and cited passages. Existing citation IDs alone do
not establish support. A changed claim, confidence value or snapshot invalidates its review.

Use `AnswerPolicy::min_sources` (1–4) for distinct provenance groups. Shared source locators
and copied complete document text collapse transitively to one group. Different documents
can still repeat the same underlying report; real independence is a review/ingestion concern.
Explicit `Contradicts` edges throughout cited hard dependencies require the reviewer to
acknowledge the counterevidence and resolve it before returning a supported verdict.

Every claim must pass for `AnswerDecision::Release`. Otherwise the application must abstain,
gather evidence or revise the draft and obtain new reviews. Empty answers never pass. Confidence
in basis points is optional telemetry; even 10000 cannot replace evidence or a trusted review.
The assessment reports missing confidence separately and omits claim/source text from telemetry.

The host must authenticate the review path and keep reviews, policy and authorization outside
model control. Do not accept a model-generated `supported` flag as a review. This API does not
run a semantic judge, detect undeclared conflicts, certify truth, or establish that a draft
contains every factual assertion. Display only the assessed claims, and recheck on state or
policy changes. The [offline evaluation suite](https://github.com/hashgraph-online/hol-cigar/blob/main/benches/answer-quality/README.md) measures
this contract and supplies metrics for separately annotated model outputs; its scripted trials
do not demonstrate real-model hallucination reduction.

## Source chunks and updates

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

## Access control and deltas

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

## Hosting the worker in your own process

With the `bpe` feature, `hol_cigar::worker` serves the `cigar.context-worker.v1` protocol
that the `cigar-context-worker` binary speaks. An application that already ships a native
process can run the worker from that process instead of shipping the separate binary:

```rust,ignore
# fn main() -> std::io::Result<()> {
// In a child process the application starts for CIGAR:
hol_cigar::worker::serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())
# }
```

`worker::main(&args)` takes the binary's arguments (`--version`, and `--broker` with the `broker`
feature). Keep the worker in its own child process, as the binary is: it owns its graph and cache
for the life of the session, and the caller's timeouts end it by ending the process.

## Command-line tool

Run `cargo test --locked -p hol-cigar --features bpe` and
`cargo run --locked -p hol-cigar --features bpe --example compare` for verification.
The optional `cigar-context` JSON CLI reads explicit documents from stdin; `--help` describes its
input. The existing Honey daemon/SDK ABI and release artifacts remain separate from this library.

From this source checkout:

```sh
python3 scripts/dev.py context
cargo run --locked -p hol-cigar --features bpe --bin cigar-context -- --help
```

Example stdin (one object, not a path to be implicitly ingested):

```json
{"domain":"my-project","documents":[{"id":"retry","source":"src/retry.rs","text":"Retry only idempotent operations."},{"id":"contract","source":"docs/api.md","text":"Retain the original operation ID."}],"edges":[["retry","contract","requires"]],"request":{"query":"retry","max_tokens":512,"reserve_tokens":64}}
```

The CLI rejects duplicate document IDs. For intentional replacements, use `graph.upsert` in the
Rust API. Reuse an in-memory graph and tokenizer across requests; starting the CLI rebuilds both.
`SelectionStats` reports missing/unauthorized, oversized-closure, and budget-rejected optional
roots. A small or empty result is not evidence that the query is answerable.

## Frequently Asked Questions

### What is hol-cigar?

`hol-cigar` is the Rust crate for CIGAR, HOL's open-source context engineering protocol for AI
agents. It builds a local context graph from text you supply and compiles cited context that fits
an exact token budget.

### Is hol-cigar a RAG or vector database library?

It needs no vector database or embedding model. It uses a lexical index over a graph with explicit
dependency edges. If you have an embedding index, pass its ranked IDs in `semantic_candidates`.

### Does hol-cigar call a model or the network?

No. The library never opens files or calls a model or remote service on its own; your
application supplies document text. The optional `broker` feature serves local agent processes
over authenticated loopback connections.

### Why is the library imported as `hol_cigar` while the binaries are named `cigar-context`?

Cargo turns the package name `hol-cigar` into the library name `hol_cigar`. The command-line tools
keep their original names, `cigar-context` and `cigar-context-worker`.

## Resources

- [CIGAR on hol.org](https://hol.org/cigar)
- [CIGAR repository and protocol documentation](https://github.com/hashgraph-online/hol-cigar)
- [Python SDK on PyPI](https://pypi.org/project/hol-cigar/) · [TypeScript SDK on npm](https://www.npmjs.com/package/@hol-org/cigar)
- [HOL Guard: open-source antivirus for AI agents](https://github.com/hashgraph-online/hol-guard)

## License

Maintained by [HOL](https://hol.org). Licensed under
[Apache-2.0](https://github.com/hashgraph-online/hol-cigar/blob/main/LICENSE).
