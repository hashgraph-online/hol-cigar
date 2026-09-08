# CIGAR 0.10.0 library implementation and evaluation plan

Date: 2026-09-07. Base: `107880a53046b0abf0d5f5f6d9f63598722823e2`
(public main `7866bab5` plus the npm publication record). Branch: `codex/cigar-0.10.0`.

## Objective and release boundary

Deliver an ergonomic, bounded, offline Rust context graph that improves evidence retrieved per
token, supports incremental updates and repeated tasks, and has reproducible comparisons. The
new `cigar-context` library is version 0.10.0. The existing 0.9.4 protocol/runtime distribution
remains independently versioned while its compiler receives compatible optimizations. Neither
the existing Honey tag/artifacts nor their qualification records are rewritten. Publication,
production support, and claims of universal superiority are outside this development change.

## Implementation sequence

1. Preserve the exact 0.9.4 source and identify the actual packing path used by each benchmark.
   Cache immutable candidate factors; eliminate repeated expensive lookup/scoring in the
   independent fast path. Compare complete output identities against an unmodified oracle.
2. Add the small `cigar-context` library with no daemon, database, network, or model dependency:
   incremental lexical index; explicit typed required/supporting/contradicting relationships;
   graph traversal with bounded fan-out/depth; caller-authorized node filtering; deterministic
   evidence selection; exact final rendered token budgeting; source and excerpt citations;
   and explicit mandatory-context failure instead of silent truncation.
   Preserve complete technical identifiers, prefer named declarations over mentions, and provide
   explicit line chunking with original-source offsets. Default to full text; excerpt windows are
   opt-in because real-source probes showed aggressive extraction/coverage stopping could hide
   the requested symbol. Measure coverage from retained text rather than unrendered source.
3. Add provider-neutral tokenizer injection and an optional pinned local BPE tokenizer. Count
   rendered citations and framing, not only content. Keep model input text counts separate from
   provider chat-envelope charges and generated output tokens.
4. Add digest-verified context snapshots and deltas. A delta is a transport optimization for a
   receiver holding the exact prior snapshot; it never implies that an ordinary stateless LLM
   can omit its required context. Policy/domain/tokenizer changes force a fresh snapshot.
5. Add an executable JSON CLI, a short Rust example, and local source-quality CI commands.
   Explain how to supply trusted graph metadata and avoid claiming authorization from lexical
   relevance. Keep the existing authority-gated qualification routes intact.
6. Compare old compiler profiles and immutable 0.9.4 binaries with the optimized compiler; compare
   complete graph workflows against full context and token-budgeted lexical retrieval. Include
   dependencies, duplicates, conflicts, multiple requirements, corpus updates, and repeated steps.
   Freeze the corpus independently of the selector, retain all per-case measurements, and report
   regressions as well as improvements.

## Acceptance criteria

- Existing compiler profile digests and complete outputs remain equivalent to 0.9.4.
- Every successful graph result fits the actual tokenizer's count of the final rendering.
- Required dependencies and explicit counterevidence are complete; unavailable required nodes
  and unsatisfiable budgets fail clearly. Restricted nodes never appear via graph traversal.
- Incremental updates match a freshly rebuilt index; insertion order does not change selection.
- Deltas reconstruct exactly, reject the wrong base, and never reuse stale or withdrawn content.
- New code passes formatting, warnings-denied Clippy, unit/integration tests, and a clean consumer.
- Timing comparisons use release builds, warmups, interleaved repeated runs, and raw samples.
- Token reduction is reported only with evidence recall, precision, dependency closure, and
  task-specific answerability. Deterministic answerability is not live-model efficacy.

## Research informing the design

Lexical retrieval complements graph traversal for exact technical identifiers; preserving source
context around excerpts avoids isolated-chunk ambiguity. See Anthropic's
[Contextual Retrieval](https://www.anthropic.com/engineering/contextual-retrieval) and Microsoft's
[GraphRAG local search](https://microsoft.github.io/graphrag/query/local_search/).
Longer context does not automatically produce better use of evidence; position and irrelevant
material matter ([Lost in the Middle](https://arxiv.org/abs/2307.03172)). These motivate measurements,
not inherited performance claims. This release uses explicit graph metadata and extractive text;
it does not require paid LLM graph construction or hallucinated summaries.

## Later qualification

Live-model trials on a separately chosen held-out task corpus, native Linux/Windows checks,
installed full-runtime qualification, signing, long fuzz/soak campaigns, and distribution-wide
version promotion follow the tested library candidate. Their absence must remain visible in the
final report. Actual external-provider evaluation requires an available provider and an explicit
data/cost scope; offline measurements cannot establish model completion quality.

## Second-pass release preparation

- Preserve the first candidate's packaged source and compare complete snapshots, not only token
  totals, against separately built adapters with identical registry dependency bindings.
- Remove query-time rescans using deterministic top-k ranking, saturated posting frequencies,
  source-line postings and retained-range coverage. Share posting IDs and inline single-line
  positions to control the extra index memory.
- Add bounded, exact-text token caching with separate cold, warm and disabled-cache measurements;
  preserve the tokenizer identity and every final-render budget check.
- Add atomic whole-source replacement, obsolete-chunk withdrawal, no-op detection, final-capacity
  validation, and hard-reference failure on withdrawal. Add concurrency/cache-clear regressions.
- Bound the hook's entire subprocess exchange, including inherited output pipes; reproduce the
  regression against frozen old source. Keep handoff identity/authority assertions and deadlines.
- Prepare crate metadata, bundled license, changelog, docs build, package and consumer validation.
  Permit only crates.io publication in metadata without uploading; native CI, owner approval and
  the existing full-distribution qualification remain separate promotion gates.

## Implementation status

The local library, compatible compiler optimization, JSON CLI, typed graph, semantic-retriever
input, chunking/citations, exact BPE option, snapshots/deltas, developer checks, CI configuration,
and reproducible experiment/consumer harnesses are implemented on this branch. The existing
protocol, daemon, SDK, governance, replay, and legacy compiler-profile behavior are retained.
See the [second-pass report](../../reports/cigar-0.10.0-second-pass.md) and
[first-pass report](../../reports/cigar-0.10.0-evaluation.md) for acceptance
results, unsuccessful initial approaches, comparison caveats, and the remaining release gates.
