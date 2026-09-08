# CIGAR 0.10.0: implementation and measured differences

Date: 2026-09-07. Branch: `codex/cigar-0.10.0`.

Historical first-candidate report. See the [second-pass report](cigar-0.10.0-second-pass.md) for
the current implementation and release status. The evidence below binds the preserved original
package/source state, not files changed by the later pass.

## Outcome and release boundary

Implemented a usable **`cigar-context` 0.10.0 Rust library candidate**, its JSON CLI, reproducible
comparisons, and compatible optimizations to the existing CIGAR compiler. The strongest measured
improvements are faster large-candidate packing without changed output, and more useful code
evidence per token than either tested BM25 baseline.

This is not a claim of universal optimality, live-model answer improvement, or a qualified public
release. The existing Honey runtime, protocol, and SDK distribution identities remain 0.9.4.
Their functionality and qualification history were not replaced by a simplified graph API.
`cigar-context` is a separate, unpublished local-library candidate (`publish = false`). No release,
registry, GitHub, production service, user checkout, or old-version source was modified externally.

The [implementation plan](../docs/proposals/cigar-0.10.0-plan.md),
[library guide](../crates/cigar-context/README.md), and
[reproduction instructions](../benches/context-010/README.md) accompany this report.

## What changed

| Area | Implemented improvement | Important boundary |
| --- | --- | --- |
| Existing v4 compiler | Precompute immutable scoring factors; lazily reevaluate a deterministic upper-bound heap; replace quadratic independence checks with ordered sets | Frozen profile digests, tie-breaking, packing decisions, manifests, and bundles are preserved in differential tests; general dependent packing is unchanged |
| Local library usability | Small standalone Rust API and JSON stdin/stdout CLI; no daemon, database, network, or model dependency | This does not replace Honey's authenticated multi-tenant services |
| Retrieval | Incremental term postings, complete compound identifiers, declaration-aware code relevance, bounded graph expansion, and ranked semantic-retriever input | Semantic candidates must come from the application; no built-in embedding model or automatic factual contradiction discovery |
| Evidence preservation | Directed `Requires`, symmetric `Contradicts`, optional `Supports`/`Related`, full hard closure, independent-source corroboration, exact-text coalescing | Graph metadata must be trustworthy; an unavailable required dependency fails rather than silently disappearing |
| Token accounting | Optional pinned o200k_base BPE; count final JSON rendering, citations, and escaping; explicit reserve | Provider chat envelopes, reasoning/output tokens, and monetary costs are not measured |
| Source handling | Full text by default; opt-in query windows; overlapping line chunks with original source offsets and commitments | Line chunks are not AST nodes; symbol-complete ingestion remains the application's responsibility |
| Incremental use | Upsert/remove/unlink, bounded retained edges, verified snapshots, exact-base deltas, policy/domain/tokenizer isolation | Deltas save transport bytes, not stateless-model prompt tokens; obsolete chunk IDs must be withdrawn after edits |
| Developer workflow | Normal formatting/lint/test commands, complete diagnostic logs, packaged consumers, and a standalone Linux/macOS/Windows CI configuration | Existing authority-backed release gates remain intact; the new hosted CI matrix was not executed in this session |

The new crate's normal dependency tree contains 21 dependency crates in the tested core-only
consumer, or 34 with BPE, excluding the consumer and `cigar-context` itself. Neither composition
pulls in `cigar-daemon`, `cigar-store`, `cigar-protocol`, `reqwest`, or `rusqlite`.
The verified source package is 31,596 bytes compressed; that is **not** its compiled binary or
runtime memory size. BPE initialization should be amortized by reusing the tokenizer.

## Version identification and methodology

Actual source builds, not simulated labels:

| Binding | Exact source commit | Compiler profile |
| --- | --- | --- |
| 0.9.2 | `7dc5bb6d91efca5f7d89c1991449a5cab17e6b52` | `balanced_v1` |
| 0.9.3 frozen candidate | `a049fbc8ed81c9adc6b1a066ca053c5befc2578a` | `balanced_v3` |
| Exact 0.9.4 | `6e518ad95a018a80a04db295c0f91ec928a0ba0c` | `balanced_v4` |
| Optimized compatibility compiler | Base `107880a53046b0abf0d5f5f6d9f63598722823e2` plus retained source hashes | Same `balanced_v4` |

The 0.9.3 source comes from the locally retained freeze commit because the public checkout did
not contain an equivalent 0.9.3 tag. All three baseline worktrees remained clean. Each adapter
uses actual path dependencies, its baseline lockfile, and a check against dependency package
version/checksum drift. The current root lockfile adds the new library and three registry packages;
Cargo also resolves `tempfile`'s existing dependency to already-locked `getrandom 0.4.3`, matching
the exact 0.9.4 baseline, instead of the postrelease checkout's `0.3.4` edge.

Host: Apple M3 Ultra, 512 GiB RAM, macOS 26.6.1. Rust 1.92.0. Release benchmarks use one codegen
unit and thin LTO. The workstation was not an isolated performance lab; do not extrapolate these
latencies to a laptop or loaded server. Runs use warmups and interleaved treatments, retaining raw
samples. Repeating a fixture measures timing variance, **not additional independent quality data**.

## 1. Existing compiler: faster, same output

Exact-match packing, with 64 selected evidence items in each case:

| Candidates | 0.9.4 median | Optimized median | Speedup | 0.9.4 / optimized p95 |
| ---: | ---: | ---: | ---: | ---: |
| 128 | 0.880 ms | 0.506 ms | 1.74× | 0.894 / 0.528 ms |
| 512 | 5.478 ms | 1.761 ms | 3.11× | 5.576 / 1.791 ms |
| 1,024 | 15.358 ms | 3.512 ms | 4.37× | 15.559 / 3.559 ms |

The lexical-only, early-stop shape also improves: 1,024 candidates fall from 10.453 ms to
3.184 ms median (3.28×). This isolates the benefit of removing pairwise independence checks.
Each size/shape/version has 100 retained samples after 10 warmups. Small authored-case compiler
medians are effectively similar: 83.4 µs versus 81.8 µs, with a slightly worse candidate p95
(121.2 versus 120.0 µs). Large-case improvements should not be advertised as a universal speedup.

**1,280 old/new output comparisons passed**, including 200 distinct seeded cases, 420 authored-case
runs, and 660 packing runs. The comparisons cover the complete serialized bundle, manifest, plan,
selection and token total, excluding elapsed time. All 200 seeded cases compiled successfully;
these were not comparisons of two errors. Existing frozen-digest, general-packer equivalence,
dependency, conflict, budget, process-determinism, and cache tests also pass.

No token saving is attributed to this compatible compiler optimization: its output is unchanged.

## 2. Authored graph tasks: evidence versus tokens

Twelve scenarios, 24 fixed distractors per scenario, a 512-token evidence budget, and 30 retained
timing samples per case/treatment. The selector receives queries and graph metadata, never the
gold fact labels. “Required facts retained” means literal presence of the specified facts in the
selected evidence, not a model's ability to solve a task.

| Treatment | Mean input-text tokens | Required facts retained | All requested facts present | Fits 512 tokens |
| --- | ---: | ---: | ---: | ---: |
| No CIGAR: all source context | 5,936.0 | 19/20 (95%) | 11/12 | 0/12 |
| No CIGAR: budgeted BM25 | 36.8 | 12/20 (60%) | 6/12 | 12/12 |
| 0.9.2 compiler adapter / v1 | 301.0 | 19/20 (95%) | 11/12 | 12/12 |
| 0.9.3 compiler adapter / v3 | 40.4 | 14/20 (70%) | 6/12 | 12/12 |
| 0.9.4 compiler adapter / v4 | 37.6 | 13/20 (65%) | 5/12 | 12/12 |
| Optimized v4 compatibility adapter | 37.6 | 13/20 (65%) | 5/12 | 12/12 |
| New 0.10.0 context graph, default full text | 48.7 | 17/20 (85%) | 9/12 | 12/12 |

One expected fact is deliberately absent from every source. Among the 19 actually available facts,
the graph retains 17 and BM25 retains 12. Compared with full context, the graph uses 99.18% fewer
tokens **but also omits two available facts**. Compared with BM25, it spends 32.4% more tokens to
retain five more facts. Compared with the 0.9.2 adapter it uses 83.8% fewer tokens, but has lower
fact coverage. These tradeoffs are part of the result, not hidden regressions.

The two recoverable gaps are a semantic paraphrase with no lexical/graph connection and an
unlinked counterclaim. Applications can supply a semantic retriever's ranked IDs or explicit
counterclaim edges; tests verify these routes and their authorization checks. The benchmark does
not inject gold IDs to erase these failures. The unavailable-fact case returns empty context,
instead of padding the response with unrelated sources.

**Adapter caveat:** historical compiler inputs contain query-derived features and `requires`
dependencies, not each release's complete daemon ingestion/retrieval/claim pipeline. In particular,
the adapter does not construct Honey's authenticated claim metadata. These rows do not establish
that older CIGAR cannot preserve counterevidence or reproduce its historical release benchmarks.
Compiler timings exclude retrieval/rendering and must not be compared directly with graph query
latencies. New graph query median/p95 on these tiny cases is 52.8/83.3 µs; BM25 is 10.1/19.4 µs.

## 3. Real Rust source: code retrieval

The unchanged 0.9.4 source supplies 44 files from compiler, policy, retrieval, and protocol packages.
Both retrievers receive identical 80-line chunks with eight-line overlap: 504 chunks, equivalent
to 384,882 tokens if all rendered. No graph edges are supplied in this experiment. Eight probes
ask for named code symbols; each has 20 retained trials after five warmups.

| Treatment | Mean tokens | Symbols found | Median query | p95 query |
| --- | ---: | ---: | ---: | ---: |
| BM25, split-token analyzer | 1,950.3 | 6/8 | 78.00 ms | 145.70 ms |
| BM25, compound-identifier-aware analyzer | 1,959.3 | 6/8 | 77.62 ms | 152.29 ms |
| CIGAR full chunks, default | 1,385.9 | 8/8 | 27.86 ms | 29.77 ms |
| CIGAR query windows, opt-in | 837.3 | 8/8 | 14.63 ms | 21.12 ms |

Against the stronger BM25 configuration, full chunks use **29.3% fewer tokens**, and optional
windows use **57.3% fewer**. Both recover the two symbols that BM25 misses in these probes.
The full-context rendering exceeds the 2,048-token budget; every budgeted treatment fits it.

Index construction is excluded from query times: graph 50.0 ms; split-token BM25 24.1 ms;
identifier-aware BM25 34.6 ms. BPE initialization is 53.1 ms. CIGAR pays more at ingestion to retain
identifier/declaration metadata. The BM25 implementation greedily tests final token counts while
packing; its latency is not representative of every optimized search engine.

### What the investigation rejected

The initial selector found only 1/8 symbols with windows and 5/8 with full chunks. Those results
are retained separately. Splitting identifiers into common words and stopping after superficial
coverage was too aggressive. The implementation now retains compound identifiers, gives named
declarations priority over mere mentions, computes coverage from retained text, and defaults to
full source retention. Windows remain opt-in because symbol presence does not prove that an
excerpt preserves every condition or syntactically complete function.

These probes helped shape the implementation and are **not held-out evaluation**. Eight successful
symbol-discovery probes are not eight successful programming tasks or proof of general superiority.

## 4. Scale, updates, and repeated context

Synthetic short-document graphs, with exact BPE accounting:

| Documents | Index build | Selective query median | Common-term query median | One-document update |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 3.52 ms | 21.2 µs | 1.29 ms | 7.7 µs |
| 10,000 | 38.15 ms | 22.5 µs | 7.34 ms | 10.1 µs |
| 50,000 | 194.29 ms | 22.6 µs | 42.19 ms | 13.6 µs |

Selective lookup remains cheap, but common-term queries still scan/score large posting sets before
candidate truncation. That is a documented remaining optimization opportunity, not constant-time
retrieval. Each scale run also verifies a changed snapshot and exact delta reconstruction. Update
timings are single observations, unlike the 20 retained query timings; they are not update p95s.
This is not a 50,000-file, dense-edge, concurrent, or long-duration memory benchmark.

For example, the unchanged retry-contract snapshot is 1,164 serialized bytes and its delta is
651 bytes: 44.1% less transport. An empty result saves only 16 bytes (466 to 450). Deltas require
the exact acknowledged base, reject policy/domain/tokenizer changes, withdraw omitted blocks,
and verify reconstruction. They do **not** let a stateless model omit necessary prompt context.

## Verification and retained evidence

- New library: 26 tests plus one documentation example pass with BPE; core-only tests also pass.
  This includes 128 generated graph cases, permutation invariance, hard closure/cycles, restricted
  graph hops, withdrawals, retained-edge churn bounds, duplicate corroboration, source offsets,
  symbol preference, tampering, wrong-base deltas, CLI process boundaries, and token budgets.
- Existing compiler: 51 tests pass; its explicit performance diagnostic remains ignored by the
  ordinary test command and is supplemented by the separate release-build comparisons above.
- Broad workspace formatting and warnings-denied Clippy pass; Clippy excludes the existing
  `cigar-soak` development exception. A full run passed 1,246 test invocations and 39 documentation
  examples, with 28 ignored tests. The final repeat, including the additional edge-retention test,
  passed 1,246 and failed one unchanged Claude-hook test. It is **not an unconditionally green
  workspace**. Overlapping package/workspace runs should not be added as independent tests.
- The actual packaged crate passes verification and its packaged tests. Fresh external consumers
  succeed with core-only and BPE features, with their resolved lockfile and dependency trees saved.
- Initial broad testing failed at cross-SDK replay because Node/Go were absent from the supplied
  test PATH. After supplying Node 24.19.0, Python 3.14.7, Go 1.26.6, and protoc 33.2, those tests pass.
  No SDK test was removed or weakened. Native Linux/Windows execution, production services,
  ignored external-service/scale campaigns, and signed release qualification were not performed.

The intermittent failure is `subagent_handoff_never_substitutes_the_parent_bundle`, returning
`BackendUnavailable` around its two-second deadline. The entire hook package is unchanged relative
to exact 0.9.4. In three additional interleaved package runs, the candidate passed 3/3; untouched
0.9.4 passed 2/3 and reproduced the identical failure in the third. This demonstrates that the
failure predates this change. It is consistent with the deadline but has not been fully root-caused.
No timeout was relaxed and no assertion was removed to obtain a passing result. The failure and
baseline reproduction remain a qualification issue for the full runtime, distinct from the local
library and compatible compiler changes.

The [evidence manifest](evidence/context-010/manifest.json) binds source-file hashes and compressed
raw artifacts: comparison samples, real-source file commitments, the initial unsuccessful selector
results, complete successful/failed validation logs, hook baseline rechecks, consumer lockfile,
and package verification. The verified local source `.crate` is retained there as well. Gzip logs contain
ordinary JSON/text and can be opened with standard decompression tools. Nothing in these local
artifacts is a release-authority signature or a live-provider receipt.

## Remaining work before promoting a full CIGAR 0.10.0 distribution

1. Evaluate separately selected, held-out coding/agent tasks with real model answers, task tests,
   complete input/output token accounting, realistic graph metadata, and a declared provider/data
   budget. Include BM25, semantic retrieval, full context, and existing Honey configurations.
2. Profile common-term/dense-graph workloads. Consider bounded posting top-k selection and cached
   representation counts keyed by exact source/tokenizer identity; keep final-render budget checks
   and compare against the current deterministic selector before adopting either optimization.
3. Integrate the local API with the chosen application/SDK and durable ingestion lifecycle.
   Preserve existing policy/claim/replay semantics; a local allow-list is not a replacement for
   Honey's governance. Validate batch source replacement and stale-chunk withdrawal on real edits.
4. Resolve the reproduced hook deadline flake, execute the new native CI matrix, longer fuzz/churn/concurrency/soak runs, and relevant installed
   consumers. Then promote distribution-wide versions, installation assets, release notes, and
   qualification records together through the existing release process.

The defensible conclusion is a materially improved, tested library candidate and a substantially
faster compatible packing path—not “the best possible context graph” on the strength of a small
offline experiment. The release should optimize retained evidence and successful tasks per token,
not token count in isolation.
