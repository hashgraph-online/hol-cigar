# CIGAR 0.10.0: second-pass improvements and release readiness

Date: 2026-09-07. Worktree/branch: `hol-cigar-0.10.0` / `codex/cigar-0.10.0`.

## Outcome

The second candidate substantially reduces query CPU time while retaining the first candidate's
complete selected evidence, citations, token counts, snapshot identities and error outcomes in
differential testing. It adds atomic source replacement, bounded exact-token caching, a real hook
deadline fix, and more dependable development/release checks. No existing API was removed and no
dependency was added to the standalone library.

This report supersedes the [first-pass report](cigar-0.10.0-evaluation.md) for the current source.
The [library guide](../crates/cigar-context/README.md) documents the new APIs. The distribution
boundary is unchanged: `cigar-context` is 0.10.0; Honey runtime/SDK identities remain 0.9.4.
The crate is prepared for release review, not uploaded or asserted production-qualified.

## Measured KPIs

Same Apple M3 Ultra workstation, Rust 1.92.0, optimized builds, identical registry dependency
bindings, identical inputs and output oracle. Two rounds reverse treatment ordering. Each
real-source row aggregates 320 post-warmup observations across eight probes; each scale row has
40 observations. Repeated observations measure latency, not additional independent quality tasks.

| Workload | Previous 0.10.0 median | New cold median | New warm median | Warm speedup |
| --- | ---: | ---: | ---: | ---: |
| Real Rust source, full chunks | 27.56 ms | 17.21 ms | 0.906 ms | 30.4× |
| Real Rust source, excerpt windows | 14.27 ms | 4.93 ms | 0.893 ms | 16.0× |
| Common terms, 1,000 documents | 1.287 ms | 0.752 ms | 0.304 ms | 4.23× |
| Common terms, 10,000 documents | 7.314 ms | 2.445 ms | 1.959 ms | 3.73× |
| Common terms, 50,000 documents | 42.00 ms | 14.29 ms | 13.53 ms | 3.10× |
| Selective term, 50,000 documents | 22.67 µs | 9.83 µs | 5.71 µs | 3.97× |

Real-source p95 improves from 29.52 to 18.29 ms cold / 1.064 ms warm for full chunks, and
20.65 to 8.20 ms cold / 1.164 ms warm for windows. Cold-cache queries clear the cache immediately
before timing; warm queries reuse it. “Cold” excludes vocabulary/index construction, which is
reported separately below. The previous implementation has no token cache. Disabling the new
cache entirely still gives 17.23 ms full / 5.21 ms windows: substantial algorithmic improvement,
not only a cache demonstration. These are offline library timings, not LLM response latency.

### No additional evidence loss or token-count reduction

**6,204 complete old/new comparisons passed across 1,034 distinct request inputs**: four requests
on each of 250 seeded graphs, 12 authored cases, 16 real-source query/mode combinations, and six
scale queries. There are 937 successful snapshots and 97 expected error outcomes per treatment.
Every repeated timing observation is also checked against that request's first result. Comparisons
include all serialized snapshot fields, not merely selected IDs or a matching token total.

Both full and window modes still find 8/8 target symbols. Mean context remains 1,385.875 and
837.25 tokens respectively. The first pass's 29.3% / 57.3% token reductions against the stronger
BM25 baseline therefore remain intact on these probes. This pass makes that context cheaper to
compute; it does **not** claim an additional prompt-token reduction. The original semantic-gap
and unlinked-counterclaim limitations remain. Source probes are not held-out model-answer tests.

The earlier compatible compiler improvement is untouched: its source hash still matches the
first-pass evidence. That pass measured up to 4.37× faster packing with 1,280 old/new output
comparisons. Those results are retained, not falsely counted as newly rerun benchmarks here.

### Costs and tradeoffs

- Real-source indexing rises from about 49.4 to 61 ms; the 50,000-document synthetic index rises
  from about 188 to 207 ms. Work moved from repeated queries to ingestion.
- Peak adapter process RSS is about 191 MB before and 206–210 MB after (decimal MB, roughly
  8–10% more). This includes the tokenizer, input parsing, indexes and cache, not just graph heap.
  An intermediate line-index design used about 251–256 MB; shared posting IDs and compact
  exceptional-line storage removed most of that increase. The final implementation is not claimed
  to reduce memory versus the first candidate.
- BPE caching retains at most 1,024 strings / 8 MiB of text by default, plus bounded metadata.
  It can be disabled or cleared. The verified source archive is 42,285 bytes versus 31,596 before;
  the increase includes implementation, tests, changelog and bundled license, not model context.
- Common-term retrieval still visits matching postings. It is faster, not constant-time. No dense
  million-edge, long-duration production soak or universal throughput guarantee is established.

## Implementation details

1. Saturated term frequency lives beside each posting ID, avoiding per-term document lookups.
   Borrowed IDs and partial top-k selection avoid cloning/sorting every match. A complete ordering
   ending in document ID preserves deterministic tie-breaking despite randomized hash iteration.
2. Source-line postings find matching windows and retained query-term coverage without repeatedly
   parsing candidate bodies. Full-source handling no longer builds discarded excerpt strings.
   Shared immutable posting IDs and compact common-line storage control index overhead.
3. `CachedTokenCounter<T>` memoizes **complete exact strings**. Hash collisions still require string
   equality; counts are never approximated or summed across independently rendered blocks. Errors
   are not cached. Cache locks do not cover expensive BPE work. Generation tracking prevents an
   in-flight miss from reintroducing retained text after `clear_cache()`.
4. `replace_source(locator, documents)` validates and indexes a replacement before mutation. It
   rejects duplicate IDs and collisions with another source; checks final, not transient, capacity;
   removes obsolete chunks; keeps identical batches stable; and advances revision once for a
   changed batch. Hard references to withdrawn chunks remain fail-closed until explicitly repaired.
5. The hook deadline now covers child exit **and** both output streams. Reader futures are cancelled
   together on timeout/error, rather than detached. An inherited-pipe regression fails on isolated
   copies of exact 0.9.4 three times and passes on the final candidate three times. Production
   deadline values and authority checks are unchanged.

## Reliability investigation

The old handoff fixture remained intermittent after eliminating unnecessary `grep` child processes:
96/100 repetitions passed, with four failures at the same two-second deadline. Launching the same
fixture through the existing `/bin/sh` interpreter, rather than as a freshly written executable,
then passed **100/100**. The test still checks the same request fields, create/accept sequence,
recipient-specific bundle and authority, using two real child processes and the same deadline.
The private launcher can carry a fixed argument prefix for this fixture; production launch prefixes
remain empty. This is evidence for a fixture-launch sensitivity, not a claim that every platform's
process-start behavior has been fully characterized.

A repeated parallel workspace run also exposed four unchanged extension-host deadline failures
and an unchanged MCP cancellation-fixture startup failure. The failed cancellation left a test-owned
busy-loop child holding an unrelated test's inherited pipe; profiling showed the handshake test
blocked in `wait_with_output`. The exact owned orphan was terminated to finish collecting the
failed run. No user service or user data was removed.

The repository already documents this Rust 1.92/macOS pipe/CLOEXEC issue in
[its nextest configuration](../.config/nextest.toml), and requires serial macOS qualification.
`scripts/dev.py` now follows that setting by default. Explicit concurrency tests still create their
own threads/clients; no assertion, test, deadline, ignored-test policy or authority gate was weakened.
The failed parallel results are retained and are not presented as release-quality evidence.

## Verification and release checklist

- Standalone library: 32 tests plus one documentation example pass with BPE; core-only checks pass.
  New coverage includes source transactions, stale-chunk withdrawal, collision/capacity rollback,
  cache eviction/disable/errors, 8,000 concurrent cache requests, cache-clear races and cached versus
  uncached snapshots across updates and authorization changes.
- Formatting, warnings-denied Clippy and warnings-denied public API documentation pass.
- Packaged source verification, packaged tests and fresh external core-only/BPE consumers pass.
  Both consumers exercise source replacement and dependency preservation; the BPE consumer also
  exercises cache inspection/clear. Normal dependency counts remain 21 core / 34 BPE.
- A point-in-time OSV query for all 34 registry packages in the standalone consumer lockfile returned
  no listed advisories. Only public names/versions were sent. Python's default certificate lookup
  initially failed; using the existing OS CA bundle succeeded with TLS verification still enabled.
  This is not an exhaustive source security audit or a guarantee against unknown vulnerabilities.
- Final native macOS serial workspace run: **1,254 test invocations and 39 documentation examples
  passed**, with zero failures and 28 existing ignored tests. The earlier parallel run passed 1,253
  tests before the additional cache-clear regression; its repeat passed 1,249 and failed five.
  Successful and unsuccessful runs are retained separately, not added as independent test coverage.
- Crate metadata now restricts publication to crates.io instead of disabling it; explicit archive
  contents, the existing Apache-2.0 license text, changelog and docs.rs BPE configuration are included.
  [Cargo's publication setting](https://doc.rust-lang.org/cargo/reference/manifest.html#the-publish-field)
  permits a later publisher action; changing it does not upload or reserve a package name.

### Remaining promotion gates

1. Execute the committed Linux/macOS/Windows native CI matrix and review its results. Only native
   macOS ran here; Docker is installed but no daemon/socket is available. Cross-platform runtime
   behavior and registry ownership/name availability are not certified by local packaging.
2. Review/commit the candidate and approve the standalone package's publication scope. No commit,
   push, registry upload, signed receipt or distribution-wide version promotion was performed.
3. For a **full Honey 0.10.0 distribution**, run the existing authority-backed installed-runtime,
   SDK, signing and release process. Publishing this library does not silently qualify that system.
4. Before advertising improved model task efficacy, run independently chosen held-out model tasks
   with an approved provider/data/cost scope. The measured gain here is computation efficiency with
   retained evidence, not a new claim of answer accuracy or “best possible” global optimality.

The [retained evidence manifest](evidence/context-010-pass2/manifest.json) binds final source hashes,
raw inputs/snapshots/timings, diagnostic logs, failed explorations, package bytes and advisory results.
The [reproduction guide](../benches/context-010/README.md) provides commands. These are local
development/qualification diagnostics, not signatures from a release authority.
