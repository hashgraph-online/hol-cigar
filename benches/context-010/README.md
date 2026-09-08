# 0.10.0 reproducible development comparisons

These are local diagnostic experiments, not release qualification or live-model evaluations.
Run from the repository root with Rust 1.92.0. Use **new, absolute** output directories; scripts
refuse to overwrite prior runs. None modifies baseline source, publishes artifacts, or calls a model.

```sh
python3 scripts/dev.py context --log-dir /absolute/new-context-logs
python3 scripts/dev.py compiler --log-dir /absolute/new-compiler-logs
python3 scripts/dev.py workspace --log-dir /absolute/new-workspace-logs
python3 benches/context-010/run.py \
  --baseline92 /absolute/frozen-0.9.2 \
  --baseline93 /absolute/frozen-0.9.3 \
  --baseline94 /absolute/frozen-0.9.4 \
  --cargo /absolute/rust-1.92.0/bin/cargo \
  --target /absolute/comparison-build-cache \
  --output /absolute/new-comparison-output --source-evaluation
python3 benches/context-010/qualify.py \
  --cargo /absolute/rust-1.92.0/bin/cargo \
  --target /absolute/package-build-cache --output /absolute/new-package-consumer
```

Workspace tests need `protoc` (or `PROTOC`), Node 24 with TypeScript support, Python 3.14, and
Go 1.26.6 on PATH. Core/library/compiler diagnostics do not require those language runtimes.
For an explicit non-PATH Rust installation, pass `--cargo` to `scripts/dev.py` as well.
On macOS the runner defaults to `--test-threads=1`, matching the repository's existing
`.config/nextest.toml` macOS qualification isolation. That profile documents Rust 1.92's
non-atomic pipe/CLOEXEC behavior during concurrent process launches. Tests still run their own
explicit concurrency exercises; no assertion, timeout or test is disabled. `--test-threads N`
can override this for development experiments, not qualification claims.

`run.py` builds four independent Rust executables from their actual source paths. It seeds the
adapters with each baseline's lockfile and rejects dependency version/checksum drift. Version,
source tree, dirty status, compiler profile, and binary hashes are recorded. Adapters use the
same query-derived candidate features and input token counts. They map `requires` dependencies,
but do **not** recreate native ingestion, authenticated claim construction, daemon retrieval,
or every historical feature. Consequently, the authored quality comparison is about these
explicit adapter configurations, not an assertion that older CIGAR cannot represent counterclaims.

`comparison.json` retains 30 post-warmup observations per authored case/treatment, 200 seeded
complete-output comparisons with 0.9.4, and 100 post-warmup packing timings per size/shape/version.
Old compiler outputs include the full bundle, manifest and plan in the comparison oracle;
the harness fails if any corresponding field changes. Packing has lexical-only and exact-match
shapes so both early stopping and repeated admission are exercised. Hashes of oracle outputs
are retained; errors and empty selections are not silently counted as successful compilation.

The 12 authored scenarios include an unavailable fact, a semantic gap, and an unlinked counterclaim.
The reported fact metric is literal required-fact presence, **not model answer accuracy**. One of
the 20 expected facts is deliberately absent from the source corpus. Repeated timings are not
independent quality samples. The selector never receives gold fact labels.

The real-source experiment reads only Rust source under four explicit baseline packages, hashes
every file, and gives both retrievers identical 80-line/8-line-overlap chunks. It checks eight
symbol-discovery probes, not complete programming-task solutions. Both indexes are prebuilt;
their build times and the tokenizer initialization time are reported separately. `--smoke` on
the `source_compare` example runs one untimed-quality diagnostic iteration and skips scale tests.
The 1k/10k/50k scale fixture measures selective/common-term query timings and a verified update.

The BM25 baseline implements standard k1=1.2, b=0.75 with deterministic ID tie-breaking and final
rendered token-budget checks. Its generic split-token lexical analyzer is intentionally frozen;
the new library additionally preserves compound identifiers and prioritizes named declarations.
A stronger second real-source BM25 treatment also preserves complete compound identifiers, to
separate the benefits of a code-aware analyzer from declaration-aware selection.
BM25's full-budget greedy packing can be slower than a tuned production search engine; these
numbers are not a comparison with Elasticsearch, a vector database, or an optimized commercial RAG.

`qualify.py` verifies the actual `.crate`, builds external core-only and BPE consumers from the
normalized package, checks their dependency trees, and runs the packaged tests. `export.py`
retains raw JSON/logs as deterministic gzip files with source hashes for the accompanying report.

## Second-candidate compatibility and performance

`pass2.py` builds the same JSONL adapter against the original packaged 0.10.0 candidate and the
current source. It checks equal registry dependency bindings, then compares complete snapshots
and exact error categories on 250 seeded graphs (four requests each), the 12 authored cases,
16 real-source query/mode combinations, and six scale queries. Two rounds reverse treatment
order. Cold mode clears the new token cache before each query; warm mode reuses it; uncached mode
disables it. Clearing happens outside the measured query. The old candidate has no token cache.
Every timed repetition is checked against that request's first output. Peak RSS on macOS includes
the adapter, BPE vocabulary, parsed input, graph and cache, not just the graph's heap.

```sh
python3 benches/context-010/pass2.py \
  --baseline-package /absolute/preserved-original-package/cigar-context-0.10.0 \
  --source /absolute/frozen-0.9.4 \
  --cargo /absolute/rust-1.92.0/bin/cargo \
  --target /absolute/comparison-cache --output /absolute/new-pass2-output
python3 benches/context-010/hook-regression.py \
  --baseline /absolute/frozen-0.9.4 --cargo /absolute/rust-1.92.0/bin/cargo \
  --target /absolute/hook-cache --output /absolute/new-hook-proof
python3 benches/context-010/dependency-audit.py \
  --lockfile /absolute/packaged-consumer/Cargo.lock --output /absolute/new-advisories.json
```

The hook probe runs against isolated old/new source copies and requires the old source to fail
the exact inherited-pipe deadline test while the new source passes. It does not edit old worktrees
or relax production deadlines. The advisory check sends **only public registry names/versions**
to OSV; it is a point-in-time known-advisory lookup, not a source security audit.
