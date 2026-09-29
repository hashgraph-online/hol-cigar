# Scoped-view cost diagnostic

This source-only study separates indexed retrieval from the additional work of
constructing and committing an authorized view. It compares three treatments in
fresh Python/native processes with identical input documents:

- `root`: unrestricted host-owned graph compilation.
- `view-one`: a view authorized for one hot document in the same large graph.
- `view-all`: a view authorized for the hot document and every cold document.

Every call selects the same one required document, under the same token budget.
The controls have different authorization semantics; a faster root is not a
replacement for a restricted agent view. The result identifies costs worth
profiling, not a CIGAR version improvement or a recommendation to bypass scopes.

Build an optimized diagnostic worker with symbols so native samples are useful:

```sh
CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=1 \
  cargo build --locked --release -p cigar-context \
    --features bpe,broker-persistence --bin cigar-context-worker
python benchmarks/scope_profile.py \
  --worker /absolute/target/release/cigar-context-worker \
  --output /absolute/new-scope-study \
  --documents 100 1000 5000 --cohorts 8 --rounds 100 --native-profile
```

The native profiler option requires macOS `/usr/bin/sample`. Linux can run the
same workload without that option and use a separately recorded native profiler.
The worker's hash and byte size, SDK source hash, harness/helper hashes, Git HEAD,
dirty-worktree flag, corpus bytes and host/runtime description are retained.
Keep the build command/settings with the evidence; the script cannot infer a
compiler configuration from an executable. It neither installs packages nor
contacts services/models. It does not claim OS network denial.

Latency includes Python serialization, queue/pipe transport, native compilation,
result decoding and the harness's exact-selection/budget checks, rendered-text
hash and complete-result JSON hash. Worker startup, ingestion and five warmups are excluded. A concurrent
20 ms sampler retains simultaneous Python-plus-worker resident bytes. These are
RSS samples, not PSS or a claim to have caught every allocation peak.

Treatments rotate order within eight paired process cohorts. The comparison
resamples process medians, not individual calls. Pooled call quantiles remain
descriptive and do not create additional independent observations. Failed or
missing processes cannot produce a successful paired result; changed corpus or
selected output invalidates the comparison.

When requested, a separate five-second native sampling pass and 100-call Python
profile run after measured latency/RSS collection, once per treatment at the
largest corpus size. Inspect the `*.native.txt` stacks and `*.python.pstats`
call paths. Profiler overhead is not included in the reported latency or RSS.
These profiling files can contain local source paths; retain them in the private
evaluation directory rather than a public source commit.

This is a single-client, warm-scope diagnostic. It does not qualify broker
scheduling, independent-agent fairness, mutation invalidation, durable storage,
installation, model accuracy or end-to-end application performance. An accepted
optimization still needs exact valid identity preservation, stale/revoked scope
tests, paired before/after measurements and the full release performance gates.

Use the companion comparison for a native optimization, building both workers
with identical compiler settings and retaining their build receipts:

```sh
python benchmarks/scope_compare.py \
  --baseline-worker /absolute/baseline/cigar-context-worker \
  --candidate-worker /absolute/candidate/cigar-context-worker \
  --output /absolute/new-scope-comparison \
  --documents 100 1000 5000 --cohorts 8 --rounds 100
```

This retains both worker executables, exact corpora, harness sources and the
candidate's uncommitted native diff. It alternates worker order in each paired
fresh-process cohort and runs the same current harness against both. Complete
result hashes must agree within each treatment, including scope IDs and snapshot
fields; equal rendered text alone is insufficient. Different scope treatments
are allowed to produce different scope commitments. Profilers do not run during
this comparison. Earlier diagnostic timings using only rendered-text hashing
are not interchangeable with timings from the current harness.
