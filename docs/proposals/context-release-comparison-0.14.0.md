# Installed regression comparison for 0.14 development

Register this plan before measuring the current candidate. Compare the released
0.12 wheel, the retained 0.13 alpha wheel and a source-bound development wheel in
three fresh environments using the same Python 3.14.7 executable and protobuf
6.33.5. Bind archive, source, worker, fixture and harness hashes. The development
wheel may still carry the alpha version; labels must use its distinct source
commit and archive hash, never infer identity from a shared version string.

Run each child under macOS `sandbox-exec` with network access denied. Do not run
local builds, tests, other benchmarks or a soak concurrently. Hosted CI on other
machines may continue. No model provider or external service participates.

Retain the existing `benches/context-012/compare_installed.py` child probes and
`benchmarks/shared_views.py` child workloads without changing their measurements.
Freeze their bytes and their generated compile/answer cases before installation.

- Compare all 172 complete compile results, native verification, reviewed-answer
  fixture decisions at all five confidence settings, valid semantic bundle ID,
  rejection of ambiguous digest mappings and retained public exports.
- Measure import, local/remote API resolution, first graph, graph construction
  and worker verification in 25 fresh-process cohorts after two discarded warmup
  cohorts. Measure Python allocations separately in five fresh-process cohorts;
  do not combine traced and untraced latency samples.
- Run the existing 768-document/64-query RPC workload in eight fresh-process
  cohorts per treatment. Preserve full-result identities, compile samples and
  the update/compile/delta/apply cycle. Native verification runs outside the
  compile timer. Compare cohort medians, not individual dependent calls.
- Run eight fresh-process cohorts for 1/5/12 clients, 64 documents per source,
  50 scheduled replacement/review rounds. Include legacy/shared-root/private
  modes for every version, and views for alpha/candidate (unsupported in 0.12).
  Measure every call and simultaneous host+worker RSS. These scoped clients live
  in one SDK host; the independent-process broker study remains separate.

Rotate the three-treatment order deterministically across cohorts. Keep failures,
outliers and unavailable results. An incomplete cell fails the study; a corrected
harness requires a newly frozen study directory. Do not rewrite old observations.

Compare the candidate with each supported reference in the same workload/mode.
Use paired cohort percentage changes and a seeded, cohort-level bootstrap for
descriptive 95% intervals. The existing guardrails are at most 10% median latency
increase and 20% sampled total RSS increase. Report p95/max separately, retaining
all tails. New-feature cross-mode comparisons are benefit/cost descriptions,
not equivalent-workload non-regression gates. Exact output/decision mismatch,
scope/budget/citation failure, stale acceptance or cleanup failure blocks promotion.

These authored fixtures establish compatibility and execution invariants, not
semantic truth or a live-model hallucination rate. This one-host study is distinct
from seven-platform installed artifact qualification and the 24-hour broker soak.
