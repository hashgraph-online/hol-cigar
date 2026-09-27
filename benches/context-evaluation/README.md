# Context evaluation evidence

`evaluation.py` is the common offline envelope and metric verifier for the 0.14
SDK studies. It reads data and hashes files; it never loads a measured package,
executes its code, contacts a provider, or infers a result from a release label.
The producer must retain the observations and exact inputs before a report can
be recomputed. Run:

```sh
python benches/context-evaluation/evaluation.py /absolute/evidence-directory \
  --output /absolute/new-result.json
python -m unittest discover -s benches/context-evaluation -p 'test_*.py'
```

Output is created exclusively. Existing evidence/results are not overwritten.
Keep the input directory immutable while verifying it. Artifacts must be regular
files below that directory, without symlink components. Hashes are checked before
and after analysis. This is a reproducibility check, not publisher authentication,
an OS sandbox, or proof that the producer recorded every real event.

## Versioned contract

The executable validator is `evaluation.py`. All fields below are required and
unknown fields are rejected. JSON duplicate members and non-finite numbers fail.

| Document / schema | Fields |
| --- | --- |
| `manifest.json` / `cigar.context-evaluation-manifest.v1` | `schema`, `plan`, `tasks`, `observations`, `evaluator`, `artifacts` |
| Bound plan / `cigar.context-evaluation-plan.v1` | `schema`, `id`, `evidence_class`, `oracle_kind`, `model_mode`, `cluster_unit`, `seed`, `baseline`, `candidate`, `cohorts`, `treatments`, `metrics`, `inputs`, `conditions` |
| Bound task inventory / `cigar.context-evaluation-tasks.v1` | `schema`, `tasks` |
| Each raw JSONL observation / `cigar.context-observation.v1` | `schema`, `task`, `treatment`, `cohort`, `replicate`, `metric`, `status`, `value`, `numerator`, `denominator` |

An artifact has `id`, `role`, relative `path`, SHA-256 `sha256`, and exact `bytes`.
Roles are `plan`, `tasks`, `observations`, `corpus`, `oracle`, `harness`, `package`,
`worker`, `source`, `model`, and `evaluator`. The manifest's input identifiers must resolve
to their matching artifact roles. Plan `inputs` identifies the corpus, oracle and
harness. Source, package and worker archives used by treatments are hashed too.
The evaluator source is retained and its digest must match the verifier being
run. A later verifier cannot silently reinterpret an old result under the same
evidence identity. Inspect/authenticate retained evaluator code before executing
it; this verifier never executes code supplied in an evidence directory.

Each treatment has `id`, `version`, the full `source_commit`, `artifacts`, and
explicit `settings`. Each task has `id`, `definition`, `sha256`, `cluster`,
`stratum`, and the metric IDs in `metrics`. Task SHA-256 commits to its definition
as UTF-8 JSON with sorted keys, no insignificant whitespace, unescaped Unicode,
and one final newline (the `encoded` function). Corpus/oracle content and any
generated-corpus recipe must be retained, not only named by a mutable path.

Metric definitions have `id`, `unit`, `aggregation`, and `direction` (`higher`,
`lower`, or `descriptive`). Aggregations are `mean`, `median`, nearest-rank `p95`
or `p99`, `max`, `sum`, and `ratio`. Sample units are milliseconds, bytes, tokens,
and count. Ratio units are `ratio` (a fraction in [0,1]), `tokens-per-fact`,
`tokens-per-task`, and `operations-per-second`. Ratio rows carry a numerator and
denominator with `value: null`; ordinary samples carry a value with both other
fields null. Aggregate ratios divide summed numerators by summed denominators.
Use named metrics and retained task definitions to state what each denominator
counts. No empty denominator is converted to a successful zero or one.

Every task/metric/cohort must contain matching replicate IDs for every treatment.
Duplicate observations fail. `unsupported` and `failed` rows have all three
numeric fields null. A group containing either status has an unavailable value;
an incomplete pair cannot acquire a confidence interval by dropping failures.
A zero denominator produces an unavailable value. Fractions require a zero
numerator in that case; token cost may remain positive when no useful fact was
produced and must remain in the raw observations and pooled total cost.

## Interpretation and study design

Evidence classes are `invariant`, `evidence-retention`, `task-outcome`,
`answer-replay`, `model-output`, and `performance`. Oracle origin is `authored`,
`executable`, or `independently-adjudicated`. Model modes are `none`, `recorded`,
or `local`; provider execution is outside this contract. `model-output` requires
independent labels, an identified model artifact and recorded/local output.
`answer-replay` requires recorded outputs. These are necessary metadata checks;
a reviewer must still establish that labels are independent and classifications
are honest. An authored review gate cannot measure model hallucination prevalence.

Use `task-cluster` to resample independent task/repository clusters; use
`process-cohort` for paired fresh-process performance cohorts. Per-call timings
within a process remain dependent observations. Reports include pooled descriptive
values and the equal-cluster mean candidate-minus-baseline difference, plus the
mean paired relative change when every baseline cluster is nonzero. They use
2,000 seeded bootstrap draws of entire clusters for descriptive 95% intervals.
Fewer than eight clusters yield no interval. Repeating a task does not create
independent task clusters. Results are also broken down by declared stratum.

Ratios of pooled totals and equal-cluster mean differences answer different
questions; retain both and do not present one as the other. Register workload,
sampling unit, independent task count, acceptance margins and treatment order
before a release study. This verifier does not retroactively preregister a plan
or turn an underpowered study into evidence of equivalence. Promotion gates are
defined separately in the release execution plan.

## Existing shared-view benchmark adapter

`benchmarks/shared_views.py` now supports `--agents 1`, `5`, or `12`, retaining
all timed calls, outcome events, host-plus-worker RSS samples, SDK source identity,
worker identity and harness identity. The default remains five clients. Each
cohort uses a fresh installed environment process; clients within that process
are still scheduled by one trusted host. This is not a broker concurrency test.

Run the harness against installed baseline/candidate wheels, then bind a selected
pair to the exact archives:

```sh
python benches/context-evaluation/import_shared_views.py \
  --raw /absolute/shared-views.json \
  --baseline 012-private --candidate 013-views \
  --baseline-wheel /absolute/baseline.whl \
  --candidate-wheel /absolute/candidate.whl \
  --baseline-commit FULL_BASELINE_COMMIT \
  --candidate-commit FULL_CANDIDATE_COMMIT \
  --output /absolute/new-evidence-directory
```

The legacy variant labels belong to the retained harness; measured versions and
exact source/worker bytes, not labels, identify the treatments. The adapter checks
installed package code/data against the wheel and its worker against a bundled
executable. Bytecode and native workers are excluded from the package source hash;
the selected worker has its own SHA-256 binding. It imports raw measurements and
ignores the old summary. Summary-only historical reports are rejected. Imported
plans explicitly disclose that they were assembled after the existing study.

The adapter emits **performance** evidence only. Authored abstention/freshness
events remain in the retained raw report. The two-cohort 12-client development
smoke using retained 0.12/0.13 installations tests this pipeline; it is not a 0.14
benefit or release qualification claim. Answer-quality and Hiero producers still
need adapters with their original oracle and adjudication identities preserved.
