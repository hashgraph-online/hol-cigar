# Bound offline answer studies

`import_answers.py` converts retained displayed answers and supplied annotations
into the common context-evaluation envelope. It does not generate answers, call
a provider, run a judge, or load the measured package. It uses the repository's
existing `benches/answer-quality/metrics.py` rules for validation, useful facts,
complete answers and confident-error episodes. The importer and metric source
are retained by hash alongside the original producer and oracle.

```sh
python benches/context-evaluation/import_answers.py /absolute/answer-study \
  --output /absolute/new-evidence
python benches/context-evaluation/evaluation.py /absolute/new-evidence \
  --output /absolute/recomputed-result.json
```

The original study and artifacts remain under `new-evidence/raw`. Re-importing
that directory with the same importer/evaluator code reproduces the evidence
manifest and result. An existing output directory is refused. Failed imports
may leave diagnostic artifacts but never a successful `result.json`; choose a
new directory after correcting the source. Keep the input immutable throughout.

## Producer input

`study.json` has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | `cigar.annotated-answer-study.v1` |
| `id`, `seed`, `baseline`, `candidate`, `cohorts` | Common evaluation identity and pairing fields |
| `evidence_class` | `invariant`, `answer-replay`, or `model-output` |
| `oracle_kind`, `model_mode` | Common oracle origin; mode is `none` or `recorded` |
| `conditions` | Nonempty explicit study design, workload, token accounting, generation settings and annotation procedure |
| `treatments` | Common treatment records: `id`, actual `version`, full `source_commit`, bound `artifacts`, `settings` |
| `tasks` | Common task records **without** `metrics`; each retains `id`, `definition`, `sha256`, `cluster`, `stratum` |
| `inputs` | Artifact IDs for `corpus`, `oracle`, `harness`, `records`, `outputs` |
| `artifacts` | Common exact-byte artifact inventory; paths are relative regular files without symlinks |

Each task definition must include boolean `answerable` and a distinct
`gold_facts` string list; answerable tasks require at least one gold fact. Retain
the question, task instructions, trustworthy corpus and adjudication rationale
in their original artifacts as well. The task digest uses the common `encoded`
JSON convention. Do not rename repeated samples as independent clusters.

`corpus`, `oracle` and `harness` use their corresponding artifact roles. `records`
uses `observations`; `outputs` uses `source`. The corpus must contain the evidence
used for judging, and the oracle must preserve the original label authority and
procedure, not the runtime gate's verdict relabeled as independent judgment.

Every treatment needs the exact package, worker or source identity it measured.
Recorded answer/replay efficacy additionally requires an independently
adjudicated oracle and a bound `model` artifact **for each treatment**, containing
the model identity and relevant generation/replay configuration. Authored test
cases must remain `invariant`. The adapter does not authenticate these declarations
or prove that a producer actually executed the named artifacts. Package/source
consistency, independence, sampling and provenance remain study-review duties.

The displayed-output artifact is a UTF-8 JSON object:

```json
{"schema":"cigar.displayed-answers.v1","answers":[{"id":"baseline-retry-0","text":"Retry three times."}]}
```

Retain the complete text shown to the user, including extra prose and citations.
IDs are unique. Empty text is permitted for a recorded empty display. Every entry
must be referenced exactly once; unreported outputs cannot silently disappear.

The `records` artifact is JSONL with one row per task/treatment/cohort/replicate.
Each row has exactly these fields:

```json
{
  "schema": "cigar.annotated-answer-observation.v1",
  "task": "retry",
  "treatment": "baseline",
  "cohort": "session-0",
  "replicate": 0,
  "status": "ok",
  "identity": {
    "version": "0.12.0",
    "source_commit": "FULL_40_CHARACTER_MEASURED_COMMIT",
    "artifacts": ["baseline-wheel", "baseline-worker", "baseline-model"],
    "harness_sha256": "EXACT_PRODUCER_SHA256"
  },
  "output": {"id": "baseline-retry-0", "sha256": "SHA256_OF_EXACT_UTF8_DISPLAYED_TEXT"},
  "coverage": {"reviewed_entire_display": true, "spans": {"limit": [[0, 18]]}},
  "annotation": {
    "episode_id": "retry", "treatment": "baseline", "stratum": "numeric",
    "answerable": true, "abstained": false, "gold_facts": ["retry-limit"],
    "context_tokens": 100, "latency_ms": 4,
    "claims": [{"id":"limit","fact_id":"retry-limit","label":"supported","confidence":0.9,"citation_labels":["supported"]}]
  }
}
```

Replace the identity placeholders with measured values; they are not valid
fixture IDs. `identity` must exactly match the treatment's version, source commit
and artifact list, plus the producer's bound SHA-256. Each annotation uses the
existing answer-quality row shape and must agree with the task's answerability,
gold facts and stratum. All displayed atomic claims need a distinct ID, explicit
support label, independently judged citation labels and confidence or explicit
`null`. Repeated supported statements about one fact still count as one fact.

`coverage.spans` maps every annotated claim ID to one or more nonempty half-open
`[start, end]` ranges in **Unicode characters**, not UTF-8 bytes or UTF-16 code
units. Spans anchor labels to the exact display; they do not prove that no factual
claim was omitted. `reviewed_entire_display: true` is an explicit annotation
attestation whose accuracy needs human review. The library cannot infer semantic
completeness from spans or treat this boolean as a safety certification.

For `failed` or `unsupported` records, `annotation` and `coverage` must be `null`.
`output` can retain an observed display or be `null` when none exists. Keep all
paired runs; these statuses make affected estimates unavailable. A completed
abstention is an `ok` record with `abstained: true`, no claims, and its actual token
cost/latency. It reduces useful-answer yield instead of receiving perfect accuracy.

## Metrics and interpretation

The adapter emits 22 metrics: factual precision, known-error and unverified
rates, annotation/confidence coverage, confident errors per all claims/per
confident claims/per episode, confident unknown claims, Brier score, citation
precision/completeness, answer coverage, complete correct-answer yield,
answerable success/refusal, unanswerable abstention, distinct useful-fact recall,
tokens per useful fact, total context tokens, and latency median/p95.

All rates retain raw numerator/denominator pairs and aggregate totals. The
confidence threshold is 0.8. Unknown labels are neither known errors nor correct
facts; unknown labels and missing confidence are excluded from Brier scoring and
their availability remains visible. Confidence is never inferred from assertive
wording. Positive token costs with no useful facts retain their zero denominator
and become unavailable rather than efficient. Total tokens are descriptive:
spending fewer tokens by refusing every task is not an improvement.

The common evaluator resamples declared task clusters, retaining strata and all
failures. Eight or more clusters permit a descriptive interval; repetitions
within one repository do not manufacture independent tasks. Token budgets,
predeclared margins, treatment order, full token accounting and corpus equivalence
must still be established before a release comparison. No preregistration is
inferred merely because an input contains a plan.

ECE and risk/coverage curves are deliberately absent from the common additive
metric set: averaging per-answer ECE produces the wrong quantity. The retained
annotations remain usable with the original answer-quality analysis for those
descriptive summaries. A later envelope extension must define their pooled and
cluster-resampled reductions before presenting comparative intervals.

The included tests use fake package/model bytes and authored answers solely to
exercise validation. They demonstrate no model hallucination reduction, runtime
performance improvement, or efficacy of a released CIGAR version.
