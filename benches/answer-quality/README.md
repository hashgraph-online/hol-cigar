# Offline answer-quality evaluation

There are two separate tools. `qualify.py` tests the runtime's claim-review
contract with authored cases and oracle reviews. `metrics.py` measures displayed
answers from **independently annotated** model/application runs. Neither tool
contacts a provider. Do not describe fixture success as a model hallucination rate.

## Runtime contract qualification

Build a 0.11.0 release worker and the baseline/candidate probes using
[`../context-011/qualify.py`](../context-011/qualify.py), then run:

```sh
python3 benches/answer-quality/qualify.py \
  --worker /absolute/path/to/cigar-context-worker \
  --baseline-probe /absolute/path/to/probe-baseline \
  --candidate-probe /absolute/path/to/probe-candidate \
  --output /absolute/path/to/new-directory
```

The runner records 32 scenario families at five confidence levels, including
missing confidence: 160 combinations. It tests supported/paraphrased claims,
numeric and negation errors, irrelevant/missing/fabricated citations, false
premises, unknown verdicts, partial reviews, explicit conflicts, copied/shared
sources, source/authorization/policy changes, stale reviews, source instructions,
empty answers and exhausted budgets. Every supplied factual verdict is an oracle
fixture. Four supported families (20 combinations) must release; the other 140
must abstain or return the declared error. Low confidence does not bypass review.

Each combination uses a fresh worker, two untimed warmups and ten measured calls.
Timings include IPC and current-snapshot compilation, exclude worker startup and
external semantic review, and are correlated repetitions. Raw inputs, responses,
timings and hashes are retained. This tests review enforcement; a dishonest or
incorrect trusted reviewer can still approve a false claim. In particular the
resolved-conflict control assumes that the reviewer's resolution is justified;
the library does not discover or check that resolution semantically.

Fourteen separate evidence-retention cases run against both core versions.
The twelve original quality fixtures include the semantic gap, undeclared
counterclaim and unanswerable request. Two explicit lead/edge ablations show
what trusted ingestion must supply. All cases, including failures, are reported.
Gold phrase recall and useful-block precision measure retained source text,
not factual correctness or model output. The unanswerable case has no gold fact
denominator: report its correct empty context separately, never as a recall failure.
Source-reference integrity and exact
budgets are verified by the Rust probe.

## Independently labeled answer metrics

Use one JSONL row per distinct episode and treatment. Label **every displayed
atomic factual claim**, including additional prose outside a structured response.
Keep the evaluator's labels independent from the gate's reviews. `unknown` means
unresolved annotation; it is neither correct nor a known factual error. Evidence
support is relative to a declared trustworthy corpus, not universal truth.

```json
{"episode_id":"retry-1","treatment":"v0.11.0","stratum":"numeric","answerable":true,"abstained":false,"gold_facts":["max-retries"],"context_tokens":300,"latency_ms":12.5,"claims":[{"id":"claim-1","fact_id":"max-retries","label":"supported","confidence":0.9,"citation_labels":["supported"]}]}
```

`fact_id` maps an independently judged useful claim to a gold fact, or is null.
Distinct matched facts count once, so repeating a correct statement cannot
inflate recall. A successful answer must cover every gold fact and contain no
unsupported/unknown claim. Refusing an answerable question lowers useful yield.
`citation_labels` contains a support judgment for each claim/citation pair, not
just whether the source exists. `confidence` is a finite probability [0,1] or
explicit null; missing confidence is never inferred from assertive language.
`context_tokens` is the actual context count, including unsuccessful attempts if
that is the study's declared accounting unit; record provider usage separately.

```sh
python3 benches/answer-quality/metrics.py annotated-answers.jsonl \
  --output answer-metrics.json --baseline v0.10.0 --candidate v0.11.0
python3 -m unittest discover -s benches/answer-quality -p 'test_*.py' -v
```

The output includes per-treatment and per-stratum factual precision, known error
and unverified rates, confident errors (threshold 0.8) with both denominators,
annotation/confidence availability, Brier score, ten-bin ECE, risk/coverage
points, citation precision/completeness, answer coverage, complete correct-answer
yield, useful-fact recall, answerable refusals, unanswerable abstention, exact
tokens per useful fact, and latency p50/p95. Empty denominators are null.
Calibration excludes unknown labels and unavailable confidence, with counts
explicitly reported. Confidence curves are descriptive, not calibrated safety
guarantees. Duplicate episode/treatment rows and inconsistent annotations fail.

An optional paired bootstrap estimates changes in complete correct-answer
yield and the fraction of episodes containing a confident factual error,
resampling entire paired episodes with seed 1100 (2,000 draws). Both
treatments must contain the same episode IDs, gold facts and strata. Use truly
independent episodes or aggregate/cluster repeated source/project samples
upstream. These intervals cannot make authored fixtures representative of users.
For live-model confident-error efficacy and power/acceptance criteria, follow the
[measurement plan](../../docs/proposals/cigar-0.11.0-plan.md).

The new contract is absent from 0.10.0. Its baseline value is **unavailable**, not
an invented 100% hallucination rate. Compare real applications only after defining
their generation, review and display behavior. Never treat “no native gate” as
proof that an application's existing safeguards failed.
