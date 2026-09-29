# CIGAR 0.11.0 measurement and candidate plan

Registered before implementation and candidate measurements, 2026-09-23.

## Scope and baseline

Improve the standalone `cigar-context` library and local Python/TypeScript SDKs.
Baseline is the available 0.10.0 release tag, `v0.10.0-beta.1`, commit
`11c38b0ba4fa00e1a03cad99ca316a875a03babd`. Candidate starts from 0.10.1 commit
`70122ec8`, including its retrieval/indexing improvements. The legacy Honey daemon
remains a separate 0.9.4 product. Prepare a local candidate; publication, signatures,
hosted qualification, and production claims require their own evidence.

## Problem

Retrieval relevance, lexical coverage, an intact digest, a citation that exists,
and model confidence are not proof that a claim is true. Current CIGAR preserves
declared dependencies/counterclaims but does not provide an answer-release gate.
An application can mistake well-formed context for a verified answer.

Add a bounded claim-review contract. The owning application supplies factual
verdicts separately from the model's draft, from a trusted human, deterministic
oracle, or separately evaluated verifier. Reviews bind exact claim content,
citations, confidence, and the expected snapshot. Recompile using current
authorization before checking an answer. Require every released claim to have
valid selected citations, adequate distinct sources, a supported verdict, and
acknowledgment of explicitly linked counterevidence. Missing evidence/reviews
must block release. Self-reported confidence never grants permission. This gate
enforces a review contract; it does not discover truth or make a bad judge reliable.

## Success criteria fixed before measurement

| Dimension | Metric and local candidate gate |
| --- | --- |
| Confident unsupported claims | Zero release of adversarial drafts with unsupported/contradicted/unknown/unreviewed claims, including confidence >= 0.8. Report errors per all claims and per confident claims. |
| Usefulness | All fully supported, properly cited/reviewed control answers pass; report answer coverage, correct-answer yield, answerable refusal rate and unanswerable abstention separately. Never award perfect accuracy to an empty denominator. |
| Provenance | Zero release with nonexistent citations, stale snapshots/reviews, withdrawn or unauthorized evidence, ignored explicit counterevidence, or insufficient independent sources. Copied text/aliases cannot multiply witness counts. |
| Calibration | Brier score, ten-bin ECE, confidence availability, and risk versus coverage on independently labeled claims. Missing confidence is missing, not zero or certainty. No calibration claim from scripted confidence values. |
| Retrieval | Preserve complete results for the existing 1,434-request compatibility corpus; separately report gold evidence recall/precision and counterclaim/dependency retention on authored risk cases. |
| Tokens | Exact rendered BPE tokens, reserve/budget compliance, and tokens per supported useful claim. No token-saving claim that conceals missing evidence. |
| Speed | Re-run common/rotating/update workloads against 0.10.0 with identical dependencies and opposite treatment orders. Target >= 50% median reduction on large common queries, rotating queries, and unchanged-source updates. Report cold and warm p50/p95 and regressions too. |
| Memory | Report whole-process peak RSS and cache occupancy. Investigate > 15% peak RSS increase against baseline; do not hide memory traded for speed. |
| New review overhead | Report p50/p95 including current-snapshot recompilation, separately from retrieval. Local diagnostic target: p95 < 10 ms for bounded small cases after warmup. |
| Reliability | Rust format, strict clippy, feature/no-feature tests, SDK tests/types/lint, exact budgets, deterministic snapshots, source replacement and delta integrity pass. |
| Packaging | Consistent 0.11.0 core/worker/SDK identities; build and exercise local distributable candidate where tools permit. Preserve a manifest of source/artifact/evidence hashes. |

These are conjunctive gates, not a weighted score that lets speed compensate for
unsupported answers. Synthetic controls test enforcement and metric correctness;
they do not estimate real-world hallucination frequency. Distinct scenario counts
and timing repetitions are reported separately.

## Experiments

1. Freeze the baseline, plan, regression corpus and adversarial scenario taxonomy.
2. Implement answer review in Rust and expose identical worker/SDK operations.
3. Exercise supported answers, numeric/negation errors, irrelevant citations,
   missing evidence, false premises, conflicting sources, copied witnesses,
   injection-bearing source text, policy/source changes and stale review reuse.
   Record exact observations and expected outcomes; identify these as authored
   contract tests with oracle reviews, not independent model trials.
4. Re-run the existing release comparison with fresh raw data. Verify full
   snapshots/errors across cache modes, measure tokens/RSS/timing, and retain
   dependency/source/binary hashes.
5. Provide a reusable offline evaluator for independently annotated model runs.
   Validate denominators, duplicate IDs, finite confidence and label completeness.
   Report calibration and paired episode-bootstrap intervals without treating
   repeated calls to one case as independent evidence.
6. Qualify the local candidate and write the final comparison with explicit gate
   results, limitations and remaining hosted/publication requirements.

For a subsequent model efficacy study, hold generator/model version, prompts,
temperature, corpus and token budget constant; randomize paired treatment order;
separate development and held-out questions by source/project; blind claim
annotation and adjudicate disagreements. Compare the same model/application with
0.10.0 versus 0.11.0, and ablate the new gate to separate retrieval from refusal.
Power the sample from a pilot; require a paired confidence interval showing a
reduction in confident errors, with at most 2 percentage points of lost supported
answer yield. Score every factual claim in the displayed answer, not only claims
the model volunteered for checking. Record provider token usage, cost and latency.
Do not use gate verdicts as the independent evaluation labels. Live-provider
measurements are pending authorization/configuration; offline results cannot
satisfy that efficacy gate.

## Research basis

- [FActScore](https://arxiv.org/abs/2305.14251) motivates atomic support labels and
  explicitly leaves recall outside its factual-precision metric. Pair precision
  with useful-answer yield and abstention to prevent vacuous success.
- [Evaluating Verifiability in Generative Search Engines](https://arxiv.org/abs/2304.09848)
  distinguishes comprehensive citation coverage from whether citations support
  the statements attached to them. Citation existence alone measures neither.
- [Language Models (Mostly) Know What They Know](https://arxiv.org/abs/2207.05221)
  studies elicited confidence. Treat confidence as an empirical prediction to
  calibrate against labels, never as an independent factual verdict.
