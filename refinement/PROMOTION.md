# Statistical comparison and constrained Pareto promotion

`tools.refinement.statistics` consumes one canonical `cigar.comparison-input.v1` attachment. Each
task/seed row contains champion, candidate, and immutable Honey metric vectors with raw
numerators, denominators, applicability, units, and evaluation digests. The comparator rejects
missing metrics, noncanonical pair order, arithmetic substitution, applicability drift, incomplete
seed coverage, altered policy/Honey identities, and incomplete Tier 0/Tier 1 inventories before
deriving a result.

`refinement/policy/promotion-v1.json` is the versioned authority. It preserves the blocking v1
success/critical-recall/evidence-token-precision family, keeps newly calibrated Tier 2 fields
diagnostic, declares hard metric and external invariants, sets absolute SLOs and relative
performance limits, requires all nine protected strata, and binds the Honey 0.9.1 anchor bytes.

## Statistical method

Repetitions of one task under different assignment seeds are one correlated cluster. Each
bootstrap repetition samples whole task clusters within each stratum and preserves every seed in
the chosen cluster. Development evidence uses its declared 95% policy; shadow, promotion, and
release evidence require at least 30 independent tasks per stratum, two seeds, 10,000 repetitions,
and 99% intervals.

Benefit is oriented so positive is always better. Blocking primary metrics must be non-inferior to
both the current champion and Honey, meet absolute SLOs, and pass independently in every protected
stratum. Declared improvements use one-sided bootstrap tail probabilities with Holm step-down
correction across the applicable primary family. Both assignment seeds must have positive
direction. Performance metrics apply paired relative intervals, absolute ceilings, and explicit
regression limits.

`tools.refinement.promotion` maps the comparison to one closed decision code. It cannot turn
invalid evidence, a hard invariant failure, a protected-stratum loss, a noisy result, a
seed-inconsistent result, or a performance regression into promotion.

## Exact commands

```sh
python3 -m tools.refinement.statistics compare \
  --input /absolute/evidence/comparison-input.json \
  --policy /absolute/hol-cigar/refinement/policy/promotion-v1.json \
  --honey-anchor /absolute/hol-cigar/refinement/baselines/honey-anchor.v1.json \
  --schemas /absolute/hol-cigar/schemas/refinement

python3 -m tools.refinement.statistics replay \
  --expected /absolute/evidence/comparison.json \
  --input /absolute/evidence/comparison-input.json \
  --policy /absolute/hol-cigar/refinement/policy/promotion-v1.json \
  --honey-anchor /absolute/hol-cigar/refinement/baselines/honey-anchor.v1.json \
  --schemas /absolute/hol-cigar/schemas/refinement

python3 -m tools.refinement.promotion decide \
  --comparison /absolute/evidence/comparison.json \
  --schemas /absolute/hol-cigar/schemas/refinement
```

Non-promoted but evidence-valid candidates may be appended to an external owner-only Pareto
archive. Records are immutable and hash chained. Each record stores objective values, the
comparison IDs that dominate it, and the nondominated comparison-ID frontier after that event.
This research frontier never changes the champion; only a `promote` decision can do that.
