# CIGARBench analysis policy

The canonical analyzer is `benches/cigarbench/cigarbench.py`. It consumes the
versioned raw-event stream only after binding it to the seeded plan, canonical
manifests, environment capture, installed-consumer multihash, and an independent
evaluator attestation. It performs task-clustered paired bootstrap analysis and
emits global and per-stratum results. Release analysis requires at least 30
independent tasks and 30 post-warm pairs in every fixed v1 stratum,
treatment-order balance, calibrated host variance below 5%,
qualification-class events, and at least 10,000 bootstrap resamples. Smoke
fixtures are permanently reported as `insufficient_evidence`.

PolicyBoundary, EffectCrash, and MultiProject-Switch are evaluated separately;
a global aggregate cannot conceal a failure in any of those strata. Rare harm
uses a Wilson interval, so repeated measurements of one task and zero events in
a small sample cannot manufacture a narrow interval. The hidden seed is never
copied into evidence: only its SHA-256 multihash commitment appears.

The checked-in baseline manifest is a protocol inventory, not evidence that the
seven baselines or five ablations ran. Qualification remains blocked until the
pinned installed consumer implements each selected baseline/ablation and an
evaluator produces fresh attested results for it.
