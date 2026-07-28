# Versioned intelligence profiles

`balanced.v1` is Honey's frozen default. Its retrieval weights, compiler profile
digest, plan/bundle/manifest golden identities, and all default constructors remain
unchanged. Experimental selection is compiled only for the non-published
`cigarbench-consumer` through explicit Cargo features and an optional,
assignment-bound `intelligence_profile` field. Absence selects `balanced.v1`.

`balanced.v2-candidate.1` is not a default and cannot become one without an R06
shadow promotion decision. It changes only deterministic, authorized metadata
features and versioned planning/packing behavior:

| Feature | Direct authorized source | Integer definition |
|---|---|---|
| exact match | exact identity, exact path, or declared exact-term evidence after partition authorization | 10,000 for identity; 9,000 for path/declared term |
| lexical match | normalized query terms intersecting the authorized document lexical projection | `8000*matched/query + 1500*declared + 500*path`, capped at 10,000 |
| task proximity | declared-term or exact-path match | 10,000 or 8,000 |
| verification | atom `quality.confidence` | millionths divided by 100 |
| novelty/coverage | atom `quality.coverage` | millionths divided by 100 |
| entity coverage | matched authorized query/declared terms | stable SHA-256-derived 64-bit set |
| graph proximity | authorized active edge traversal | 10,000 minus 250 per bounded depth |
| freshness/staleness | authorized tenant revision lag | frozen integer definitions |

The v2 query planner adds depth-two graph expansion only after an exact authorized
root. A separate bounded current-state augmentation subprofile is retained for
ablation, but is not enabled in `balanced.v2-candidate.1`. Every cap is at most 256
and each stage retains a timeout.

The compiler profile makes marginal requirement/entity gain depend on the current
selection, charges direct dependency count, rewards a previously absent lane, and
penalizes already-covered requirements/entities. It ranks by absolute marginal
utility rather than v1 utility density so high-value evidence cannot be displaced
solely by shorter low-value material. It also disables the v1 additive local-swap
repair, whose sum-of-utility objective can replace one high-value block with two
individually weaker distractors. A minimum lexical feature of 8,000 prevents
optional low-overlap candidates from filling unused budget after the high-overlap
evidence has been selected. All arithmetic is checked integer arithmetic.
Eight single-component ablations have distinct profile digests, enabling
paired attribution. The v1 digest deliberately omits the zero-valued experimental
fields, preserving its historical identity.

Denied documents are removed before v2 feature generation, graph traversal, and
coverage hashing. No denied payload, path, term, edge, quality signal, or task label
can affect a candidate feature.
