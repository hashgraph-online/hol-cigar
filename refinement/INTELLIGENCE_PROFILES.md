# Versioned intelligence profiles

`balanced.v1` is published Honey 0.9.1's frozen behavior and the Honey 0.9.2
release default. Its retrieval weights, compiler profile digest, and historical
plan/bundle/manifest golden identities remain unchanged. It remains selectable in
Honey 0.9.3 for exact replay; new daemon configurations default to `balanced_v3`.

`balanced.v2-candidate.1` is the internally versioned H1 behavior retained as an
explicit experimental opt-in. The identifier retains its private profile name so
existing evidence and digests do not rotate during packaging. It changes
only deterministic, authorized metadata features and versioned planning/packing
behavior:

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

The selected retrieval profile is propagated explicitly through the benchmark
application's planner, staged retriever, reducer, validator, and compiler. The v2
plan fingerprint, authorized index fingerprint, retained retrieval receipt, compiler
profile pin, and observation identity bind the same retrieval-profile identifier and
digest. A retriever/profile mismatch, a score that cannot be recomputed under the
selected profile, or a score changed after same-version coalescing fails closed as a
corrupt generation. Balanced-v1 continues to use its frozen fingerprint domains and
default entry points so its historical plan, index, receipt, bundle, manifest, and
explanation identities do not rotate.

## Exact-source H1 release qualification

The H1 release lane builds the published Honey source, the frozen H1 champion, and
the current 0.9.2 candidate as three distinct release executables. All three use the
frozen H1 champion's measurement harness, so release work cannot move its own
measuring stick. The external plan and build-set receipt bind each executable's
product source, harness source, intelligence profile, toolchain, retained lockfile,
byte digest, and clean post-build state.

Tier-1 checks are not caller-authored status strings. `gate_evidence` executes the
closed named-command mapping and emits one authenticated receipt per policy gate
using a key distinct from the final qualification key. `intelligence` accepts only
the exact plan, build set, and receipts. It carries all three source and executable
identities through observations, comparison, Tier-0 evidence, and final attestation.
Legacy aggregate gate attachments and an unbound three-treatment executable fail
closed.

Tier-1 commands run with isolated `HOME` and `TMPDIR` values rooted in a short,
owner-private temporary path so macOS Unix-socket tests remain within platform path
limits. Offline Python gates may reuse only a canonical, owner-controlled uv cache;
credentials, proxies, and other ambient environment values remain excluded.

A bounded consumer process exit is measurement data, not a controller exception.
The profile runner records its safe failure code, output digests, executable and
assignment identities, latency, zero-valued task metrics, and evaluator attestation,
then continues the other treatments. Timeouts, output overflow, descendants,
malformed observations, profile-transition drift, source drift, and custody errors
still abort the qualification without producing an authoritative result.

All of these artifacts remain private until the single public-PR approval
breakpoint. Qualification evidence cannot tag, release, publish, or mutate the
public repository.

## H2 requirement-aware candidate

`balanced.v2-candidate.2` is the private Cycle B H2 candidate. It inherits the
qualified H1 compiler packing configuration without changing token-budget behavior.
Before compiler packing, it deterministically orders candidates using:

- newly covered blocking and nonblocking requirements;
- newly covered query-concept bits;
- source, source-section, and atom-kind diversity;
- generic lexical-match, repeated-requirement, repeated-concept, and authenticated
  similarity penalties; and
- the H2 retrieval score, estimated token count, source identity, path, and version
  identity as the closed tie order.

All candidates returned for a blocking requirement retain H1's protected status.
The explanation order therefore cannot silently reduce blocking-stage recall. If a
blocking requirement has no candidate at all, reduction fails closed instead of
emitting partial ranking evidence.

Every H2 compiler-intake candidate has one winner-versus-runner-up decision. The
decision records its complete checked-integer score decomposition, new coverage,
diversity signals, selection basis, and remaining uncovered blocking requirements.
The H2 compiler consumes the resulting ordinal before its unchanged H1 utility tie
order, including when choosing the representative for a blocking requirement.
The evidence digest binds the exact plan, H2 retrieval profile and digest, critical
requirement inventory, every decision, and every tie outcome. The compiler rejects
missing, corrupt, profile-mismatched, incomplete, or uncovered-critical evidence and
seals valid summaries and decision chunks into optional selection-manifest
extensions under `cigar/ranking-evidence.v1` and
`cigar/ranking-decisions.v1/*`.

H2 does not reserve token capacity, introduce new representations, or change the H1
packing policy. Those changes remain isolated to Cycle B H3 so ranking and packing
effects can be attributed separately.

## Honey 0.9.3 balanced profile

`balanced.v3` promotes H2's requirement-aware ranking to the Honey 0.9.3 release default and adds
one isolated compiler rule: optional packing saturates after two selected items per requirement.
Candidates that add a previously unseen entity remain admissible after requirement saturation.
Mandatory candidates, dependency closure, blocking-requirement roots, policy checks, lane budgets,
and exact profile-bound ranking evidence remain unchanged and fail closed.

The implementation maintains selected requirements, entities, sources, sections, kinds, and maximum
per-candidate similarity penalties incrementally. Candidate evaluation therefore no longer rebuilds
those sets or rescans every previously selected candidate inside the ranking loop. Golden H2 ranking
tests lock score decomposition and ordering while the 0.9.3 compiler fixture demonstrates that five
same-entity optional blocks consume 20 tokens instead of H2's 100-token fill-to-budget behavior.

The fixture is an exact deterministic regression bound, not a generalized provider-token or model
completion claim. Release qualification must still measure identical assignments and enforce zero
blocking-requirement loss, zero budget overflow, and the existing completion proxy before promotion.
At 128 candidates, the ranking operation-count fixture records 8,128 incremental similarity updates
instead of the prior loop shape's 349,504 selected-candidate evaluations, a 43-fold reduction in that
bounded hot-loop operation. Wall-clock qualification remains separately required.

Private paired qualification selects the transition explicitly:

```console
python3 -m tools.refinement.intelligence \
  --champion-profile balanced.v2-candidate.1 \
  --candidate-profile balanced.v2-candidate.2 \
  <all other bounded qualification arguments>
```
