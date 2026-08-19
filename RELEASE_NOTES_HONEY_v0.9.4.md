# CIGAR Honey v0.9.4 candidate release notes

CIGAR is an alpha project from [HOL.org](https://hol.org).

| Field | Value |
| --- | --- |
| Version | `0.9.4` |
| Channel | `honey` |
| State | Alpha developer preview |
| Context ABI | `cigar.context.v1` |

Honey 0.9.4 adds an opt-in `balanced_v4` context profile focused on lower repeated context, higher
evidence value per token, deterministic workflow recovery, and less ranking/packing work. It remains
unpublished and unsupported. These notes describe source-qualified candidate behavior; they do not
claim that the final installed artifacts, signatures, reproducibility, or long-running campaigns
have passed.

## What changed

- `balanced_v4` adds dense ordinal retrieval state, bounded requirement bitsets, an allocation-free
  winner/runner-up scan, cached similarity state, and a maximum 32-candidate cancellation polling
  interval. `balanced_v1` and `balanced_v3` identifiers, digests, errors, and golden outputs remain
  frozen.
- Retrieval derives five risk classes from trusted operation and requirement metadata. Effect-
  critical requirements reserve independent corroboration when available, and optional intake
  stops when contextual marginal utility is no longer positive.
- Compiler packing uses exact tokenizer counts, cached representation/dependency closures,
  conservative dominance, risk-aware corroboration, and a positive-utility stop rule. Mandatory
  material, blocking evidence, dependency closure, lane budgets, and conflict constraints remain
  fail-closed.
- Workflow context sessions are now first-class in Rust, Python, TypeScript, and Go. The four SDKs
  share the same bounded phase/event contract, durable resume actions, exact replay dimensions,
  error vocabulary, delta-chain checkpoint, ambiguous-effect reconciliation, and retry
  revalidation fences.
- Daemon workflow checkpoints persist identity-only state through the existing v5 service-record
  path. No storage format v6 or new SQLite migration is introduced.
- Behavior rollback selects `balanced_v3` or `balanced_v1` and restarts. Binary rollback is allowed
  only against a separately restored verified compatible state; an older runtime must never open or
  rewrite candidate state.

## Retained source and workflow evidence

The integrated source-linked five-workflow-by-20 diagnostic completed all 300 treatment
observations with 100% completion, blocking coverage, gold-source coverage, citation resolution,
and useful precision, with zero semantic duplicates. Mean exact selected tokens were 622.63 for
0.9.4, 1,253.36 for frozen 0.9.3, and 2,252.99 for frozen 0.9.2: reductions of 50.323% and 72.364%
for that registered cohort.

Against frozen 0.9.3, aggregate planner/reducer/compiler p50 improved 63.846%, compiler p95 improved
67.987%, and reducer p50/p95 improved 69.790%/74.207%. Aggregate phase p50 improved 51.322% versus
frozen 0.9.2. These are source-linked measurements on the registered qualification host, not a
cross-machine wall-clock guarantee.

The independent deterministic Hiero RC cohort retained 250 candidate observations, 50 per
workflow. Completion, blocking/gold/citation coverage, replay, fail-closed behavior, and all nine
negative cases were 100%; mean delta reuse was 75.134%. Mean CIGAR-supplied tokens improved 50.039%
over 0.9.3 and 72.217% over 0.9.2; mean CIGAR pipeline latency improved 59.781% and 77.306%. Provider
latency and provider tokens were recorded separately and did not enter those claims. No live-model
experiment was treated as deterministic evidence.

A current-source rerun against 0.9.4 commit `de8ec221` independently verified as evidence ID
`ae0abda8daa92a00b1c5e1d75b947ee35d9abc75ef7364be0549558ad7b5c1e4`. All 44 evaluated claims
passed. Mean exact tokens improved 50.039% versus frozen 0.9.3 and 72.217% versus frozen 0.9.2;
mean internal CIGAR pipeline latency improved 59.627% and 73.584%. Its larger 50-trial cohort also
showed a 48.339% EVM reducer-p95 improvement over 0.9.3, closing the tail uncertainty from the
preceding 20-trial diagnostic. See the
[content-free three-way comparison report](docs/release/honey-0.9.4-hiero-three-way-comparison.md).
Because this documentation update follows the measured commit, final frozen installed-artifact
qualification remains required.

A separate clean-source allocation qualification ran 200 alternating v3/v4 pairs after 40 warmups
at both 128 and 512 candidates. Peak request-scoped compiler allocation fell 46.806% and 53.263%;
allocated bytes fell 12.681% and 9.041%; allocation counts fell 20.416% and 12.813%. The fixed 40%
peak-reduction threshold, absolute peak bounds, and byte/count non-regression gates all passed and
were independently recomputed from the content-free raw observations. This is source qualification
for commit `1d7bf983`, not final installed-RC evidence; it must be rerun after the source freeze.

The retrieval v3-equivalence oracle matched 102,400 generated cases, and the v4 implementation
retained exact legacy profile outputs. Property/model tests, Miri, restart/crash-boundary tests,
content-free telemetry canaries, four-SDK workflow parity, and the focused compatibility/storage
sentinels pass. Long-duration fuzz, mutation, sanitizer, installed-runtime, two-builder, signing,
and soak gates remain separate and must not be inferred from those results.

## Compatibility and upgrade

The Context ABI remains `cigar.context.v1`; the public surface remains 45 operations and 70 nominal
payload types; protocol compatibility remains `1.0` through `1.x`; Python keeps distribution
`hol-cigar` and import `cigar_sdk`; and storage remains v5. During candidate qualification an
omitted intelligence profile still selects `balanced_v3`; select `balanced_v4` explicitly and
require `getCapabilities` to report `intelligence-balanced-v4`.

Upgrade only from a verified backup, retain the prior versioned installation and checksum, and
rehearse the candidate on a separately restored empty target. Follow
[`docs/guides/honey-0.9.4-upgrade.md`](docs/guides/honey-0.9.4-upgrade.md) for exact stop conditions
and rollback separation.

## Candidate inventory and open gates

The intended attachment inventory remains the closed 13-file Honey set: source, docs,
schemas/conformance, Apple-silicon runtime, TypeScript SDK, Python wheel and sdist, Rust local-
registry kit, Claude Code plugin, demos, these release notes, release manifest, and `SHA256SUMS`.

The Python distribution uses the public repository's authorized
`.github/workflows/publish-hol-cigar.yml` Trusted Publishing identity. After the source PR is
merged, publication still requires the exact `v0.9.4` tag, a non-draft GitHub prerelease containing
the exact 13 verified attachments, the approved manifest SHA-256, the protected `pypi` environment,
and an explicit owner confirmation. Follow the
[0.9.4 PyPI release gate](docs/release/honey-0.9.4/pypi-release.md); merging the source PR alone does
not publish a package.

No attachment is authorized by this source change. Before any promotion, the exact candidate must
still pass clean artifact assembly/installation, upgrade and binary rollback rehearsals, final
checksums/SBOM/provenance/license bindings, two-builder unsigned-byte comparison, independent
evidence recomputation, and every deferred long-running gate selected by the release owner. The
24-hour soak remains deliberately last.
