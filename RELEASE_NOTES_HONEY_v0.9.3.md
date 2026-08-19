# CIGAR Honey v0.9.3 private candidate release notes

CIGAR is an alpha project from [HOL.org](https://hol.org).

| Field | Value |
| --- | --- |
| Version | `0.9.3` |
| Channel | `honey` |
| State | Alpha developer preview |
| Context ABI | `cigar.context.v1` |

Honey 0.9.3 focuses on three connected runtime outcomes: less redundant model input, stronger
requirement coverage, and less work in candidate ranking. It remains unpublished, unsupported
evaluation software until the release owner approves an exact frozen candidate. It is not
production-qualified.

## What changed

- `balanced_v3` is the new default for embedded and local-sidecar execution. `balanced_v1` remains
  selectable for replay of 0.9.2 and earlier context-selection behavior.
- Requirement-aware ranking selects newly covered blocking requirements first, then nonblocking
  requirements and query concepts. Protected blocking candidates remain protected, and a missing
  blocking candidate fails closed.
- Every selected requirement-aware candidate carries deterministic winner-versus-runner-up evidence.
  The compiler rejects missing, incomplete, corrupt, or profile-mismatched ranking evidence.
- Optional compiler packing now saturates at two selected items per requirement. Once requirements
  are sufficiently represented, another candidate is admitted only when it adds a previously unseen
  entity. Mandatory material, blocking roots, and dependency closure are never removed by saturation.
- Ranking maintains coverage, diversity, and maximum similarity state incrementally. This removes
  repeated selected-set reconstruction and the inner scan over every previously selected candidate,
  reducing the bounded ranking hot loop from cubic selected-candidate work to quadratic work plus
  deterministic sorting.
- Storage format v5, bounded startup reconstruction, authenticated in-process snapshots, compressed
  checkpoints, and staggered durable worker heartbeats from the corrected 0.9.2 line remain included.

## Bounded evidence

The compiler regression fixture presents five equally scored 20-token optional blocks with the same
entity. The previous H2 fill-to-budget compiler emits 100 tokens; `balanced_v3` emits 20 tokens while
retaining the first useful block—an 80% reduction for that exact redundant-context fixture. This is
not a universal token-savings claim.

Requirement-aware golden tests verify critical-requirement ordering, complete ranking evidence,
determinism, digest stability, and fail-closed behavior. These are completion-quality proxies: this
release does not claim a generalized improvement in live model-provider completion rate. Exact-source
qualification must still pass identical-assignment completion, critical-evidence recall, citation,
security, token-budget, and latency gates before promotion.

The deterministic 128-candidate ranking operation-count fixture performs 8,128 incremental
similarity updates. The previous selected-candidate rescans require 349,504 evaluations for the same
selection shape: 43 times as many, or 97.6744% more similarity work removed. This is a hot-loop
operation count, not a wall-clock latency claim across machines.

## Compatibility and rollback

The Context ABI remains `cigar.context.v1`; the public API remains 45 operations and 70 nominal
payload types. Python continues to use distribution `hol-cigar` and import `cigar_sdk`. Existing
`intelligence_profile = "balanced_v1"` configurations remain valid. Omitting the field now selects
`balanced_v3`; set `balanced_v1` explicitly to compare or reproduce earlier selection behavior.

0.9.3 does not introduce a storage-format migration beyond v5. Stop the daemon before changing
versions, keep a verified backup, install binaries into a separate versioned directory, and use the
explicit `balanced_v1` profile for behavior-only rollback. Do not mutate or downgrade state in place.

## Attachments

The candidate inventory remains the closed 13-file Honey set, with every versioned filename advanced
to `0.9.3`: source, docs, schemas/conformance, Apple-silicon runtime, TypeScript SDK, Python wheel and
sdist, Rust local-registry kit, Claude Code plugin, demos, these release notes, release manifest, and
`SHA256SUMS`.

## Known limits

Only Apple-silicon macOS, embedded mode, and local-sidecar mode are selected. Archives are unsigned
and unnotarized. Cross-platform, shared deployment, remote multi-tenancy, live-provider replay,
long-duration qualification, production chaos, signing, notarization, and general model-efficacy
claims remain deferred.
