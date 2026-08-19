# Honey 0.9.4 focused manual review

Date: 2026-08-18

## Decision

The focused H094-700 review is complete at source commit
`531eed5e7c2933e4e5d63476372b720555a9e227`. The review found seven release-relevant defects or
hardening gaps. All seven were remediated and regression-tested before this report was written.
There are no open critical, high, or medium findings from this review.

This decision closes only the focused source-review item. It does not qualify the release candidate
and does not substitute for the deferred soak, fuzz, sanitizer, installed-artifact, reproducibility,
signing, or production-promotion gates.

## Review boundary

- Frozen `0.9.3` comparison source:
  `a049fbc8ed81c9adc6b1a066ca053c5befc2578a`.
- Reviewed and remediated `0.9.4` source:
  `531eed5e7c2933e4e5d63476372b720555a9e227`.
- Git ancestry: the comparison source is the merge base and an ancestor of the reviewed source.
- Diff size: 131 files, 32,406 insertions, and 981 deletions.
- The remediation commit is `531eed5e` (`harden v4 evidence and workflow identities`).

The review followed identities and invariants across retrieval, compiler packing, delta creation and
application, effect fencing, durable workflow state, replay comparison, all four SDK workflow
helpers, profile configuration, workflow-efficacy evidence, and release-evidence verification. It
used source inspection, adversarial state construction, cross-component invariant tracing, and
focused negative tests. Generated code was not manually rewritten.

## Findings and remediation

### H094-MR-001 — v4 ranking evidence referenced a non-retained runner-up

- Pre-fix severity: high release correctness; completion-impacting, not a confidentiality issue.
- Condition: marginal stopping or the absolute compiler-intake cap could retain the winning v4
  candidate while leaving its `next_best_version` pointed at a candidate excluded from the final
  intake set. The compiler correctly rejects such evidence because every referenced runner-up must
  exist in the selected evidence version set.
- Impact: a valid bounded retrieval result could deterministically fail at compilation, reducing
  actual-workflow completion efficacy.
- Resolution: v4 now clears both runner-up identity and score when the runner-up is not retained;
  evidence validation independently enforces the retained-reference invariant. The rule is scoped
  to `balanced_v4`, preserving frozen legacy ranking-evidence behavior.
- Proof: the v4 marginal-stop regression asserts one retained decision with no dangling runner-up;
  the full retrieval suite and frozen legacy evidence-digest tests pass.

### H094-MR-002 — dominance pruning did not bind complete governance/provenance identity

- Pre-fix severity: high integrity.
- Condition: the v4 dominance predicate compared source/lineage, claim, coverage, value, and closure
  properties, but did not require equality of policy outcome, classification, instruction
  authority, or provenance digest.
- Impact: a nominally stronger candidate could erase distinct governed evidence and emit the
  `same_provenance_no_weaker_value` reason even when provenance or authority was not the same.
- Resolution: dominance now requires exact equality for all four fields. The original metamorphic
  fixture now uses a genuinely equal provenance digest, and a four-axis negative matrix proves that
  each distinction prevents a dominance decision.
- Proof: all 32 non-benchmark compiler integration tests pass; the explicit benchmark remains
  ignored by design.

### H094-MR-003 — v4 packing workspace fingerprint used unframed concatenation

- Pre-fix severity: medium evidence integrity.
- Condition: variable-length strings, collections, and optional claim/receipt fields were appended
  to the workspace hash without uniform structural framing.
- Impact: the encoding did not provide a direct proof that distinct field boundaries always map to
  distinct hash input byte streams.
- Resolution: the unreleased workspace domain advanced from `v1` to `v2`; byte strings are
  length-prefixed, collection lengths are explicit, and optional values carry presence tags.
- Proof: exact-count/cache invalidation, permutation, compiler evidence, and full compiler tests
  pass. This changes only unreleased v4 packing evidence.

### H094-MR-004 — delta replay identity did not link its base to materialization

- Pre-fix severity: medium replay and recovery integrity.
- Condition: a selected delta was required to target the selected context, but its base was not
  required to equal the bundle actually materialized for the provider invocation.
- Impact: a restored daemon record or caller-supplied replay transcript could represent an
  impossible cross-root cycle.
- Resolution: daemon restoration, daemon replay validation, and Rust, Python, TypeScript, and Go
  SDK replay validation now require `delta.base == materialized_bundle` and reject self-deltas.
  This preserves the intended two-root turn: the model consumes the pre-observation base and the
  post-observation target is selected for revalidation and the next turn.
- Proof: daemon restore/replay and all four SDK suites include an incoherent-base negative case.

### H094-MR-005 — effect state and durable counters admitted impossible combinations

- Pre-fix severity: medium effect-evidence integrity.
- Condition: terminal-state validation accepted counters independently, including success with zero
  attempts or reconciliation with no preceding attempt.
- Impact: restored or supplied replay evidence could describe a state the durable effects engine
  cannot produce.
- Resolution: the daemon and all four SDKs now share the same state/count rules: pre-dispatch states
  have no attempts, dispatch outcomes require an attempt, retry/manual resolution requires both an
  attempt and reconciliation, rejection is pre-dispatch, and reconciliation can never exist without
  an attempt. Workflow-unsupported intermediate effect states are rejected.
- Proof: every SDK rejects a forged successful terminal effect with zero attempts; daemon session
  restoration and replay tests cover the same invariant.

### H094-MR-006 — durable workflow scope omitted two live authorization dimensions

- Pre-fix severity: medium authorization partition integrity.
- Condition: the durable scope bound tenant, projects, purpose, classification, and policy digest,
  but omitted processor and maximum instruction authority even though both are live catalog
  authorization dimensions.
- Impact: exact scope equality depended on the policy digest implicitly carrying those dimensions
  instead of enforcing them independently at the durable boundary.
- Resolution: processor and maximum instruction authority are now serialized, validated, compared,
  and represented content-safely in debug output. Processor control characters, emptiness, and size
  are rejected.
- Proof: durable load tests now reject single-axis processor and instruction-authority substitution;
  all 190 daemon library tests pass.

### H094-MR-007 — lost-response idempotency accepted an unbounded expected version

- Pre-fix severity: medium durable-state correctness.
- Condition: an exact session body was returned as idempotent before validating whether the supplied
  expected version was related to the current record.
- Impact: impossible future or arbitrarily stale versions could be silently accepted when the
  session happened to match, weakening the documented CAS contract.
- Resolution: exact-state replay is accepted only at the current version or when the current
  version is exactly one greater than the supplied pre-commit version. Every other mismatch remains
  a revision conflict.
- Proof: every durable recovery boundary retains lost-response idempotency, while an exact session
  submitted with a future version is rejected.

## Reviewed invariants with no reportable finding

- Delta compilation resolves exact retained base and target roots, compares tenant/project/purpose,
  processor, policy, compiler profile, and target profile, reauthorizes both roots, performs live
  revalidation, generates a sealed delta, and locally verifies application before returning it.
- Delta reuse counts only blocks whose semantic identity and complete governed block are equal;
  dependency/provenance changes cannot be reported as reuse.
- Effect authorization and dispatch each require current exact-bundle revalidation; ambiguous
  dispatch resumes through reconciliation and retry cannot advance without a durable reconciliation
  count.
- Replay comparison keeps selection, materialization, model result, effect decision, and outcome as
  separate exact dimensions and cannot advance to verified on any mismatch.
- `balanced_v4` remains opt-in in daemon configuration. `balanced_v3` remains the default and
  `balanced_v1` remains selectable for frozen replay behavior.
- SBOM generation and verification agree on repository-wide locked dependency scope and explicitly
  state that the union is not per-artifact reachability evidence.
- Workflow-efficacy evidence validation binds the frozen historical cohort, pairing identities,
  treatment ordering, attachment digests, metric domains, aggregate recomputation, and bootstrap
  outputs without treating live-provider observations as deterministic qualification evidence.
- Release fuzz policy names 19 explicit targets and binds the corresponding total-duration
  threshold; this review did not execute those deferred campaigns.

## Verification record

All commands below were local and offline. No installer, network service, signing operation,
promotion operation, pentest, soak, fuzz campaign, or sanitizer campaign was invoked.

| Gate | Result |
| --- | --- |
| `cigar-retrieval` library | 74 passed; 1 explicit benchmark ignored |
| `cigar-compiler` integration suite | 32 passed; 1 explicit benchmark ignored |
| `cigar-daemon` library | 190 passed |
| Rust SDK workflow suite | 6 passed |
| Python SDK workflow suite | 6 passed; focused strict type check and Ruff passed |
| TypeScript SDK suite | 29 passed |
| Go SDK all packages | passed with local toolchain and vet-enabled `go test` |
| Strict Rust production-library Clippy | passed for retrieval, compiler, daemon, and Rust SDK |
| SBOM/fuzz release unit tests | 11 passed |
| Workflow-efficacy verifier unit tests | 15 passed; 2 environment-conditional tests skipped |
| Signed release-verifier self-test | passed; contract, artifact, raw-report, and unreferenced-payload tampering rejected |

The Python virtual environment's executable symlink referenced an old checkout path. Tests were run
with the current Python and the already-installed local site packages. A focused strict mypy check
of `workflow_session.py` plus its `errors.py` base passed. A direct broader invocation traversed an
excluded generated operations file and reproduced pre-existing generated-code diagnostics; no
generated code was changed or waived as part of this review.

## Residual boundaries

No finding from this focused review remains open. The following are unexecuted release gates, not
manual-review waivers:

- installed-runtime soak and retained time-series verification;
- fuzz accumulation and native sanitizers;
- dependency audits that require their pinned tools or hydrated advisory databases;
- final artifacts, clean installs, two-builder reproducibility, SBOM/provenance for the closed
  artifact set, signing, notarization, and promotion; and
- installed-artifact three-way context/workflow qualification.

Any later behavior change to the reviewed areas invalidates this source-review decision for the
affected invariant and requires a focused re-review before RC binding.
