# CIGAR repository threat model

## Overview

CIGAR is a model-agnostic runtime for governed context retrieval and compilation, workflow-context
sessions, recoverable external effects, and replayable evidence. This document is the repository
security model for the 0.9.4 candidate. It supersedes release-specific threat-model snapshots for
current development; those snapshots remain historical evidence.

The 0.9.4 security delta is concentrated in the `balanced_v4` retrieval/compiler path, authenticated
full-to-delta compilation and caches, and durable workflow-context execution. Those paths are compared
with the frozen 0.9.2/`balanced_v1` and 0.9.3/`balanced_v3` behavior, but compatibility is not an
authorization argument: every new profile and record is independently versioned, validated, bounded,
and digest-bound.

The highest-value properties are:

- confidentiality of protected source content, prompts, credentials, tool arguments, model/tool
  output, keys, handoffs, and user identity;
- integrity and authenticity of policy, candidate/ranking evidence, context identities, revisions,
  effect records, replay records, backups, release artifacts, and qualification evidence;
- tenant, project, purpose, principal, policy-generation, and authorization isolation;
- prevention of unauthorized, duplicated, stale, or ambiguous external effects;
- deterministic context identity and replay across input order, process, restart, locale, and time
  zone; and
- bounded availability under adversarial candidate graphs, records, content, and concurrency.

Security-critical components include `cigar-protocol`, `cigar-policy`, `cigar-retrieval`,
`cigar-compiler`, `cigar-daemon`, `cigar-effects`, `cigar-replay`, `cigar-store`, `cigar-crypto`, the
public API/SDK/MCP boundaries, and release/qualification tooling. Vector, parser, model, tool,
extension, and remote-provider outputs are untrusted inputs even when they come from a configured
component.

## Threat Model, Trust Boundaries, and Assumptions

### Actors and input control

An attacker may control repository and filesystem content, source names and history, aliases,
dependencies, claims, requirement matches, content-family membership attempts, context requests,
API/MCP/SDK bytes, cursors, imported archives, provider/model/tool outputs, vector candidates, effect
observations, cancellation timing, and any package or backup offered for installation or restore.
Instruction-like content remains data and cannot grant itself policy or effect authority.

An operator controls deployment mode, source and state paths, capacities, trust roots, policy,
principal mapping, key-provider references, connector capabilities, effect scopes, retention,
backup/restore, and release selection. Operator-controlled input is still parsed strictly and fails
closed when incomplete, stale, inconsistent, or path-ambiguous.

A release controller controls source, generators, lockfiles, build tools, qualification thresholds,
signing identities, provenance, and publication. Compromise of this boundary can defeat runtime
controls and therefore requires independent artifact, dependency, and installed-byte verification.

### Trust boundaries

1. **Untrusted bytes to governed catalog.** Filesystem/Git/connectors and parsers turn hostile bytes,
   names, links, histories, and graphs into versioned atoms, edges, claims, and snapshots.
2. **Client or agent to operation authority.** Embedded, HTTP/gRPC, MCP, CLI, and SDK requests are
   authenticated, tenant/project scoped, quota/deadline bounded, and routed through generated
   operation authority. A route or handler is not authorization by itself.
3. **Catalog and vector candidates to retrieval evidence.** Candidate references from exact,
   lexical, graph, or vector stages cross into governed coalescing, bounded ranking, and a sealed
   ranking-evidence record. Store order and provider order are not trusted ordinals.
4. **Retrieval evidence to compiled context.** The compiler validates the exact profile, workspace,
   candidate identities, score arithmetic, runner-up evidence, closures, conflicts, dominance,
   budgets, tokenizer, and materializer before producing a context identity.
5. **Full context to delta/cache reuse.** A prior context crosses into delta generation/application
   or a governed cache only when base/target roots and every authorization and implementation scope
   are current and exact.
6. **Workflow observation to state-machine transition.** Model, provider, and tool results cross into
   a durable session only when their cycle, request, bundle, invocation/effect, generation, and phase
   identities match. Cancellation or revocation closes this boundary before late results arrive.
7. **Decision to external effect.** An exact proposal and current authorization become durable intent
   before dispatch. Fencing, idempotency, observation, and reconciliation govern every retry.
8. **Runtime to durable evidence and maintenance.** Repository commits, anchors, blobs, backups,
   restores, migration, compaction, and GC cross crash/process boundaries with authenticated roots,
   atomic publication, create-new targets, and explicit receipts.
9. **Runtime to telemetry and support output.** Only closed enums, counters, bounded timings, and
   presence flags may leave the authority plane. Source, prompt, secret, path, user, tool-argument,
   model-output, and tool-result values are forbidden.
10. **Source tree to release consumer.** Builds, SBOMs, provenance, archives, checksums, install
    layouts, and qualification reports must bind the exact source and installed bytes.

### Security invariants

- Policy and disclosure checks happen before content, identity, counts, explanations, cache entries,
  vector lookup results, or timing can expose a denied candidate.
- Every accepted ranking decision is reproducible from sealed, profile-bound inputs. Decision
  ordinals are one-based sequence positions; workspace indices are internal only and cannot be
  reinterpreted after coalescing, sorting, truncation, or pruning.
- Requirement sets preserve bits at and across machine-word boundaries. Conversions, counts, score
  arithmetic, and allocation arithmetic are checked and fail closed.
- Mandatory, blocking, policy, contradictory, independently corroborating, and higher-authority
  evidence cannot be erased by top-K limits, content equivalence, dominance, cache optimization, or
  token reduction.
- Content equivalence may charge compatible bytes once, but unions obligations, provenance,
  citations, dependencies, and invalidation identity; incompatible governance, loss, claim, receipt,
  or dependency domains remain separate.
- Delta and cache reuse binds tenant, project, purpose, principal, authorization/policy generation,
  base and target bundle/root, catalog watermark, profile, tokenizer, materializer, and candidate
  workspace. Missing or stale scope is a miss or rejection, never best-effort reuse.
- A workflow transition accepts only the currently expected typed response and exact identity.
  Cancellation, revocation, restart, or quarantine cannot be reversed by a late provider/tool result.
- Every external effect has durable intent, scoped authorization, an attempt fence, idempotency, and
  an authenticated observation. Ambiguous execution remains `UNKNOWN` until reconciliation; blind
  retry is prohibited.
- Canonical records use strict versions, bounded collections, canonical encodings, domain-separated
  digests, and authenticated repository provenance. Unknown authority-bearing fields are rejected.
- Telemetry, diagnostics, debug formatting, support bundles, and release evidence are content-free.
  Attacker-controlled strings cannot become metric names, labels, span fields, policy, or effect
  arguments.
- Release gates never interpret missing, skipped, waived, unknown, source-only, or unsigned evidence
  as a passed installed-runtime qualification.

### Assumptions and limits

The local Honey profile assumes the kernel, filesystem primitives, process owner, and OS credential
store behave correctly. It is not a hostile isolation boundary between processes already possessing
the same user's full file, keychain, debug, and code-execution authority. Secure modes and
cryptographic integrity may still detect accidental or offline corruption, but do not revoke
equivalent account authority.

Cryptographic roots prove canonical bytes, order, and inclusion given trusted keys and inputs. They
do not prove source claims are true, model output is correct, human intent was captured, or an omitted
external event never occurred. Networked multi-tenancy, generalized remote effects/extensions,
production key custody, publisher authentication, notarization, and hostile same-user isolation must
be separately selected and qualified. Until all H094 release gates pass, 0.9.4 remains a release
candidate rather than a production claim.

## 0.9.4 Trust-Transition-to-Test Map

These identifiers are stable review handles. A transition is not covered merely because a package
test passes: the named regression must execute. Commands use substring selectors intentionally so
Rust module qualification does not make the evidence platform-dependent.

### H094-TT-01 — Ranking evidence authenticity

**Transition:** governed candidates and a selected retrieval profile become ordered winner/runner-up
decisions, then become compiler authority. **Attack:** forge or truncate a decision, substitute the
profile/workspace, alter runner-up data, or reinterpret evidence under another scoring profile.
**Required behavior:** validation recomputes every accepted score and ordering field, rejects any
one-bit mutation or missing decision, and seals the exact evidence into the manifest.

- `cargo test -p cigar-retrieval --lib every_accepted_score_is_reproducible_and_one_bit_tampering_is_rejected`
- `cargo test -p cigar-retrieval --lib h2_ties_explanations_and_evidence_digest_are_permutation_stable`
- `cargo test -p cigar-compiler --test compiler h2_ranking_evidence_is_required_validated_and_sealed_into_the_manifest`

### H094-TT-02 — Dense requirement bitsets

**Transition:** public requirement indices become dense internal words and fast-path coverage counts.
**Attack:** induce off-by-one aliasing or silent loss at 63/64, 127/128, 191/192, or 255/256, or
overflow a count/score. **Required behavior:** each index remains distinct, critical coverage is exact,
empty/zero-capacity paths are closed, and integer bounds reject rather than saturate authority.

- `cargo test -p cigar-retrieval --lib dense_requirement_bit_boundaries_and_fast_paths_are_fail_closed`
- `cargo test -p cigar-retrieval --lib dense_ranking_arithmetic_fails_closed_at_integer_bounds`
- `cargo test -p cigar-compiler --test compiler conflict_order_and_candidate_requirement_indices_fail_closed`

### H094-TT-03 — Candidate identity across reduction

**Transition:** unordered multi-stage references become version-coalesced, content-coalesced, capped,
sorted, and ordinal-indexed candidates. **Attack:** retain an ordinal from a pre-coalesced vector and
apply it to another version after pruning or permutation. **Required behavior:** identities are resolved
from the current deterministic workspace, dense and independent reference implementations agree, and
input permutations produce byte-identical evidence.

- `cargo test -p cigar-retrieval --lib dense_workspace_matches_sorting_reference_for_102400_generated_cases`
- `cargo test -p cigar-retrieval --lib flood_alias_content_caps_and_diversity_are_permutation_stable`
- `cargo test -p cigar-compiler --test compiler balanced_v4_dominance_and_permutation_are_semantically_metamorphic`

### H094-TT-04 — Safe dominance and conflict preservation

**Transition:** candidates become content-equivalence classes, conflict dispositions, and conservative
dominance decisions. **Attack:** manufacture apparent equivalence/dominance to erase contradictory,
mandatory, blocking, independently corroborating, or higher-authority evidence. **Required behavior:**
semantic incompatibilities remain separate, critical conflicts fail closed, protected evidence bypasses
ordinary caps, and every dominance decision is deterministic and explained.

- `cargo test -p cigar-compiler --test compiler balanced_v4_preserves_alias_conflict_and_dependency_safety_before_packing`
- `cargo test -p cigar-compiler --test compiler balanced_v4_retains_all_mandatory_items_and_reports_exact_unsatisfiable_bound`
- `cargo test -p cigar-retrieval --lib exact_blocking_policy_and_high_authority_candidates_bypass_optional_caps`
- `cargo test -p cigar-compiler --test compiler conflict_order_and_candidate_requirement_indices_fail_closed`

### H094-TT-05 — Delta and governed-cache reuse

**Transition:** a prior full bundle or cached derivation becomes authority for a new result. **Attack:**
substitute the delta base, reuse stale authorization, change tokenizer/materializer/profile, or collide
tenant/project/policy cache keys. **Required behavior:** exact live roots and all scope fingerprints are
rechecked; reset, restart, compaction, mutation, or governance change invalidates reuse deterministically.

- `cargo test -p cigar-compiler --test materialization_delta_cache delta_round_trip_rejects_wrong_base_tamper_and_target_change`
- `cargo test -p cigar-compiler --test materialization_delta_cache caches_isolate_scopes_recheck_governance_and_evict_deterministically`
- `cargo test -p cigar-daemon --lib delta_requires_exact_live_authorized_roots_and_matching_profiles`
- `cargo test -p cigar-daemon --lib authenticated_delta_state_survives_restart_and_reset_and_compaction_invalidate`
- `cargo test -p cigar-daemon --lib governed_cache_is_policy_scoped_and_restarts_cold`

### H094-TT-06 — Workflow replay and late-result admission

**Transition:** durable session identity admits replay comparisons and asynchronous provider/tool
results. **Attack:** substitute a plan, bundle, delta, model output, effect, or outcome; inject a result
after cancellation/revocation; or restore an impossible phase. **Required behavior:** each field is
compared independently, verification requires an exact match, quarantine is monotonic, and impossible
restored states reject.

- `cargo test -p cigar-daemon --lib no_effect_cycle_has_one_closed_operation_order_and_replay_terminal`
- `cargo test -p cigar-daemon --lib cancellation_and_revocation_quarantine_late_provider_and_tool_results`
- `cargo test -p cigar-daemon --lib durable_identity_snapshot_round_trips_and_rejects_impossible_phase`
- `cargo test -p cigar-replay --test wp13_replay_modes cancellation_while_live_provider_is_blocked_quarantines_output_before_effect_dispatch`

### H094-TT-07 — Prompt/tool output as untrusted data

**Transition:** retrieved content, model/tool observations, debug state, and request metadata approach
instruction, policy, effect, or telemetry boundaries. **Attack:** embed system-like instructions,
credentials, forged citations, effect arguments, high-cardinality labels, or telemetry canaries.
**Required behavior:** only configured authority supplies instructions/policy; tool results remain sealed
observations; debug and telemetry surfaces expose only closed content-free values.

- `python3 demos/run.py --scenario prompt-injection-defense --output-dir reports/demos`
- `cargo test -p cigar-daemon --lib cancellation_and_revocation_quarantine_late_provider_and_tool_results`
- `cargo test -p cigar-daemon --lib telemetry_surfaces_drop_ambient_metadata_and_never_accept_content_canaries`
- `cargo test -p cigar-daemon --lib debug_output_contains_only_counts_and_presence_flags`
- `cargo test -p cigar-daemon --lib debug_output_redacts_payload_key_and_authenticated_scope`

### H094-TT-08 — Algorithmic complexity and memory exhaustion

**Transition:** aliases, dependencies, requirements, conflicts, and content families become internal
maps, closures, bitsets, queues, and caches. **Attack:** use floods, giant closures, cycles, adversarial
similarity, or blocked work to force superlinear CPU, unbounded allocation, stack growth, or queue
starvation. **Required behavior:** request/stage/item/byte/depth/queue limits are checked before growth,
closure caches are bounded, cycles reject, cancellation polling is bounded, and overload fails closed.

- `cargo test -p cigar-retrieval --lib protected_flood_fails_at_the_explicit_request_bound`
- `cargo test -p cigar-retrieval --lib ranking_similarity_cache_updates_each_candidate_pair_once`
- `cargo test -p cigar-compiler --test compiler balanced_v4_caches_shared_closures_and_rejects_a_giant_dependency`
- `cargo test -p cigar-compiler --test compiler dependency_cycles_and_critical_conflicts_fail_closed`
- `cargo test -p cigar-daemon --lib blocking_pool_bounds_active_and_queued_work_and_releases_after_cancel_and_deadline`

### H094-TT-09 — Cancellation around effect dispatch

**Transition:** workflow intent becomes durable authorization, dispatch ownership, remote execution,
observation, and possible retry. **Attack:** race cancellation/revocation against intent persistence or
connector entry, inject an old result, or convert ambiguity into duplicate dispatch. **Required
behavior:** committed intent and an exclusive attempt fence precede connector entry; cancellation
propagates; late results quarantine; `UNKNOWN` requires authenticated reconciliation and fresh context
revalidation before retry.

- `cargo test -p cigar-effects --test wp12_effects dispatch_requires_committed_authorization_attempt_fence_and_outbox`
- `cargo test -p cigar-effects --test wp12_effects concurrent_workers_cannot_reuse_one_durable_permit_at_connector_entry`
- `cargo test -p cigar-effects --test wp12_effects expiry_cancellation_rejection_and_manual_resolution_are_explicit`
- `cargo test -p cigar-daemon --lib ambiguous_effect_requires_reconciliation_and_fresh_revalidation_before_retry`
- `cargo test -p cigar-daemon --lib replay_request_cancellation_reaches_in_flight_repository_token`
- `cargo test -p cigar-replay --test wp13_replay_modes live_effects_reject_old_ids_gate_fresh_ids_and_simulate_without_dispatch`

The full `tests/security/matrix-v1.json` remains the broader security regression gate. Fuzzing,
historical corpus replay, Miri, sanitizers, supply-chain audits, SBOM/provenance generation, telemetry
canary qualification, and focused manual review are distinct H094-700 gates; passing this traceability
slice does not waive them.

## Attack Surface, Mitigations, and Attacker Stories

### Retrieval, compiler, and derived indexes

An attacker can flood one source/lineage, create aliases or byte-identical copies, manipulate vector
neighbors, exploit score/token overflow, race policy/catalog/index generations, or infer denied
candidates from errors/counts/timing. Controls are governance before disclosure, exact snapshot and
generation pins, bounded stages, checked arithmetic, deterministic coalescing/order, mandatory closure,
strict lane/item/token limits, profile-bound ranking evidence, conservative dominance, and
provenance-complete blocks. Vector services return candidate pointers only; authoritative state is
fetched and reauthorized by exact version.

### Workflow, replay, and effects

Provider/model/tool output can be malformed, stale, malicious, delayed, or attached to the wrong
cycle. Imported replay may substitute any identity or attempt live egress. Effects may change target or
arguments after approval, dispatch twice, exploit redirects/proxies, forge success, or turn timeout
into unsafe retry. Typed phase transitions, exact identity binding, monotonic quarantine, network-free
observational replay, durable intent, current authorization, connector declarations, attempt fencing,
idempotency, and explicit `UNKNOWN` reconciliation mitigate these stories.

### Durable state, maintenance, and cryptography

Relevant attacks include malformed or oversized records, truncated/reordered chains, stale/forked
anchors, rollback, disk exhaustion, path substitution, same-user writer races, receipt tampering, blob
swap, backup substitution, interrupted migration, and compaction of held history. Strict canonical
encodings, domain-separated digests, parent/root chains, external anchors, defensive SQLite, WAL with
full synchronization, restricted regular paths, a single writer, bounded replay, authenticated
backups, create-new restores/migrations, and separate compaction/GC receipts preserve prior-or-complete
state across crashes.

### API, providers, observability, and supply chain

Malformed/oversized frames, counterfeit authentication material, replayed cursors/idempotency keys,
slow streams, untrusted
extensions, ambient network/filesystem credentials, telemetry injection, archive traversal, dependency
compromise, and artifact substitution cross these boundaries. Exact generated operations, strict
schemas, quotas/deadlines/cancellation, scoped capability brokers, bounded protocols, explicit trust
roots, closed telemetry catalogs, exact lockfiles, archive inventories, checksums, SBOM/provenance, and
installed-byte qualification form the required defense. Checksums provide integrity relative to a
trusted manifest; they do not by themselves authenticate a publisher.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

A realistic path to broad irreversible authority: unauthenticated remote or cross-tenant arbitrary
effect execution with protected credentials; accepted release/build compromise; private-key extraction
enabling repository-wide forgery; or maintenance predictably destroying the only evidence and verified
backups across tenants.

### High

Cross-tenant/project protected-content disclosure; policy-before-disclosure bypass; ranking/dominance
manipulation that suppresses mandatory or higher-authority evidence and authorizes an effect; replay or
late-result substitution causing unauthorized/duplicate effects; path escape; accepted state, delta,
anchor, backup, or artifact substitution; or authentication bypass granting operator authority.

### Medium

Bounded denial of service from pathological parsing/ranking/closure/workflow inputs; persistent but
recoverable readiness loss; limited metadata leakage without content; cache poisoning contained to one
scope and detected before effects; telemetry cardinality abuse; or deterministic drift that invalidates
reproducibility without bypassing policy. Severity rises when remote, persistent, cross-tenant, or able
to suppress required evidence.

### Low

Content-free diagnostic inaccuracies, bounded local inefficiency, non-sensitive version/capability
disclosure, or documentation and test-only issues that cannot enter selected artifacts or weaken an
enforced control.

Repository: codex-security-target/v1:sha256:d835d536b8afbb4b4474dd608ed0a0f84d680a6302f35c820729af8b6c51255b
Version: f91087194429945b4aa70a8236903c7555814204
