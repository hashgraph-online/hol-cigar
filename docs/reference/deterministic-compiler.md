# Deterministic context compiler

WP08 compiles only frozen, authorized inputs. The compiler has no default model, provider, tool, or
network path. Upstream retrieval contributes a staged query-plan digest and metadata-only candidates;
upstream policy contributes the current policy digest and per-candidate outcome. Any catalog, graph,
policy, index, query plan, compiler profile, tokenizer, or materializer pin mismatch fails before
selection.

## Normalize, reconcile, and close

Contract normalization applies field-specific NFC, whitespace, case, and set rules, then reruns the
protocol validator and hashes deterministic CBOR. Candidates are sorted by immutable version and
logical aliases collapse under balanced-v1 score, token cost, canonical URI, and version ties. Typed
claims reconcile by world-valid time, observation time, authority, verification, and stable source
order. Candidate requirement indices outside the normalized contract fail before scoring. Equal-rank
contradictory claims fail as unresolved critical conflicts when either side belongs to the rule or
task lane, so a higher-scoring non-critical candidate cannot hide a critical conflict.

Dependencies form a bounded acyclic graph. Every blocking requirement chooses an authorized root;
explicit mandatory roots and their transitive dependencies must have a lossless representation. The
compiler computes the exact per-lane lower bound before optional packing and returns
`BudgetUnsatisfiable` with the minimum required tokens if closure cannot fit. A blocking requirement
is always selected or compilation returns `RequiredMissing`.

After lifecycle and claim reconciliation, Honey 0.9.1 groups compatible cross-logical candidates
whose complete canonical representation sets are identical. Lane, policy outcome, classification,
instruction authority, claim semantics, token/loss metadata, and transform receipts must also match.
Redacted markers and dependency contractions that could erase or cycle an obligation remain separate.
The stable representative inherits the union of mandatory status, requirement coverage, entity
coverage, and dependencies before closure and packing.

The daemon bounds compiler intake before protected content loading. It derives candidate allowances
from lane tokens, compiler item limits/minima, and a frozen oversubscription factor; gives exact,
blocking, policy, higher-authority, and dependency evidence a separately bounded bypass; coalesces
authorized channel/content aliases; applies per-source, lineage, and content-family caps; and runs
deterministic integer diversity selection. All bound/diversity constants are in the retrieval-plan
fingerprint. The compiler remains authoritative for exact token costs, dependency closure, policy,
and safe content equivalence.

## Represent and pack

Representation constructors cover exact, evidence-backed extractive, pre-existing verified summary,
and typed redacted variants. Extracts and summaries require a receipt. Mutually exclusive variants
carry exact target-token counts and a loss class; the default path never creates a generative summary.

Balanced-v1 retrieval features remain integer-valued. Packing adds requirement and entity coverage
gain and subtracts versioned loss penalties. Priority ratios use checked cross multiplication, not
floating point. Mandatory closure is inserted first, lane minima second, and positive-utility optional
content last. Fixed-pass local repair can replace one optional item with one or two better alternatives
under the same exact budgets. Dependency closure participates in both token and item-cap feasibility.
Every proposed repair rechecks lane tokens, profile item maxima, and blocking-requirement coverage;
the final result additionally rechecks applicable lane minima. A lane minimum is inactive only when
that lane has no eligible candidate. Final repair reruns all lane and total token arithmetic.

## Seal and explain

Sealing deterministically derives plan, manifest, block, and bundle identities; validates the frozen
protocol records; and registers every represented member/dependency version plus policy, index,
retrieval-plan, and compiler-profile invalidation roots. A shared block charges its representation
tokens and item count once while its canonical provenance contains every equivalent version and the
complete transitive dependency closure. The manifest still includes every considered version with
its final disposition, supplementary reasons, and provenance digest; compatible non-representatives
use the v1 `budget_displaced` reason.

`CompileOutput::content_equivalence` is protected, non-wire diagnostic state. It preserves class
members, provenance commitments, representatives, and selected block IDs. After applying disclosure
authorization, `CompileOutput::resolve_citation` maps any represented member version to the shared
block without replacing the cited source identity. The daemon retains and reauthorizes every member
for invalidation even though materialization reads the representative bytes once.

The full manifest is protected. `CompileOutput::explain` accepts a freshly authorized version set and
omits every other entry, so an explanation cannot reveal denied IDs, counts, reasons, or provenance.
The same normalized contract and frozen inputs produce identical bytes under candidate permutations
and concurrent execution. macOS process qualification also varies input order, locale, timezone, and
process hash-seed environment while requiring identical plan, manifest, and bundle identities.
