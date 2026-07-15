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
protocol records; and registers selected catalog versions plus policy, index, retrieval-plan, and
compiler-profile invalidation roots. Block provenance contains the selected version and complete
transitive dependency closure. The manifest includes every considered version with its final
disposition, supplementary reasons, and provenance digest.

The full manifest is protected. `CompileOutput::explain` accepts a freshly authorized version set and
omits every other entry, so an explanation cannot reveal denied IDs, counts, reasons, or provenance.
The same normalized contract and frozen inputs produce identical bytes under candidate permutations
and concurrent execution. macOS process qualification also varies input order, locale, timezone, and
process hash-seed environment while requiring identical plan, manifest, and bundle identities.
