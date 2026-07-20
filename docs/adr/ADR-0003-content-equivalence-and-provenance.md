# ADR-0003: Content equivalence with complete provenance

- Status: Accepted for Honey 0.9.1 implementation
- Date: 2026-07-20
- Applies to: deterministic compiler selection and sealing
- Compatibility: no new v1 operation, payload type, enum value, or disposition reason

## Context

The paired evaluation preserved required-source coverage and citation quality, but 27.15% of selected
content was duplicated overall and one workflow cohort reached 80%. Candidates can have different
version/logical identities and provenance while offering byte-identical rendered representations.
The current logical-ID collapse cannot combine such candidates. Selecting each duplicate spends
tokens and item capacity multiple times and reduces source diversity.

Deduplication must not erase source identity, dependency closure, mandatory coverage, policy,
instruction authority, transform receipts, invalidation, explanation entries, or citation aliases.
The public v1 manifest also has no new `content_equivalent` disposition reason, so 0.9.1 must use its
existing closed vocabulary.

## Decision

The compiler adds deterministic content-equivalence grouping after normalization, authorization,
policy/lifecycle/representation eligibility, logical alias collapse, and critical conflict
reconciliation, but before mandatory closure and budget packing.

The compiler groups representation choices, not unexamined source records. One selected
representation is charged once while its emitted block carries the sorted union of every compatible
member version and transitive dependency required to prove it.

## Eligibility order

Grouping may observe only candidates already admitted by governance. Processing order is:

1. normalize/validate contract and frozen pins;
2. canonicalize candidates and reject malformed/duplicate version records;
3. apply pre-exclusion, policy, lifecycle, disclosure, processor, and instruction-authority gates;
4. collapse same-logical-ID versions using existing deterministic precedence;
5. reconcile typed claims and critical conflicts;
6. construct and validate deterministic representation variants;
7. build content-equivalence classes;
8. calculate mandatory/dependency closure and exact lane lower bounds;
9. pack and repair under item/token budgets; and
10. seal plan, manifest, blocks, bundle, citations, and invalidation roots.

Denied or otherwise ineligible identities are never disclosed to grouping metrics, selected
provenance, explanations, or citations.

## Equivalence key and compatibility

The base equivalence identity is `(representation kind, content digest)`. Candidates can join the
same class only when all of these are compatible:

- same destination lane;
- same policy outcome and disclosure behavior after governance;
- same classification handling and instruction-authority requirement;
- same representation kind, exact content digest, token count, loss class, and transform-receipt
  semantics;
- no unresolved critical claim conflict;
- dependency closures are individually valid and their union remains bounded and acyclic; and
- combining mandatory/requirement obligations does not weaken a member's exact authorization or
  evidence requirements.

A matching digest with inconsistent token count, loss, or required transform receipt is invalid
input, not an equivalence opportunity. Candidates whose governance or authority requirements differ
remain separate even if their bytes match. Redacted representations cannot merge across distinct
disclosure decisions merely because their visible marker bytes match.

For the 0.9.1 patch, candidates with multiple representations join one class only when their complete
canonical eligible variant sets match, including kind, digest, token count, loss, and receipt. This
conservative rule prevents one colliding summary from merging different required lossless content and
does not discard a unique alternative. A future compiler with explicit per-variant selection nodes may
group matching exact variants while retaining different summary alternatives. Representation
alternatives remain mutually exclusive under the existing compiler rules.

## Representative and aggregate metadata

Within a class, representative ordering uses the existing stable `candidate_order` over source
candidates, with version ID as the final tie. Representation ordering remains the existing loss,
token-count, kind, and content-digest order. Input order, map hash seed, locale, timezone, and thread
schedule cannot affect the representative.

The aggregate class contains checked, bounded unions of:

- member version IDs;
- each member's transitive dependency version IDs;
- requirement indices;
- mandatory status (`true` if any member is mandatory);
- entity coverage bits;
- provenance digests and transform receipt commitments; and
- invalidation catalog versions.

The representative's retrieval score and canonical URI determine packing priority. The
implementation must not sum duplicate relevance scores, because repeated copies from one source
could then manufacture priority. Requirement and entity coverage are unioned once. Any union over
the configured member, requirement, provenance, or dependency limit fails closed.

## Mandatory and dependency behavior

If any member is mandatory, the aggregate is mandatory. If a member satisfies a blocking
requirement, selecting the aggregate satisfies it only when that member and every dependency needed
for its proof are present in aggregate provenance. Dependency closure is calculated per member,
unioned, cycle-checked, and charged according to actual unique selected representations.

Content equivalence does not allow ordinary top-K, diversity, or budget logic to remove mandatory
evidence. If the unique mandatory closure cannot fit, compilation returns the existing fail-closed
budget/required error rather than dropping provenance.

## Packing and charging

The selected representative consumes one context-block item and the selected representation's exact
token count once. Equivalent members do not each consume a block or token charge. Distinct dependency
content is still charged normally unless it independently forms a compatible content-equivalence
class.

Packing utilities use the representative's existing balanced score plus unioned requirement/entity
coverage. All arithmetic remains checked integer/fixed-point arithmetic. Local repair operates on
equivalence-class identities so it cannot reintroduce a duplicate member.

## Plan, manifest, block, and citations

The public v1 plan names the representative version for the selected block. The v1 manifest retains
one entry for every considered authorized candidate:

- the representative receives the existing `selected` disposition;
- compatible non-representatives use the existing `budget_displaced` disposition/reason; and
- their protected disposition records retain their individual provenance digests.

No new v1 reason or enum is introduced. Documentation explains that, in 0.9.1, a
`budget_displaced` candidate may have been represented by an equivalent selected block. This is a
compiler interpretation within existing semantics, not a new wire value.

The emitted `ContextBlock.provenance` is the sorted unique union of representative/member versions
and complete required dependency closure. The block ID hashes the selected representation plus that
complete provenance, so adding or removing an equivalent source changes evidence identity even when
rendered content does not.

In v1, immutable member version IDs are the valid citation aliases. Protected compiler diagnostics
register every equivalent member version to the selected block. Resolving one returns the exact
member/source identity plus the shared block; it does not rewrite all citations to pretend the
representative was the original source. Required-source coverage is evaluated across the whole
equivalence class.

Invalidation registration includes every member and dependency version. A change, revocation,
lifecycle transition, policy change, or provenance invalidation affecting any member invalidates the
artifact and forces recompilation.

## Telemetry

Content-free closed metrics record candidates before grouping, classes after grouping, selected
classes, member count histogram, duplicate representations avoided, unique content keys, unique
source versions, and unique lineages. Labels never contain content digests, source IDs, tenant IDs,
paths, or arbitrary workflow values.

Qualification calculates duplicate selected content by `(representation kind, content digest)` from
authorized private observations and emits only aggregate counts/rates. The release gate is at most
5%; required-source coverage remains 100% and citation resolvability remains at least 99%.

## Compatibility

- `cigar.context.v1`, its 45 operations, 70 payload types, and generated clients remain unchanged.
- Existing clients continue to see one selected block and normal v1 manifest dispositions.
- The contract digest remains unchanged and still includes arbitrary v1 extensions as it did in
  0.9.0.
- Content grouping is fixed by the compiler-profile digest and invalidates caches when enabled or
  configured differently.

## Consequences

The same content can represent multiple independently governed sources without duplicate token cost,
while provenance and citations become richer. Bundle/block identities can change relative to 0.9.0
because complete provenance now affects them; this is intentional and profile-bound. Manifest users
must not assume every `budget_displaced` record has absent content in the selected bundle.

## Rejected alternatives

- **Deduplicate only by logical ID:** already exists and cannot address cross-logical duplicates.
- **Keep only representative provenance:** saves metadata but destroys source/citation/audit truth.
- **Merge on text without representation kind:** can equate exact, summarized, extracted, and
  redacted semantics incorrectly.
- **Merge before governance:** risks disclosing or laundering denied identities through an allowed
  representative.
- **Add a v1 disposition reason:** violates the frozen v1 registry; it belongs in a future protocol.
- **Prefer the candidate with the most duplicates:** rewards source flooding and is manipulable.

## Verification obligations

- Property tests for input permutation, representative ties, multiple representation variants,
  dependency union, duplicate application, and bounded unions.
- Mandatory/nonmandatory and blocking-requirement mixtures cannot drop required evidence.
- Policy, classification, instruction-authority, lifecycle, and transform incompatibilities never
  merge.
- Every member citation resolves to the selected block and preserves exact source identity.
- Changing any member invalidates the selected artifact.
- Frozen cohort passes duplicate, diversity, displacement, citation, required-source, deterministic
  identity, and fail-closed gates.
