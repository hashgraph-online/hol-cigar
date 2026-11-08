# Changelog

## 0.14.2 (unpublished release candidate)

- Prepare consistent stable core, Python and TypeScript identities and lockfiles
  after RC2 qualification. Keep publication disabled until the release gates pass.
- Include the exact-token query optimizations and additive atomic ticket
  consumption from the development and RC2 entries below.
- Preserve context ABI/protocol v1, authorization, freshness checks, token
  identity, bounded caches, limits, persistence and existing SDK operations.
- Correct package validation formatting and normalize Python prerelease identity
  in the separate Honey compatibility test. No benchmark definition changes.
- See `docs/release/context-sdk-0.14.2-readiness.md` for the retained RC2 timing
  evidence, registry state and unresolved release blockers.

## 0.14.2-rc.2 (unpublished)

- Add owner-bound, single-use `consume_ticket`: current authority/evidence
  validation and ticket removal occur in one serialized broker operation.
  It never authorizes effects, retries unknown outcomes or skips freshness checks.
- Expose the additive command in Python and TypeScript and advertise its capability.
- Preserve existing query, revalidate, forget and execution-handoff semantics.

## 0.14.2 development work (before RC2)

- Load only the encoder and regex required for exact ordinary o200k counts,
  avoiding unused decoder, special-token and per-thread tokenizer construction.
- Preserve the pinned vocabulary, token identity, merge ordering, bounded cache,
  snapshot/delta semantics, authorization and work limits. Long pieces retain
  heap merging; regex errors fail closed.
- Add upstream differential, vocabulary identity and concurrent counting tests.
  See `docs/performance/0.14.2-protocol.md` for the paired measurement gates.
- Keep the 0.14.1 security fixes and runtime floors. Local validation does not
  qualify untested platforms or authorize publication.

## 0.14.1 — security candidate

- Bound aggregate compilation traversal, evidence copying, rendering and scoring before allocation; excessive work returns `LimitExceeded`.
- Enforce Python HTTP response deadlines through headers, bodies and event streams; close active reads on async stream cancellation.
- Require patched Node.js `>=24.22.1 <25` and reject older runtimes for built-in remote fetch (CVE-2026-111497). Operators must upgrade Node and restart consumers.
- Prepare matching native/Python/npm 0.14.1 packages; publication and platform qualification are pending.

## 0.13.0-alpha.1

- Add bounded host-scoped views on one graph/index, source write limits and revocation.
- Bind the complete readable scope into snapshot/review identities; retain reviews
  across outside writes while requiring fresh reviews after inside-scope changes.
- Preserve root API freshness, canonical snapshots, answer rules and the v1 protocol.
- Add Rust/Python/TypeScript five-agent regressions and installed offline examples.
- Local alpha only: no durable recovery, scheduler, new effect authority or parallel
  worker execution. MacOS ARM64 qualification does not qualify other platforms.

## 0.10.1 — incremental retrieval performance

## 0.11.0

- Add bounded atomic answer drafts and separately supplied trusted claim reviews.
- Recompile under current authorization before accepting exact snapshot/review bindings.
- Require selected citations, distinct source groups, supported verdicts and review of
  declared counterevidence. Missing/unknown reviews and empty drafts block release;
  confidence never grants permission.
- Expose identical review-key and answer-check operations through the local worker and SDKs.
- Add offline contract qualification and independently annotated answer-quality metrics.
- Preserve snapshot/delta/retrieval behavior and the 0.10.1 performance improvements.


- Raise the default exact-token cache to 2,048 entries while retaining the 8 MiB text cap.
- Accumulate broad-query scores in reusable document slots; preserve exact ranking,
  authorization, hard closure, selected evidence and snapshot commitments.
- Retain unchanged indexed documents during atomic source replacement, staging only changes.
- Add opt-in `ContextPrompt`, `ContextSnapshot::prompt_view`, verification and citation
  resolution, also exposed by the persistent worker and both local SDKs.
- Prepare stable core/Python/TypeScript 0.10.1 packages and a fixed-tag release workflow
  retaining independent-build, offline-consumer and signed-provenance requirements.

8,604 differential comparisons over 1,434 requests agreed with 0.10.0. Same-host median
latency fell 80–85% for rotating real-source queries, 81% for a 50k-document common-term
query, and over 99% for unchanged/single-change source updates. Full-comparison process
peak memory rose 8.0%. These are measured workload-specific gains, not answer-quality
claims. Existing request/snapshot/delta schemas, token identity and remote v1 APIs are preserved.

# 0.10.0-beta.1 — local context beta

- Standalone incremental context graph, exact rendered-token budgets, source citations, typed
  relations, hard dependency/counterclaim closure, access filtering, semantic retriever input,
  independent corroboration, and deterministic full-text or opt-in excerpt selection.
- Verified snapshots and exact-base transport deltas, including withdrawals and policy isolation.
- Atomic whole-source replacement, including obsolete chunk withdrawal and collision protection.
- Deterministic top-k ranking without sorting all matches; saturated frequencies and source-line
  postings remove repeated document lookups and query-time text analysis.
- Bounded instance-local exact-token caching with explicit disable, clear and measurement APIs.
- JSON CLI; core-only/BPE builds; packaged consumers; documentation and native CI configuration.

The second candidate pass preserves the first candidate's public request/snapshot/delta schemas,
tokenizer identity and selected output in differential testing. New APIs are additive. BPE caching
changes memory retention (bounded and configurable), not token counts. The separate Honey runtime
and Rust/Go remote SDK versions are not promoted by publishing this library.

The beta adds Python `0.10.0b1` and TypeScript `0.10.0-beta.1` local graph APIs,
preserving the 0.9.4 remote API surface. The macOS ARM64 bundled worker is rebuilt
from the beta source crate. Publication requires independent hosted-build byte
agreement, fresh-install and offline qualification, SBOMs, and signed provenance.
