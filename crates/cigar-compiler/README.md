# cigar-compiler

Stability: kernel, pre-v1. Owns deterministic governed context planning, transforms, packing, manifests, caches, and deltas.

`DeterministicCompiler` normalizes and validates a `ContextContract`, verifies every frozen catalog,
graph, policy, retrieval-plan, index, compiler-profile, tokenizer, and materializer fingerprint, then
canonicalizes already authorized metadata-only candidates. It reconciles logical duplicates and typed
claims, rejects dependency cycles, proves lossless mandatory closure feasibility, satisfies lane
quotas, and packs optional representations with checked integer utility/token comparisons and bounded
one-for-two local swaps. Closure and every repair preserve lane token budgets, profile item bounds,
and blocking-requirement coverage before any output is sealed.

The compiler performs no model or network call. Exact, extractive, verified-summary, and redacted
variants carry exact token costs and required receipts. Sealing emits protocol-valid plan, manifest,
and bundle records plus synchronous invalidation roots. Every considered version receives a stable
disposition; caller explanations filter the protected manifest by current disclosure authorization.

Provider rendering then verifies every exact block body against its declared digest and emits JSON,
Markdown, fact-set, Claude prompt, or MCP envelopes without interpolating protected bytes. Exact
tokenizers are type-separated from conservative estimates. The built-in
`cigar.reference-tokenizer.utf8-bytes.v1` and
`cigar.reference-tokenizer.unicode-scalars.v1` profiles provide strict-UTF-8 exact reference
accounting with algorithm-derived immutable fingerprints; they are not aliases for an Anthropic,
OpenAI, or other external-provider tokenizer. `ReferenceTokenizerProfile::target_profile` binds the
provider `cigar-reference`, the profile identifier as model family, and the immutable fingerprint;
resolution requires that complete tuple. Unknown fingerprints, external providers, and cross-paired
model families fail closed. Governed caches isolate tenant and disclosure domains and recheck policy
and revocation on every hit; sealed deltas verify their exact
digest, base, and reconstructed target before opaque verified-application evidence can be
acknowledged. Provider-present observations reject zero or non-advancing changed sequences. The
daemon's internal trusted-adapter boundary persists only acknowledgements derived from that opaque
evidence, using target-, policy-, revocation-, generation-, and adapter-key-bound contiguous
sequences; it does not add a caller-controlled public-v1 provider operation.

See [`docs/reference/deterministic-compiler.md`](../../docs/reference/deterministic-compiler.md) and
[`docs/reference/materialization-cache-deltas.md`](../../docs/reference/materialization-cache-deltas.md).
