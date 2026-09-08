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
