# cigar-code-intel

Stability: kernel, pre-v1. Owns Tree-sitter adapters, structural atomizers, and incremental code extraction.

Required v1 Tree-sitter adapters cover Rust, TypeScript, JavaScript, Python, Go, Java, C, and C++.
They return exact half-open byte and line/column ranges, explicit parser-error regions, stable
symbol identities, version digests, and bounded incremental-state fingerprints. Invalid UTF-8,
oversized inputs, incompatible prior state, cancellation, and excessive syntax trees fail closed.

The built-in atomizer registry covers plain text, heading-aligned Markdown, strict JSON, YAML,
TOML, well-formed XML, bounded Protocol Buffers schemas, CIGAR-native records, Git material,
interaction material, and all required code languages. Code atomization publishes file chunks plus
structural symbol chunks with `DerivedFrom` provenance. All lineages and record IDs are
deterministic; exact source bytes remain protected by protocol payload/debug redaction.

Token-bounded builders produce symbol, diff, decision, and checkpoint capsules. They sort and
deduplicate set-like inputs, bind every semantic field into a canonical digest, and return a typed
limit failure rather than silently truncating mandatory content.
