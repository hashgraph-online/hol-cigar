# Fuzz targets

Fourteen bounded fuzz entry points cover canonical serialization, public decoders, identities,
policy, compilation, deltas, explanation redaction, handoffs, materialization, effect recovery,
replay, the extension ABI, MCP, and built-in source parsers. Each target has a checked-in seed and
all targets share `dictionaries/cigar.dict`.

Build every harness without running it:

```sh
cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets
```

Run the complete deterministic ASan smoke, property/Loom suite, and strict Miri slice while
emitting content-free qualification evidence:

```sh
python3 tools/quality/fuzz_and_mutation.py smoke
```

The default runs every target for the campaign's full 60-second smoke threshold with four bounded
workers. `--runs N` is available for local harness viability checks, but evidence from run-count
mode is explicitly non-qualifying. Run the deterministic canonical trust-boundary mutation slice
and then verify both artifacts against the current source tree:

```sh
python3 tools/quality/fuzz_and_mutation.py mutation
python3 tools/quality/fuzz_and_mutation.py verify
```

Run one target directly:

```sh
cargo fuzz run canonical_json_cbor fuzz/corpus/canonical_json_cbor \
  -- -dict=fuzz/dictionaries/cigar.dict -max_total_time=60 -timeout=10 -rss_limit_mb=2048
```

The release campaign is defined by `campaign-v1.json`. Evidence is cumulative only when it binds
the source digest, target, sanitizer, corpus digest, toolchain, start/end times, clean exit, and
crash count. Crashes, hangs, sanitizer failures, or missing targets reset the clean campaign for the
affected target. A short smoke run proves harness viability but never satisfies the seven-day-
equivalent release threshold.

Rust's supported `cargo-fuzz` sanitizer for this native release smoke is AddressSanitizer. Strict
Miri provenance and alignment interpretation is recorded separately as the supplemental memory
model; the campaign does not claim an unavailable Rust UndefinedBehaviorSanitizer mode.
