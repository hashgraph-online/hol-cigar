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
EVIDENCE_DIR="$(mktemp -d)"
chmod 700 "$EVIDENCE_DIR"
python3 tools/quality/fuzz_and_mutation.py smoke --evidence-dir "$EVIDENCE_DIR"
python3 tools/quality/fuzz_and_mutation.py verify-smoke --evidence-dir "$EVIDENCE_DIR"
```

The default runs every target for the campaign's full 60-second smoke threshold with four bounded
workers and deterministic seed 190000. `verify-smoke` accepts only that exact canonical duration,
seed sequence, command set, current source/seed-corpus state, receipt schema, scratch-cleanup proof,
and private log set; pass counts and libFuzzer run/time metrics are recomputed from the bound logs.
The deleted private worker corpus means its recorded post-run digest is self-asserted: the verifier
checks its exact schema, integer counts, maximum observed input size, monotonic growth, and the
separate private-worker policy ceilings, but cannot reconstruct those measurements after successful
scratch cleanup. The checked-in/minimized corpus remains bounded at 4,096 files and 16 MiB per
target. A disposable smoke worker may grow to 8,192 files and 32 MiB while retaining the same 1 MiB
per-input ceiling; exceeding any worker bound fails before a receipt is written and preserves the
failed scratch. Use a fresh, otherwise-empty evidence directory for each smoke attempt. `--runs N`
is available for local
harness viability checks, but evidence from run-count mode is explicitly non-qualifying. Every
fuzzer gets a private temporary copy of its seed corpus, and all compilation runs from a
Git-index-derived external source mirror. Fault/build scratch is preserved on failure and deleted
only after a clean run proves the mirror and read-only candidate unchanged; private bounded logs
remain attached to the receipt. Successful qualification therefore cannot add to or rewrite
`fuzz/corpus`.

The deterministic canonical trust-boundary mutation slice remains available for diagnostics:

```sh
python3 tools/quality/fuzz_and_mutation.py mutation --evidence-dir "$EVIDENCE_DIR"
```

The legacy combined `verify` and `all` routes intentionally fail closed before verification or
execution. The retained mutation receipt does not yet preserve a bounded raw outcome attachment
from which every cargo-mutants metric can be independently recomputed, so it cannot authorize a
combined smoke/mutation claim. Until that evidence format and its substitution tests are
implemented, only `verify-smoke` is a qualifying verifier; the representative mutation slice also
does not claim the PRD's full four-hour release-candidate campaign.

`CIGAR_EVIDENCE_DIR` is equivalent to `--evidence-dir`. The runner rejects repository-internal,
group/world-writable, and existing receipt destinations. It never overwrites a receipt.

## Corpus inventory and minimization

`corpus-policy.v1.json` pins all hand-authored seeds and the minimized MCP numeric-ID regression,
sets distinct checked-in/minimized and disposable-worker byte/count ceilings, and defines
crash-artifact names. Capture a content-free
inventory outside the checkout before curating corpus growth:

```sh
AUDIT_DIR="$(mktemp -d)"
chmod 700 "$AUDIT_DIR"
python3 tools/quality/corpus_manager.py inventory \
  --report "$AUDIT_DIR/inventory.json"
```

The inventory separately labels checked-in reusable inputs, untracked transient growth, named
seeds/regressions, duplicates, fault artifacts, and tracked deletions. Deleted tracked inputs are
read from Git's index, not restored over the working tree. Coverage-minimize one target into a new
external directory:

```sh
python3 tools/quality/corpus_manager.py minimize \
  --target mcp_messages \
  --output-dir "$AUDIT_DIR/mcp-minimized"
```

Run qualification minimization from a Git-clean detached candidate whose root/tracked directories
are mode 0555 and whose tracked files are mode 0444/0555. The manager rejects symlink, submodule,
special, dirty, or writable candidate inputs. It checks out the closed regular-file index set into
an owner-private external execution mirror, preserves the Git executable bit while hardening
tracked mirror content read-only, and leaves writable only the mirror fuzz root and cargo-fuzz's
empty artifact scratch. Cargo configuration, manifests, path dependencies, dictionaries, and
working directory all point at that mirror.

The command copies all current and index-recovered corpus inputs, runs direct `cargo-fuzz` merge
minimization only on external copies, forces cargo-fuzz's inner Cargo through a content-bound
`--locked --offline` wrapper under the nightly toolchain, adds every pinned named fixture back,
canonicalizes anonymous names to the SHA-1 of their bytes, and enforces the policy ceilings. It
checks the candidate and mirror after every primary/repeat pass. On complete success it deletes
only fresh tool-owned build, mirror, wrapper, and work scratch, then emits an exact-top-level
`minimization-report.json` and content-free old-to-new digest map. On any failure it preserves the
whole nonqualifying stage. Every retry requires a never-used output path. The manager never deletes
or overwrites source corpus.

After reviewing an external inventory, reconcile interrupted smoke-run churn with an explicit,
fail-closed operation:

```sh
python3 tools/quality/corpus_manager.py reconcile \
  --inventory-report "$AUDIT_DIR/inventory.json" \
  --quarantine-dir "$AUDIT_DIR/quarantine" \
  --apply
```

Reconciliation first proves the live corpus and artifact inventory still exactly matches the
preserved report. It copies every untracked transient into a fresh mode-0700 external quarantine,
verifies bytes and digests, and durably writes a prepared manifest before changing the checkout.
It then restores missing tracked inputs from Git's index with create-new writes and unlinks only
unchanged, verified transient copies. Named fixtures, crash artifacts, symlinks, unclassified
files, concurrent changes, existing output paths, or a stale inventory fail closed. A completed
`reconciliation-manifest.json` records every action and the zero-churn postcondition. If the
process is interrupted after the prepared manifest, keep the quarantine and inspect the recorded
per-file progress before any manual recovery.

Verify a complete staged campaign and exercise all staged inputs without making them writable:

```sh
python3 tools/quality/corpus_manager.py verify \
  --output-dir "$AUDIT_DIR/minimized-all" \
  --require-all-targets
STAGED_SMOKE="$(mktemp -d)"
chmod 700 "$STAGED_SMOKE"
python3 tools/quality/fuzz_and_mutation.py smoke \
  --runs 1 --jobs 14 \
  --corpus-dir "$AUDIT_DIR/minimized-all/corpus" \
  --evidence-dir "$STAGED_SMOKE"
```

The smoke runner accepts an explicit corpus only when it is external, contains exactly all
fourteen campaign targets, and every target digest matches the adjacent minimization report bound
to the current campaign and corpus policy. It still copies each staged target into a separate
private worker directory before invoking libFuzzer.

`fuzz/.work/` is reserved for disposable local worker corpus copies. Never place crash, timeout,
leak, OOM, or slow-unit artifacts there; `fuzz/artifacts/` remains visible to Git for triage.

Run one target directly:

```sh
WORKER_CORPUS="$(mktemp -d)"
FAULT_ARTIFACTS="$(mktemp -d)"
cp -R fuzz/corpus/canonical_json_cbor "$WORKER_CORPUS/canonical_json_cbor"
cargo fuzz run canonical_json_cbor "$WORKER_CORPUS/canonical_json_cbor" -- \
  -dict=fuzz/dictionaries/cigar.dict \
  -artifact_prefix="$FAULT_ARTIFACTS/" \
  -max_total_time=60 -timeout=10 -rss_limit_mb=2048
```

Keep `FAULT_ARTIFACTS` until every generated fault is triaged. The checked-in corpus remains a
read-only input even for direct local runs.

The release campaign is defined by `campaign-v1.json`. Evidence is cumulative only when it binds
the source digest, target, sanitizer, corpus digest, toolchain, start/end times, clean exit, and
crash count. Crashes, hangs, sanitizer failures, or missing targets reset the clean campaign for the
affected target. A short smoke run proves harness viability but never satisfies the seven-day-
equivalent release threshold.

Rust's supported `cargo-fuzz` sanitizer for this native release smoke is AddressSanitizer. Strict
Miri provenance and alignment interpretation is recorded separately as the supplemental memory
model; the campaign does not claim an unavailable Rust UndefinedBehaviorSanitizer mode.
