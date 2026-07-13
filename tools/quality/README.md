# Quality matrix runner

`run_matrix.py` executes versioned JSON test matrices without a shell and writes
content-free evidence. Child stdout and stderr are represented only by byte
counts and SHA-256 digests. A synthetic secret canary is injected into every
child; observing it in either stream fails the case. Cargo test cases always run
with `CARGO_NET_OFFLINE=true`.

Before starting any selected Cargo case, the runner performs one locked,
offline Cargo metadata preflight. An incomplete dependency cache or inconsistent
`Cargo.lock` therefore fails once before any test evidence is written instead
of producing the same cargo-nextest metadata error for every case. Hydrate a
fresh cache as a separate, explicit step:

```sh
python3 tools/quality/run_matrix.py \
  --matrix tests/security/matrix-v1.json \
  --prepare-cargo-cache
```

That mode runs `cargo fetch --locked`, writes no matrix result, and exits. Run
the matrix in a second invocation so dependency network access cannot be
mistaken for offline test execution. Cache preparation honors any network
restriction already set by the caller and suppresses command output; run
`cargo fetch --locked` directly when private diagnostics are needed.

Local example:

```sh
python3 tools/quality/run_matrix.py \
  --matrix tests/security/matrix-v1.json \
  --profile local \
  --output reports/security-matrix.local.json
```

`release` selects local and external qualification cases. Missing required
service credentials or endpoints fail closed. `--log-dir` is intended only for
local debugging; it writes mode-0600 logs and those logs must never enter a
release evidence bundle.

`fuzz_and_mutation.py` runs the WP19 fuzz, property/Loom, Miri, and mutation
slices with external evidence and private mutable worker corpora.
`corpus_manager.py` inventories, externally minimizes, and safely reconciles
libFuzzer corpus growth. See `fuzz/README.md` and `fuzz/corpus-policy.v1.json`;
neither tool is allowed to silently mutate or discard the checked-in corpus.
Qualification minimization and smoke execution compile only from a closed
Git-index external source mirror bound to a Git-clean read-only candidate.
Direct cargo-fuzz runs use a wrapper-first `PATH`, explicit `CARGO`, nightly
selection, locked/offline inner Cargo, and a Darwin no-network sandbox. Failed
scratch is preserved; successful tool-owned build/mirror/artifact scratch is
verified and removed before the content-free receipt is written.
