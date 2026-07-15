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

The PRD command-plane routes for compatibility, integration, end-to-end,
security, offline, concurrency models, chaos, and migrations are currently
native-macOS development gates. They require one private external evidence
workspace and never write their receipt into the checkout:

```sh
export CIGAR_EVIDENCE_DIR=/private/tmp/cigar-quality-evidence
mkdir -m 700 "$CIGAR_EVIDENCE_DIR"
cargo xtask test compatibility
cargo xtask test integration
cargo xtask test e2e
cargo xtask test security
cargo xtask test offline
cargo xtask test models
cargo xtask test chaos
cargo xtask test migrations
```

Each route selects a distinct versioned matrix and a distinct create-new JSON
receipt below `quality/`. The runner withholds `CIGAR_EVIDENCE_DIR` from test
children, records only stream sizes and digests, and rejects an evidence root
inside the repository. These command-plane routes use the `local` matrix
profile, so their receipts always set `release_eligible` to `false`, including
on a clean tree. A direct `release` matrix run requires a clean committed source
candidate and separate release prerequisites.

The security matrix includes `SEC-MCP-002`, a non-fuzz historical-crash gate. It validates the
closed-world `fuzz/historical-crashes.v1.json` fixture/source manifest and runs only its exact MCP
request-ID and backend-number Nextest selectors. The child suppresses protected test output,
revalidates every bound byte after execution, and fails on missing, extra, tampered, duplicated,
remapped, linked, special, or case-aliased fixtures. Run the inventory alone with
`python3 tools/quality/historical_crashes.py verify`; run its deterministic native-macOS tests with
`python3 tools/quality/historical_crashes.py run`. Neither command starts fuzz, soak, or mutation
work.

The compatibility matrix includes `COMPAT-SURFACE-001`, a deterministic source-only operation
surface sentinel for the Apple-silicon macOS development cohort:

```sh
python3 tools/quality/operation_surface_parity.py
```

It derives one normalized 45-operation contract from the frozen operation and payload catalogs,
then requires exact semantic parity in OpenAPI/HTTP, Proto/gRPC, the Rust typed registry, all four
SDK descriptors, the dashboard projection, and the generated 34-entry CLI and 10-tool MCP closed
subsets (33 distinct CLI operations because one command is an explicit alias). It also binds the
34-error problem contract, the single generated identity used by request
log/debug contexts, and the deliberate aggregate metric policy. Operation or caller identifiers
remain structurally unavailable as metric labels; API metrics cover all operations through bounded
aggregate outcomes rather than 45 high-cardinality series. The emitted JSON is source-bound and
always records `release_eligible=false` and `candidate_frozen=false`; it is not installed-artifact
or publication evidence.

Every Cargo Nextest case in these macOS matrices explicitly selects its
checked-in Nextest configuration (`.config/nextest.toml`, or the isolated
property workspace's equivalent), ignores ambient user configuration, uses the
strict serial `macos-qualification` profile, and sets `--no-tests fail`. The
profile has zero retries and retains fail-on-leaked-handle semantics; a failure
is never hidden by retrying it.

Native Apple-silicon macOS qualification uses the repository's serial Nextest profile while the
Rust standard library's non-atomic macOS pipe/CLOEXEC spawn path remains unresolved:

```sh
NO_COLOR=1 NEXTEST_HIDE_PROGRESS_BAR=1 \
  cargo nextest run --locked --workspace --all-targets \
    --exclude cigar-soak --no-fail-fast -P macos-qualification
```

`macos-qualification` inherits the fail-closed CI policy, including the two-second leaked-handle
failure, but launches only one test process at a time so a concurrent spawn cannot inherit another
test's capture pipe. The normal parallel profile remains useful development feedback; its result is
not native macOS qualification evidence. This command intentionally excludes the separately
mandatory soak crate for the current bounded execution cohort and does not waive fuzz or soak.

`release` selects local and external qualification cases. Missing required
service credentials or endpoints fail closed. `--log-dir` is intended only for
local debugging; it writes mode-0600 logs and those logs must never enter a
release evidence bundle.

## Production sanitizer qualification (native macOS)

`production_sanitizers.py` executes the bounded, non-fuzz, non-soak production
sanitizer cohort for native Apple-silicon macOS. The checked manifest requires
`nightly-2026-07-13` (rustc 1.99.0-nightly, commit
`77cf889bc178ddb44d6a1c78e5a820b5abb31d8d`, LLVM 22.1.8) and Homebrew clang
22.1.8 at `/opt/homebrew/opt/llvm/bin/clang`. TSan builds an instrumented Rust
standard library with `-Zbuild-std`; ASan also instruments native C dependencies
with the matching clang. Commands, environment, exact test selectors, runtime
dylibs, source inventory, toolchain, and results are bound into a canonical
external receipt. The policy has no test exclusions, retries, ignored tests, or
implicit workspace expansion.

The runner's scratch directory and receipt are create-new. Remove only a
reviewed prior tool-owned scratch directory before a new run, and choose a new
owner-only external receipt directory:

```sh
python3 tools/quality/production_sanitizers.py verify-manifest
mkdir -m 700 /private/tmp/cigar-production-sanitizer-evidence
python3 tools/quality/production_sanitizers.py run \
  --receipt /private/tmp/cigar-production-sanitizer-evidence/receipt.json
python3 tools/quality/production_sanitizers.py verify-receipt \
  --receipt /private/tmp/cigar-production-sanitizer-evidence/receipt.json
```

The six TSan cases cover cache publication, snapshots, context revisions,
outbox/store fencing, cursor/subscription state, invalidation, shutdown, effects,
shared coordination, provider-state CAS, and retrieval generation publication.
The four ASan cases cover SQLite service CAS, SQLite effect recovery, the full
tree-sitter language matrix, and catalog SQLite invalidation. This cohort does
not build or execute fuzz targets or soak workloads.

Rust's macOS sanitizer interface rejects `-Zsanitizer=undefined`, so the runner
records `rust_ubsan_run=false` and never labels the reviewed equivalent as
UBSan. The equivalent verifies the workspace `unsafe_code = "forbid"` policy,
inventories first-party and dependency native/FFI surfaces, records the exact
Windows-only source excluded from the macOS review, and relies on matched-LLVM
ASan execution for applicable native C paths. A receipt from a dirty checkout
is diagnostic only: it may prove the bounded checks passed, but
`release_eligible` remains false until the same gate runs against one clean,
immutable candidate.

## Native macOS CI workflow receipts

`ci_workflow_receipt.py` is the outer evidence envelope for the native
Apple-silicon CI lanes. It accepts only a closed lane inventory and requires an
exact clean event commit, its Git tree, a native `Darwin arm64` host, the GitHub
repository/run/attempt/job identity, a fixed command digest, and protected
external content-free attachments. Publication is create-new in an owner-only
external directory. Verification reopens the receipt and every attachment and
rechecks the current platform, event SHA, source state, builder identity, and
command digest. Receipt claims permanently keep fuzz, soak, signing,
notarization, publication, and release qualification false.

The associated workflows are deliberately narrower than complete release
qualification:

- `security.yml` runs the exact production TSan/ASan manifest nightly or on a
  manual dispatch, independently verifies its sanitizer receipt, then retains
  only content-free receipts.
- `macos-long-running-qualification.yml` schedules or manually selects the full
  non-fuzz mutation gate, the 24,000 process-kill effect campaign, a reduced
  physical backup/recovery diagnostic plus 300-GiB capacity preflight, and
  bounded CIGARBench replay/performance diagnostics.
- `macos-release-candidate-diagnostics.yml` manually exercises source-bound
  security and reproducibility gates plus the unsigned native archive and
  Homebrew producer/verifier chain. Only content-free prerequisite receipts are
  uploaded; package bytes are not uploaded or published.

Every job uses `macos-15`, read-only repository permissions, a timeout and
non-cancelling concurrency lock, SHA-pinned actions, checkout without persisted
credentials, locked dependency hydration followed by offline execution where
applicable, and fail-closed upload digest validation. These workflows have no
production secret, signing, notarization, publication, or promotion path. The
100-GiB physical scale campaign remains a separately authorized installed-
candidate gate. Fuzz and soak are intentionally not invoked by these workflows
for the current bounded run. Local actionlint and policy tests validate the
configuration; only a hosted run can establish hosted execution evidence.

## Pinned Semgrep policy

`semgrep_policy.py` separates network-enabled ruleset hydration from offline
execution. The policy pins Semgrep 1.168.0, the complete canonical upstream
rule-block digest, the exact rule count, and the effective ruleset digest.
Semgrep's registry may return the same rule blocks in a different order, so
hydration accepts only that ordering variance and emits one deterministic order.
It does not normalize rule bodies: a changed ID, pattern, metadata field, byte,
encoding, or ruleset framing fails the canonical digest check. It also refuses
a registry redirect, a changed scanner version, scan output inside the checkout,
findings, or parser errors.
Hydrate once into a private external directory, then run the scan without
Semgrep metrics or registry access:

```sh
mkdir -m 700 /private/tmp/cigar-semgrep
python3 tools/quality/semgrep_policy.py hydrate \
  --output /private/tmp/cigar-semgrep/rules.yml
python3 tools/quality/semgrep_policy.py scan \
  --ruleset /private/tmp/cigar-semgrep/rules.yml \
  --report /private/tmp/cigar-semgrep/report.json \
  --receipt /private/tmp/cigar-semgrep/receipt.json
```

The single rule/path exception preserves the byte-exact Rust standard-library
legal notice. It is bound to that notice's size and SHA-256 and only excludes
the plaintext-link rule; every other rule still scans the file. A toolchain
notice change invalidates hydration and scanning until the provenance and
exception are reviewed together. Source-level suppressions remain exact-rule,
same-line annotations with adjacent security rationale and regression checks.

## Trivy dependency reachability policy

`trivy_policy.py` runs the digest-pinned Trivy 0.69.2 scanner over the complete
checkout. It supplies a private empty config and ignore file, strips ambient
`TRIVY_*` overrides, requests every fixed and unfixed HIGH/CRITICAL dependency
finding, and requires the main Rust, Go, TypeScript, and Python targets to
appear in the report. Reports and receipts must be new
files outside the checkout:

```sh
mkdir -m 700 /private/tmp/cigar-trivy-policy
python3 tools/quality/trivy_policy.py scan \
  --report /private/tmp/cigar-trivy-policy/report.json \
  --receipt /private/tmp/cigar-trivy-policy/receipt.json
```

The policy does not use `.trivyignore`, `--skip-dirs`, global advisory waivers,
or candidate finding dispositions. The obsolete upstream library
`vendor/aws-creds-0.39.1/Cargo.lock` was removed: it was neither a workspace
resolution authority nor required source, and retaining it caused scanners and
development source archives to carry stale vulnerable versions. The exact
upstream manifest remains byte-pinned and the source snapshot remains available
only in the development source archive for provenance. The wrapper proves the
deleted lock is absent through real, non-symlink parents; validates the exact 17
Apple-silicon development artifact IDs and every selected package contract; and
requires `source` to be the sole contract that could select either snapshot
path. It also digest-binds the reviewed source builder and executes the reviewed
SBOM component functions over the repository's actual Rust, npm, Python, and Go
locks. Locked offline Cargo metadata must resolve the distinct patched
`cigar-aws-creds` package, and the artifact, Cargo, and SBOM closures must all
exclude the forbidden versions while retaining their reviewed replacements.
Any HIGH/CRITICAL finding is unclassified and release-blocking. A clean checkout
with zero findings is eligible; a dirty checkout remains diagnostic even when
its scan is empty.

## Isolated pnpm production dependency audit

The build and packaging contract remains pinned to pnpm 10.34.5. The npm audit
service no longer accepts the legacy audit requests emitted by that release, so
`pnpm_audit.py` uses a separate, audit-only pnpm 11.13.0 distribution. The
wrapper binds the complete 456-file pnpm distribution and its Corepack SHA-512
authority. It also requires the exact official Node.js 24.10.0 Darwin-arm64
executable bytes and verifies its Developer ID signature, Node.js Foundation
team, identifier, and full SHA-256 code-directory hash before execution. The
wrapper invokes the auditor directly through Node. It does not change the
repository manifests, install dependencies, execute package scripts, or make
pnpm 11 a build tool.

The wrapper copies only the closed five-file package/lock metadata inventory to
an owner-private temporary workspace. It changes only the temporary root
`packageManager` and pnpm engine fields, isolates all npm/pnpm configuration,
uses the canonical npm registry, and requires strict JSON with no advisory at
any severity. The `--prod` scope covers runtime and optional dependencies; the
development lock graph remains covered by the separate Trivy policy. Before the
request, stable no-follow reads copy the exact Node executable and all 456 pnpm
files into a create-new, owner-private, read-only runtime. The staged runtime is
verified before and after execution, then the original source and tool bytes are
reopened. Only a content-free, mode-0400, create-new receipt is published
outside the checkout.

Hydration is the only tool download step. A local native run is:

```sh
export COREPACK_HOME=/private/tmp/cigar-pnpm-auditor-corepack
export CIGAR_AUDIT_NODE=/private/tmp/node-v24.10.0-darwin-arm64/bin/node
test ! -e "$COREPACK_HOME"
mkdir -m 700 "$COREPACK_HOME"
corepack prepare pnpm@11.13.0 --activate
auditor_root="$COREPACK_HOME/v1/pnpm/11.13.0"

python3 tools/quality/pnpm_audit.py verify-tool \
  --node "$CIGAR_AUDIT_NODE" \
  --pnpm-root "$auditor_root"

evidence=/private/tmp/cigar-pnpm-production-audit-evidence
test ! -e "$evidence"
mkdir -m 700 "$evidence"
python3 tools/quality/pnpm_audit.py scan \
  --node "$CIGAR_AUDIT_NODE" \
  --pnpm-root "$auditor_root" \
  --receipt "$evidence/receipt.json"
python3 tools/quality/pnpm_audit.py verify-receipt \
  --node "$CIGAR_AUDIT_NODE" \
  --pnpm-root "$auditor_root" \
  --receipt "$evidence/receipt.json"
```

The receipt is release-eligible only for a clean committed candidate. It always
records that no fuzz or soak workload was executed by this dependency gate.

`fuzz_and_mutation.py` runs the WP19 fuzz, property/Loom, Miri, and diagnostic
mutation slices with external evidence and private mutable worker corpora. Its
closed `verify-smoke` route requires an exact canonical campaign and workspace,
binds all private logs, recomputes recorded test/fuzzer metrics, and rejects
receipt, log, command, corpus, source, or scratch substitution. The legacy
combined `verify` and `all` routes remain deliberately unavailable; smoke and
release mutation evidence are separate.

The authoritative mutation-only route is now
`cargo xtask test mutations --verify`. On native Apple-silicon macOS it requires
a clean committed source, cargo-mutants 27.1.0, the exact 24-package production
inventory and five explicit package exclusions, exact generated/vendor/test
source exclusions (with production build scripts still included), locked
offline nextest, a Darwin deny-network sandbox, and a create-new source-bound
raw attachment. Verification independently recomputes
the source-file/mutant inventory, baseline, outcome counts, viable denominator,
score, duration, timeout count, and critical survivors. The release policy
requires a 90% score, 14,400 seconds in one complete campaign, every production
Rust package, zero timeouts, and zero viable survivor in critical authentication,
isolation, effect, canonicalization, or integrity code. The four-hour campaign
was deliberately not executed in the current cohort, so no passing mutation
qualification result is claimed. The representative `cigar-canon` diagnostic
sets none of these release metrics.

`fuzz_accumulation.py` is the release-campaign ledger verifier. It accepts only
signed worker receipts for the exact 14-target ASan policy, publishes immutable
hash-chained create-new entries, checks worker trust/time windows, rejects
overlap/replay/mixed candidates/stale binaries/corrupt corpus lineage, resets an
affected target after a defect, and emits exact per-target plus aggregate
metrics. It does not launch a fuzzer. Each target must independently accumulate
604,800 clean CPU-seconds and the reconciled aggregate must be 8,467,200 seconds.
Each qualifying libFuzzer target has a deterministic wall bound equal to its
canonical campaign duration plus a fixed 900-second cold instrumented-build
allowance. The bound is recorded in every process receipt and `verify-smoke`
requires the exact reviewed value; it does not weaken the independently parsed
libFuzzer-duration threshold.
Checked-in and externally minimized corpora retain the canonical 4,096-file,
16-MiB per-target ceiling. Smoke runs use disposable private copies with a
separate 8,192-file, 32-MiB ceiling and the same 1-MiB per-input maximum. The
runner enforces those worker bounds before writing evidence, and `verify-smoke`
rejects malformed or out-of-policy worker measurements.
`corpus_manager.py` inventories, externally minimizes, and safely reconciles
libFuzzer corpus growth. See `fuzz/README.md` and `fuzz/corpus-policy.v1.json`;
neither tool is allowed to silently mutate or discard the checked-in corpus.
Qualification minimization and smoke execution compile only from a closed
Git-index external source mirror bound to a Git-clean read-only candidate.
Direct cargo-fuzz runs use a wrapper-first `PATH`, explicit `CARGO`, nightly
selection, locked/offline inner Cargo, and a Darwin no-network sandbox. Failed
scratch is preserved; successful tool-owned build/mirror/artifact scratch is
verified and removed before the content-free receipt is written.
