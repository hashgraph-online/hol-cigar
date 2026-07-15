# xtask

Stability: internal build infrastructure. This crate is the authoritative implementation of bootstrap, generation, quality, test, documentation, package, and release-verification commands.

## PRD section 28.1 command inventory

`PRD_28_1_COMMANDS` in `src/lib.rs` is the executable authority for all 29 clean-source
qualification routes. Exact examples dispatch through that table before legacy/internal command
forms. The same table generates:

- `prd-28.1-command-manifest.v1.json`, the complete machine authority;
- `generated/readme-command-inventory.md`, the human projection;
- `generated/ci-command-inventory.v1.json`, the 29 implemented native gates; and
- `generated/release-command-inventory.v1.json`, the complete 30-row projection,
  including the additional sanitizer route.

`cargo xtask generate --check` rejects byte drift in all four projections.

The PRD inventory deliberately distinguishes 28 implemented gates from the one intentionally
deferred `fuzz smoke` gate. `cargo xtask test sanitizers` is an additional, non-PRD native command,
so the generated CI inventory has 29 implemented entries. Fuzz and soak are not executed by the
command evidence helper; coverage explicitly excludes `cigar-soak`. The
native macOS coverage gate uses the date-pinned `nightly-2026-07-13` compiler required for LLVM
branch instrumentation: rustc `77cf889bc178ddb44d6a1c78e5a820b5abb31d8d`, Cargo
`59800466c5c41c444d264b1010b4d57e85a7117f`, and LLVM `22.1.8`. The gate accumulates profiles for
every supported explicit workspace feature composition and all targets. It then runs the
independent `tests/properties` workspace with dependency coverage enabled for its production
crates. `cigar-windows-ipc` is the only platform exclusion because its implementation is not
compiled or shipped on macOS.

The mutation route is separate from fuzz and soak and does not run either. It selects all 24
production packages under cargo-mutants 27.1.0, accounts for the five explicit non-production or
foreign-platform workspace exclusions, excludes only the exact reviewed generated/vendor/test
paths, and executes locked/offline nextest under a native Darwin deny-network sandbox. A passing
run must last at least 14,400 observed seconds, score at least 90%, cover every production package,
have zero timeouts, and have zero viable survivor in critical code. The raw-outcome verifier
independently recomputes all source/mutant identities, phase summaries, counts, denominator, score,
duration, and critical classification before accepting the source-bound attachment. Implementing
this route did not execute the four-hour campaign.

All command routes recognize one global `--evidence-dir <absolute-directory>` selector in any
argument position. `CIGAR_EVIDENCE_DIR` is the mutually exclusive environment alternative; both
forms require an absolute normalized path outside the checkout. Use a distinct empty workspace for
each command. Exact PRD routes are currently restricted to native Apple-silicon macOS and fail
before gate execution unless `HEAD` exists and the checkout is clean.

Before an implemented gate runs, xtask captures the full Git revision/tree, verifies the protected
external workspace is empty, and pins the source state. A successful gate is accepted only if the
same clean source remains afterward and the workspace contains exactly one nonempty raw result.
The helper then adds a create-new, owner-read-only (`0400`) wrapper receipt bound to that result,
the command manifest, source, producer, and native host. Matrix and reproducibility routes retain
their existing content-free result as the raw attachment. Coverage rejects missing packages,
targets, declared features, zero/missing branch denominators, malformed percentages, and any
per-package line or branch result below the release-policy threshold. Its content-free receipt
contains recomputed aggregate/per-package minima, output digests, and the checked policy digest.
When `CIGAR_COVERAGE_REPORT_DIR` names a new private directory outside the checkout, the same gate
also publishes its validated branch-bearing `lcov.info` and source-bound per-package JSON there;
CI uses this path for artifacts and never trusts an unverified LCOV upload.

Publication output is not accepted as proof by itself. Xtask invokes a separate read-only verifier
that derives the expected receipt and attachment paths again, opens the exact workspace inventory
through pinned directory descriptors, recomputes bytes and SHA-256, and requires canonical strict
JSON plus the exact command, manifest, producer, source, host, status, and non-release limitations.
Only the coverage and mutation routes may report metrics. Coverage's 14 metric names and
count/covered/percentage relationships are closed and reconciled; mutation's five metrics are
independently reconstructed from the exact raw campaign. Missing or mutable attachments, path substitution, stale
source or producer digests, duplicate manifest IDs, prohibited status, synthetic metrics, and
NaN/infinity therefore fail before the Rust dispatcher accepts command success.

These local receipts are deliberately unsigned and record
`source_descriptor_bound: false`, `source_archive_bound: false`, and
`release_eligible: false`. They cannot qualify a release until the independent candidate
descriptor, source archive, artifact bindings, signatures, and remaining unavailable gates exist.

## Python interpreter contract

There are three intentionally separate Python execution lanes on macOS:

- Rust launches `command_plane_evidence.py` through the absolute root-owned
  `/usr/bin/python3`. The macOS 15 baseline currently resolves this to Apple Python `3.9.6`.
  `command_plane_evidence.py`, `tool_authority.py`, their imported helper closure, and all xtask
  Python tests must therefore remain Python 3.9 compatible. The two system-helper entrypoints use
  an absolute `/usr/bin/python3` shebang; ambient `PATH` cannot select their interpreter.
- Native benchmark, package, sanitizer, and release adapters are launched only through
  `CIGAR_XTASK_NATIVE_PYTHON_PATH`. Rust and the adapter independently require the reviewed binary
  to report exactly Python `3.14.6` and match `CIGAR_XTASK_NATIVE_PYTHON_SHA256`. The adapter is
  import-compatible with 3.9 for complete test discovery, but a native route cannot execute on it.
- A standard route's `python3` is the exact executable in that route's reviewed tool authority.
  Hosted CI pins it to `3.14.6`; it is neither inherited from ambient `PATH` nor substituted for
  the fixed system evidence interpreter.

The compatibility regression command is:

```sh
/usr/bin/python3 -B -m unittest discover -s crates/xtask/tests -p 'test_*.py'
```

The suite also starts `/usr/bin/python3` from a closed environment and imports all three xtask
helpers, preventing Python-3.10-only runtime APIs from silently returning to the system lane.

## Reviewed standard-tool authority

Every implemented non-native route runs under a least-privilege tool authority. The exact tool
names for each route are source-controlled in `route-tools.v1.json`; a route rejects an omitted or
extra tool, an authority for another command ID, and any executable whose protected-file SHA-256
differs from operator approval. Xtask clears the ambient environment, exposes the reviewed tools
through a private shim directory, and binds every direct execution and its content-free output
digests into the receipt. The receipt explicitly reports `network_enforcement: "not-enforced"`;
offline environment flags are not represented as an operating-system no-egress guarantee. Cargo,
Python, Node, and similar runtimes can load transitive files outside their top-level executable, so
these receipts are diagnostic and remain `release_eligible: false`.

`tool_authority.py` never invents an approval digest. An operator first supplies a canonical,
owner-private `cigar.xtask-reviewed-tools.v1` document containing exactly the selected route's
absolute canonical executable paths and independently reviewed lowercase SHA-256 values. From a
clean committed checkout, create the source-bound authority in an external private directory:

```sh
authority_root=/private/tmp/cigar-reviewed-tools
umask 077
test ! -e "$authority_root"
mkdir -m 700 "$authority_root"
mkdir -m 700 "$authority_root"/{cargo,corepack,go-build,go-mod,home,npm,rustup,uv}

/usr/bin/python3 -B crates/xtask/tool_authority.py draft \
  --command-id format-check \
  --reviewed-tools "$authority_root/reviewed-format-tools.json" \
  --environment "CARGO_HOME=$authority_root/cargo" \
  --environment "COREPACK_HOME=$authority_root/corepack" \
  --environment "GOCACHE=$authority_root/go-build" \
  --environment "GOMODCACHE=$authority_root/go-mod" \
  --environment "HOME=$authority_root/home" \
  --environment "NPM_CONFIG_CACHE=$authority_root/npm" \
  --environment "RUSTUP_HOME=$authority_root/rustup" \
  --environment "UV_CACHE_DIR=$authority_root/uv" \
  --output "$authority_root/format-check.authority.json"
```

Each environment directory must already exist, be canonical, owner-owned, and mode `0700`. The
operator must compare the emitted authority SHA-256 through an independent review channel. The
reviewed value is mandatory when independently reopening the document and for an
operator-reviewed execution:

```sh
approved_sha256='<independently-reviewed-lowercase-sha256>'
/usr/bin/python3 -B crates/xtask/tool_authority.py validate \
  --authority "$authority_root/format-check.authority.json" \
  --expected-sha256 "$approved_sha256"
export CIGAR_XTASK_TOOL_INPUTS="$authority_root/format-check.authority.json"
export CIGAR_XTASK_TOOL_INPUTS_SHA256="$approved_sha256"
```

If the SHA selector is deliberately omitted, Rust labels the authority
`review_status: "diagnostic-self-observed"`; the already non-release-eligible receipt may support
development debugging but is not launch qualification. Supplying a malformed or wrong digest
always fails. Release workflows must require `review_status: "operator-reviewed"`.

One authority is valid for one command ID and one exact clean Git source only. CI therefore needs
an operator-maintained digest set for the pinned macOS runner image and must draft a distinct
authority after tool installation for every xtask route it invokes. Until those external reviewed
digests are configured, affected hosted xtask jobs are an explicit bootstrap blocker rather than
release evidence.

### Hosted macOS CI bootstrap contract

The current `fast-ci.yml` and `security.yml` route invocations do not manufacture or approve tool
authority. They therefore fail closed before delegated execution until the release operator adds a
trusted bootstrap step. That step must run separately for each command ID and must:

1. start from the exact checked-out clean commit and pinned macOS arm64 runner/tool installation;
2. obtain the route's exact tool names from `route-tools.v1.json`, with no global superset;
3. obtain each canonical executable path and SHA-256 from an independent operator-controlled
   review channel, then create the protected `cigar.xtask-reviewed-tools.v1` input;
4. create all eight external mode-`0700` environment directories and use `tool_authority.py draft`
   to produce one source-bound authority document;
5. compare that document's SHA-256 through the independent channel and run
   `tool_authority.py validate --expected-sha256 ...` before exporting both selector variables;
6. invoke exactly one matching xtask route, unset both selectors, and independently reopen the
   receipt; and
7. reject launch qualification unless the receipt binds the expected source, route, manifest,
   exact tool set, execution digests, and `review_status: "operator-reviewed"`.

Because the authority embeds the Git source object, neither an authority document nor its approval
digest may be reused for a different commit. Runner-image or tool-byte changes also require a new
review. Omitting only `CIGAR_XTASK_TOOL_INPUTS_SHA256` is an explicit development diagnostic; it can
never satisfy this bootstrap contract. Omitting `CIGAR_XTASK_TOOL_INPUTS`, using an authority for a
different route, or supplying a stale/wrong digest always blocks execution.

The remaining live-proof prerequisite is one clean committed checkout plus that externally
approved route authority. The shared integration checkout is intentionally unsuitable while it has
concurrent edits: source snapshotting must reject it instead of issuing a launch receipt.

## External benchmark, package, and release inputs

The nine PRD benchmark/package/release routes have exact command lines but intentionally do not put
signer handles, evaluator keys, independent trust roots, candidate locations, or producer
workspaces on their CLI. Select those inputs with exactly one
`CIGAR_XTASK_COMMAND_INPUTS=/absolute/canonical/authority.json` and its independently reviewed
byte digest with `CIGAR_XTASK_COMMAND_INPUTS_SHA256=<lowercase-sha256>`. The authority is strict canonical
JSON, mode `0400` or `0600`, owner-owned, single-link, outside the checkout, and contains exactly:

- `schema_version: "cigar.xtask-native-macos-command-inputs.v1"`;
- one exact `route` ID;
- the clean Git `source` object emitted by the command evidence snapshot; and
- one route-specific, closed `inputs` object.

The adapter rejects embedded private-key bytes. Key and seed fields contain only absolute protected
file paths; candidate CLI paths such as `dist/` remain safe-relative and resolve only beneath the
authority's external `artifact_root`. Every input path is canonical and free of symlink traversal,
hardlinks, writable group/world permissions, portable case/Unicode aliases, and repository-local
fallback. File identity, size, timestamps, and SHA-256—and read-only input-tree inventories where
applicable—must remain stable through the delegated tool. Only the authority byte count and digest,
tool output digests, counts, and status are retained in the content-free raw result.

Native routes also require an explicitly selected interpreter:
`CIGAR_XTASK_NATIVE_PYTHON_PATH=<absolute-canonical-path>` and
`CIGAR_XTASK_NATIVE_PYTHON_SHA256=<operator-reviewed-sha256>`. The executable and every ancestor
must be protected; Homebrew is not assumed. The interpreter must report exactly Python `3.14.6`.
Its version-probe stdout/stderr byte counts and SHA-256 values are independently captured by Rust
and the Python adapter and included in the raw binding. The top-level executable is pinned, while
its transitive standard-library/framework files are explicitly not claimed as bound.

The closed input sets are:

| Route | Required authority inputs |
|---|---|
| `bench-micro-verify` | Candidate/baseline performance manifests, sample streams, attestations, evaluator-key files, and the comparison report |
| `bench-macro-verify` | The micro inputs plus installed local-scale driver, immutable profile/binding, and completed physical-scale receipt |
| `bench-efficacy` | Complete 12-comparator evidence root, environment, hidden seed file, evaluator-key file, and expected matrix report |
| `package-all` | Ten exact producer workspaces, empty assembly output root, and source epoch |
| `package-smoke` | External artifact root, runtime/tool build receipts, and empty installed-qualification evidence root |
| `release-sbom` | External artifact root, safe candidate/output directories, and source epoch |
| `release-sign` | External candidate, signer/public/private-key paths, reviewed OpenSSL identity, time window, signature directory, and exact payload/purpose list |
| `release-attest` | External candidate, source epoch, builder/workflow/network declarations, exact build commands, materials, and output path |
| `release-verify` | External artifact root, independent trust policy, verification time, and empty report workspace |

Absent or mismatched authority fails blocked before the delegated operation. Signing is never
inferred and no production key is generated. The sanitizer route rejects this selector and instead
uses the fixed public `verify-manifest`, `run --receipt`, and `verify-receipt --receipt` contract in
`tools/quality/production_sanitizers.py`.

For example, from a clean committed checkout:

```sh
evidence_parent="$(mktemp -d /private/tmp/cigar-evidence.XXXXXX)"
evidence_root="$evidence_parent/generate-check"
CIGAR_EVIDENCE_DIR="$evidence_root" cargo xtask generate --check
```

The generated inventory, not this example, is authoritative for route availability.
