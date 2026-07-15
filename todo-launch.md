# CIGAR v1 production launch backlog

Audience: Codex GPT-5.6 SOL and release operators
Generated from repository state: 2026-07-13
Candidate identity: derive the full commit/tree from the immutable source descriptor after freeze; a hash embedded in this mutable backlog is never release identity
Target: a clean, immutable CIGAR v1.0.0 candidate and exact-byte production release

### Current execution cohort — 2026-07-14

- [x] Limit this run to native Apple-silicon macOS (`aarch64-apple-darwin`). Linux,
      Windows, Intel macOS/Rosetta, and OCI require separate profiles and cannot inherit this
      cohort's evidence.
- [x] Defer fuzz accumulation and installed-service soak execution for this run without treating
      either as passed, waived, or optional. Both remain release-blocking before publication.
- [x] Keep every selected artifact in development/planned state until exact bytes independently
      reach built, packaged, qualified, published, and supported states.

## Launch verdict

**STOP-SHIP. The observed commit is a useful baseline, not a releasable candidate.**

Do not tag, publish, notarize, sign, or describe this revision as production-ready until every release-blocking item below is complete and the final offline verifier passes.

| Area | Observed state | Required state |
|---|---|---|
| Source | Development history and historical receipts are not release identity; current workspace changes remain unqualified until frozen and rerun | One clean candidate commit/tree in the external source descriptor; qualification writes outside the checkout; no receipt rebinding |
| Command plane | All 29 PRD section 28.1 routes parse strictly: 28 non-fuzz macOS-arm64 routes have distinct receipt-producing implementations; only `fuzz smoke` remains explicitly unavailable and was not executed. Soak was also not executed. Candidate-bound reruns remain open. | Every PRD section 28.1 command dispatches to a distinct real, fail-closed gate with source-bound receipts |
| Security | Current-tree diagnostics pass the 10/10 security matrix and a 603-rule Semgrep scan over 13,025 targets with zero findings; neither result is clean-candidate/final-artifact evidence | All release cases and pinned scans pass on applicable native platforms |
| Security review | Previous scan read 73/380 source-like files fully and retains 12 deferred proof gaps | Fresh deep scan of exact candidate, 100% claimed-surface disposition, zero critical/high |
| Coverage | Stale LCOV covers 642 lines, reports 36.449% line coverage, and no branches | All release code/targets; line >= 80%, branch >= 70% |
| Fuzz | 14 targets passed approximately 60 seconds each | Each target >= 604,800 clean CPU-seconds; aggregate >= 8,467,200; zero defects |
| Mutation | 42-second `cigar-canon` slice caught 10/10 viable mutants | Full production RC campaign >= 4 hours; critical survivors/timeouts = 0 |
| Traceability | The v2 registry resolves all 177 source/derived requirements through active exact-command mappings, but the result is not yet candidate-bound | Every normative requirement maps to active candidate-bound evidence |
| WP20 | Seven demos, four recorded SDK workflows, and 540-event dry run pass local scope only | Installed-byte runs, real comparators, >= 270 independent adjudicated tasks, independent evaluator |
| Packaging | All 17 rows selected by the macOS development profile have deterministic development producers; the five unimplemented rows are the explicitly deferred Linux, Intel-macOS, Windows, and OCI artifacts; no candidate `dist/` exists | Every claimed artifact has a deterministic producer, contract, installed test, and final-byte evidence |
| Licensing | 629 lock-resolved source components are inventoried with zero technically unresolved policy expressions; legal approval and final packaged-byte reconciliation remain open | Zero unreviewed distributed components |
| Metadata | The GA matrix remains development while WP22 requires v1.0.0. A separate `0.1.0-beta.1` profile exists but is not candidate- or artifact-qualified; all GA and beta qualification gaps remain open | One GA version/ABI and every GA gap closed independently; one exact beta identity and every beta gap closed before prerelease publication |
| Operations | Eight runbooks pass static validation only | Eight live exercises against exact installed bytes |
| CI/repository | A pinned macOS-arm64 fast lane and a non-uploading unsigned archive diagnostic exist and pass local workflow validation; no authoritative hosted run or configured Git remote is available here | Authoritative protected remote plus merge, nightly, weekly, RC, build, qualification, signing, and promotion workflows |

## Initial beta lane — `0.1.0-beta.1`

**STOP-SHIP. This is a prerelease workspace-administration lane, not a v1.0.0 shortcut and not a production-ready build.**

Beta completion does not mark any GA task, WP19, WP20, WP21, WP22, or final PRD checklist item complete. The exact contract is in `docs/release/INITIAL_BETA.md`.

Pinned identity: profile `cigar.beta.embedded-local.linux-x86_64.v1`, tag `v0.1.0-beta.1`, target `x86_64-unknown-linux-gnu`, required qualification runtime Ubuntu 24.04 x86_64 with glibc 2.39, Rust 1.92.0, Python 3.14.6, prerelease `true`, production-ready `false`. The included executable surface is limited to local workspace-state administration: `init`; source add/list/remove; project list/attach/detach/switch/link/unlink; focus switch/close; help; and version. It does not ingest, index, retrieve, compile context, serve a daemon/API/MCP endpoint, execute effects, load extensions/plugins, export OTLP, provide SDKs, use vector/remote/shared modes, or claim macOS, Windows, ARM, OCI, or installers.

### BETA-000 — Close and verify the beta contract

Dependencies: none
Executor: Codex
Beta release blocking: yes

- [x] Execute the pinned profile/schema checker and its fail-closed eight-test suite in the development workspace.
- [x] Execute compile-time feature-isolation checks: full and beta modes remain separate, neither/both fail closed, and asserted excluded dependency families are absent from the beta graph.
- [x] Execute the beta CLI suite in the development workspace; 22 tests (10 unit and 12 integration) passed at the recorded proof point.
- [x] Narrow the capability manifest's broad “embedded-local execution” description to the actual workspace-administration-only behavior and make profile, compiled help, implementation, tests, and public documentation identical.
- [x] Remove or explicitly contract-test accepted aliases/options outside the advertised surface, including `--confirm`, `--help`/`-h`, and `--version`/`-V`.
- [x] Fix and regress the state-directory replacement/lock-bypass race; prove exclusive mutation, symlink/path-race resistance, restrictive modes, atomic durability, recovery, deadlines, and deterministic concurrency failure.
- [x] Require evidence/signature helpers and their production call path to validate complete candidate, source-archive, artifact, version, profile, purpose, and complete-set bindings; add missing/duplicate/substitution negative tests.

### BETA-001 — Freeze one immutable beta candidate

Dependencies: BETA-000
Executor: Codex
Beta release blocking: yes

- [x] Commit all intended beta source, contracts, tests, generated files, documentation, lockfiles, and release tooling; record the full candidate SHA and tree and prove the worktree clean before and after every gate.
- [x] Produce a deterministic source archive and canonical source descriptor binding commit, tree, source-archive name/SHA-256/size, commit-derived `SOURCE_DATE_EPOCH`/generation time, and exact profile/policy/contract/tool-input digests. Builder, toolchain, and network observations belong to the later candidate provenance and qualification receipts.
- [x] Run from a detached read-only checkout or verified source archive, with all evidence and build outputs external to candidate source. Prove source bytes and Git status remain unchanged.
- [x] Rerun the three recorded workspace checks and every BETA-000 regression against the exact candidate; workspace receipts do not qualify by reuse.

### BETA-002 — Build the exact six-artifact set

Dependencies: BETA-001; qualified native Ubuntu 24.04 x86_64/glibc 2.39 builder
Executor: Codex plus release builder operator
Beta release blocking: yes

- [ ] On an isolated native Ubuntu 24.04 x86_64/glibc 2.39 builder with Rust 1.92.0 and Python 3.14.6, produce exactly `cigar-0.1.0-beta.1-source.tar.gz`, `-docs.tar.gz`, `-schemas.tar.gz`, `-conformance.tar.gz`, `-licenses.tar.gz`, and `-x86_64-unknown-linux-gnu.tar.gz` from the same source descriptor.
- [ ] Require the binary archive to contain only the allowlisted `bin/cigar` executable payload; reject missing/extra files, unsafe types/paths/links, wrong modes/owners/timestamps, collisions, bombs, and trailing data in every archive.
- [ ] Independently rebuild from the same source archive and prove deterministic byte identity or the approved closed normalization comparison. Bind both builders, toolchains, materials, and results.
- [ ] Generate one canonical checksums document; reject an unlisted seventh artifact or a missing required artifact.

### BETA-003 — Qualify installed bytes and supply chain

Dependencies: BETA-002
Executor: Codex plus security, legal, and signing operators
Beta release blocking: yes

- [ ] Install the exact binary archive as an unprivileged user in a clean Ubuntu 24.04 x86_64/glibc 2.39 environment without source, compiler, writable dependency cache, privilege, or undeclared runtime dependency.
- [ ] Enforce OS-level no-egress and run positive smoke for every included command/output mode plus restart, persistence, permission, concurrency, cancellation/deadline, malformed-state, and excluded-command negative cases.
- [ ] Scan packed and unpacked final bytes for vulnerabilities, malware indicators, secrets, unexpected endpoints, developer paths, and undeclared native/runtime dependencies; permit no critical/high or unknown/skipped result.
- [ ] Reconcile licenses/notices and produce artifact-bound SPDX and CycloneDX SBOMs plus provenance covering source, all six artifacts, materials, toolchains, builders, parameters, network mode, and reproducibility.
- [ ] Sign every qualification receipt and attachment with `cigar-beta-qualification-evidence-v1`, then sign artifacts, checksums, SBOMs, provenance, and release evidence with their reserved `cigar-beta-release-*` purposes through the approved isolated signer and independently distributed beta trust roots.

### BETA-004 — Verify and publish exact prerelease bytes

Dependencies: BETA-003; signer and publisher authority
Executor: independent verifier plus release publisher
Beta release blocking: yes

- [ ] Assemble a complete canonical `cigar.beta.release-evidence.v1` set with no failed, skipped, waived, unknown, stale, dirty, or unbound result. GA evidence schemas and signature purposes are forbidden.
- [ ] Run the independent verifier offline from a clean environment using only the candidate artifacts, signed evidence, pinned contracts/policy, and approved public trust roots.
- [ ] Obtain release-owner approval and publish the already-qualified bytes under `v0.1.0-beta.1` without rebuild or metadata mutation. Do not update `latest`, stable, or GA channels.
- [ ] Read back every public artifact, checksum, signature, SBOM, provenance, and evidence object and require exact digest agreement.

External prerequisites remain open until supplied by their owners: qualified native Ubuntu 24.04 x86_64/glibc 2.39 builder capacity (preferably two independent builders), production beta signer/trust roots, approved final scanner data and security disposition, legal approval, a verified private security-reporting channel, and protected release-host publisher authority.

The external directories named `launch-000-quality-cache-4081a835`, `launch-000-smoke-4081a835`, and `launch-000-wp20-local-4081a835` are tied to source `4081a8355b8e6bd5959dcc44c48b63b9d8dc55ca` (tree `844643f2d0daf36b4813c66fd62c3c65a2fdc952`). They remain historical diagnostics only and cannot qualify or be rebound to the beta candidate.

### Dependency-safe execution order

The phase numbers group related ownership; forward dependencies are intentional. Execute in this order:

1. LAUNCH-000 through LAUNCH-004.
2. LAUNCH-100 through LAUNCH-108 against the first clean candidate.
3. Implement LAUNCH-300, then commit a new candidate and rerun every invalidated LAUNCH-1xx gate.
4. Build preliminary exact artifacts with LAUNCH-301 through the local portion of LAUNCH-304.
5. Execute LAUNCH-200 through LAUNCH-202 against those installed bytes. Any product/performance fix creates a new candidate and loops to step 2.
6. Rebuild final artifacts once, then complete public portions of LAUNCH-303 and LAUNCH-304 through LAUNCH-309 without changing source or qualified payloads.
7. Complete LAUNCH-400 through LAUNCH-404.

Do not start long fuzz/soak/evaluator campaigns until source-changing command-plane, version, producer, and CI work is frozen.

## Checkbox and evidence contract

- [ ] **CHECK-001 — Evidence before checkbox.** Mark a box only after reading its machine evidence and confirming every pass condition. Exit zero is insufficient when evidence is stale, partial, skipped, waived, synthetic, empty, or bound to the wrong source/artifact.
- [ ] **CHECK-002 — One immutable candidate.** Bind every source receipt to one full Git SHA/tree. Bind installed receipts to source SHA, source-archive SHA-256, artifact ID/SHA-256, contract digest, and platform.
- [ ] **CHECK-003 — Read-only candidate.** Run qualification from a detached fresh checkout or verified source archive. Write receipts/raw attachments to external `CIGAR_EVIDENCE_DIR` or `dist/evidence`.
- [ ] **CHECK-004 — No waiver semantics.** Reject `failed`, `skipped`, `ignored`, `quarantined`, `flaky`, `waived`, `unknown`, missing, and empty results. Never lower thresholds, delete cases, bless vectors, weaken contracts, or broaden scanner exclusions to pass.
- [ ] **CHECK-005 — Fix at the owner.** Preserve private diagnostics outside the release tree, reproduce minimally, fix production code/harness, add a regression, create a new candidate, and rerun invalidated gates.
- [ ] **CHECK-006 — Continue around external blockers.** Complete every independent local task while recording missing external authority. Never fabricate signer, registry, evaluator, notarization, native-host, managed-service, or approval evidence.
- [ ] **CHECK-007 — Exact-byte promotion.** Build once, qualify those bytes, sign those bytes, publish those bytes. Any rebuild invalidates downstream artifact evidence.
- [ ] **CHECK-008 — Preserve user work.** Do not use `git reset --hard`, `git clean`, or bulk deletion to resolve corpus churn.

### Evidence invalidation

| Change | Minimum invalidation |
|---|---|
| Production source, tests, schema, vector, lock, generator, toolchain pin, gate policy, or build script | New candidate; all source and downstream evidence |
| Fuzz defect | Commit regression; new candidate; restart affected target's clean accumulation; rerun affected/downstream gates |
| Artifact/archive/installer/image/contract content | All evidence bound to it plus aggregate SBOM, signatures, provenance, reproducibility, release evidence |
| Requirements, thresholds, artifact matrix, trust policy, category map | All evidence evaluated by that policy; review anti-weakening pins |
| Public registry/download mismatch | Stop; never overwrite immutable versions; correct under a new version |

## Canonical execution environment

- [ ] **ENV-001 — Isolate paths and identity.**

  ```sh
  set -eu
  ROOT="$(git rev-parse --show-toplevel)"
  CANDIDATE_SHA="$(git -C "$ROOT" rev-parse HEAD)"
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$CANDIDATE_SHA")"
  : "$CIGAR_EVIDENCE_DIR"
  : "$DIST"
  export CANDIDATE_SHA SOURCE_DATE_EPOCH CIGAR_EVIDENCE_DIR DIST
  export TZ=UTC LC_ALL=C LANG=C PYTHONHASHSEED=0 NO_COLOR=1
  test -z "$(git -C "$ROOT" status --porcelain=v1)"
  ```

  Emit `preflight/environment.json` with OS/architecture, exact tools, builder, source SHA/tree, source archive digest, policy digests, start/end, and network mode.

- [ ] **ENV-002 — Separate hydration from execution.** Hydrate immutable dependency caches in an explicit network-enabled job, digest them, then run locked/offline with OS-enforced no-egress. An environment variable alone is not enforcement.
- [ ] **ENV-003 — Standardize receipts.** Each `cigar.qualification-evidence.v1` receipt must contain producer/tool digest, redacted command digest, candidate SHA/tree, source archive digest, artifact IDs/digests, policy digest, platform/builder, times/duration, network mode, metrics, status, and attachment SHA-256/size. Never include source content, secrets, hidden seeds, or private logs.

---

## Phase 0 — Make a candidate possible

### LAUNCH-000 — Reconcile fuzz churn and freeze a clean baseline

Dependencies: none
Executor: Codex
Release blocking: yes

- [x] Capture current status, tracked/untracked corpus counts, WP19 receipt diffs, and corpus digests outside the repository.
- [x] Classify fuzz data as hand-authored seed, minimized regression, reusable corpus, transient corpus, crash/artifact, or duplicate.
- [x] Preserve the MCP regression SHA-1 `8990a2f1ca2774f3cea4ad12624eac0acf7bfd31` (SHA-256 `02c4f7d2c1e81d5f3c5768d3dfdccc94fe8d99a407ad60d58e464d49ced6b144`) as a named fixture tied to its regression test.
- [x] Implement deterministic per-target minimization into fresh outputs; enforce byte/count ceilings, preserve named regressions, and emit old-to-new digest maps. Never share a writable corpus between fuzzers.
- [x] Commit only reviewed seeds/regressions/minimized corpus. Narrowly ignore transient output; never ignore crashes awaiting triage.
- [x] Move generated qualification receipts out of tracked source paths. Label any tracked sample receipt as non-qualification.
- [x] Keep current WP19 smoke/mutation receipts as historical smoke evidence only.
- [ ] Regenerate stale source-baseline content in status/gap documents and WP20/WP21 receipts against the eventual exact candidate without claiming packet or release completion.
- [ ] Commit the policy/corpus/status changes and record the later SHA. Prove a smoke gate leaves `git status --porcelain=v1` empty.

Done when the source/fixtures are intentional, no regression is lost, and the checkout is clean before and after testing.

### LAUNCH-001 — Add a first-class external evidence workspace

Dependencies: LAUNCH-000
Executor: Codex
Release blocking: yes

- [x] Implement and revalidate the shared POSIX evidence primitive used by release producers:
      absolute external owner-only roots, directory-descriptor traversal, symlink/hardlink and
      rebound-path rejection, create-new atomic publication, canonical finite JSON, stable bounded
      attachments, case/Unicode collision checks, and file/count/byte/depth ceilings. Producer
      integration remains open below.
- [x] Integrate the matrix runner with that primitive. A release-profile run now requires exactly
      one absolute external evidence root selected by `--evidence-dir` or
      `CIGAR_EVIDENCE_DIR`; conflicting selectors, repository-local output, private logs,
      overwrite, path escape, unsafe modes, symlinks, and portable-name collisions fail closed.
- [x] Integrate candidate-bound static and live operation/runbook evidence with the same external
      workspace. The legacy `--out` path remains development-static-only; candidate output is
      canonical, bounded, create-new, read-only, content-addressed, external, and rejects selector
      conflicts, nonempty roots, path rebinding, unsafe links/modes, escape, and collisions.
- [x] Integrate package-verification and final offline-verification reports with the external
      workspace. Both accept explicit/environment evidence roots, retain distinct-input checks,
      and reject repository/dist destinations, ambiguous selectors, absolute/escaping relative
      paths, overwrite, unsafe modes/links, collisions, and root rebinding before publishing
      canonical create-new `0400` reports.
- [x] Integrate installed-archive qualification reports with the external workspace while
      preserving stdout-only development qualification. Report paths are relative, create-new,
      canonical, and owner-only; child qualification drivers cannot inherit or mutate the parent
      evidence workspace.
- [x] Integrate two-builder reproducibility reports with the same external workspace. Explicit and
      environment-selected roots conflict fail closed; selected reports must use safe relative
      paths outside the source and are canonical, owner-only, create-new outputs. Legacy direct
      reports remain development-only.
- [x] Integrate provenance generation with the external workspace. Selected provenance is written
      through a pinned directory descriptor to a safe relative create-new `0400` path outside the
      source, with input/output alias, selector conflict, escape, internal-root, and overwrite
      rejection; legacy direct output remains development-only.
- [x] Integrate SPDX, CycloneDX, and artifact-binding SBOM publication with the external workspace.
      A selected relative output prefix produces three canonical create-new `0400` documents under
      a pinned external root and rejects selector conflicts, escapes, internal roots, unsafe modes,
      links, collisions, and overwrite; the empty-directory direct mode remains development-only.
- [x] Integrate the WP21 local-development qualifier receipt with the external workspace and keep
      nested commands isolated from its selector. Its ephemeral signature self-test now uses a
      canonical external owner-only scratch path on macOS, so the `/var` to `/private/var` alias is
      resolved and verified before signing and never bypasses signature output policy; the receipt
      remains explicitly `release_ready: false` and does not represent production signing evidence.
- [x] Integrate documentation-check reports with the external workspace. Selected reports require
      safe relative paths and publish canonical create-new `0400` JSON through a pinned external
      root; input aliases, selector conflicts, internal roots, escape, unsafe links/modes,
      collisions, overwrite, and rebinding fail closed. No-report and direct-report modes remain
      development-only, child commands cannot inherit the parent selector, and candidate binding
      remains a separate open gate.
- [x] Integrate third-party license-inventory publication with the external workspace. Selected
      inventories require safe relative paths and publish canonical create-new `0400` JSON through
      a pinned external root; input aliases, selector conflicts, internal roots, escape, unsafe
      links/modes, collisions, overwrite, and rebinding fail closed. Direct output remains
      development-only, Cargo metadata cannot inherit the selector, and candidate/source/artifact
      binding plus all outstanding license reviews remain separate open gates.
- [x] Integrate deterministic documentation-site publication with the external workspace. The
      complete site is staged and validated before selected safe-relative HTML, assets, and the
      canonical manifest publish create-new at mode `0400`; stable staged SHA-256/size bindings are
      rechecked before publication so post-validation substitution fails closed. Input aliases,
      selector conflicts, internal roots, escape, unsafe links/modes, collisions, overwrite, and
      rebinding fail closed. Direct output and no-output `--check` remain development-only, and
      candidate/source/artifact plus deployed-site binding remain separate open gates.
- [x] Integrate the primary CIGARBench, section-22 performance, comparator-matrix, WP20-readiness,
      seven-demo, recorded four-SDK, and installed-artifact demo producers with the shared
      external workspace. Protected outputs are safe-relative, canonical, bounded, create-new
      `0400` files; selector conflicts, repository-local output, aliases, traversal, and overwrite
      fail closed, and child probes do not inherit the parent selector. The macOS CIGARBench tool
      now packages the shared primitive. Publication receipts deliberately record
      `qualifying_evidence=false` and `source_descriptor_bound=false`; this completes safe output
      plumbing only, not WP20 efficacy or candidate binding. Focused benchmark, performance,
      matrix, readiness, demo, and macOS qualification-tool suites pass 74/74 tests without fuzz
      or soak execution.
- [x] Add one strict global xtask `--evidence-dir <absolute-directory>` selector, independent of
      argument position, with missing/duplicate/inline/relative/non-normalized forms rejected.
      `CIGAR_EVIDENCE_DIR` is the mutually exclusive validated alternative. The eight implemented
      matrix routes forward the command-line selector to the shared protected workspace; all 33
      xtask tests pass. Routes that still lack receipts remain explicitly non-release-eligible, so
      selector parsing alone is not represented as qualification evidence.
- [x] Close selector handling across the remaining release entrypoints. Evidence-producing
      assembly, signing, and verifier self-tests publish canonical external create-new `0400`
      outputs through the shared primitive; stdout-only validation, source-tree mutation, and
      verification-only entrypoints recognize then reject selectors as semantically inapplicable
      instead of fabricating receipts. The beta source-freeze/candidate and signed-release
      orchestration entrypoints now accept the same selector as an unambiguous replacement for
      legacy `--out`; their verification-only actions reject it. Focused selector/adversarial,
      legacy profile/version, beta-release/signature, and shared-workspace suites pass 93/93; an
      exact 32-entrypoint inventory test prevents future selector omissions. Real
      metadata validation, verifier self-tests in both modes, and external Ed25519 signing also
      pass. A source scan now finds no release Python entrypoint lacking explicit
      evidence-selector/workspace handling.

- [x] Make every xtask, matrix, fuzz/mutation, benchmark, demo, and release entrypoint recognize
      `--evidence-dir` or `CIGAR_EVIDENCE_DIR`. The Rust task runner validates a single global
      selector and forwards it for all implemented matrix gates; the quality matrix,
      fuzz/mutation harness, CIGARBench/performance/readiness/comparator producers, seven-demo and
      SDK/installed-artifact harnesses, and every release Python module now have explicit
      selector/workspace handling. Source-mutating and stdout-only commands reject the selector as
      inapplicable rather than emitting false evidence. Fuzz and soak execution were not used to
      close this interface-plumbing task and remain mandatory deferred gates.
- [ ] In release mode reject outputs inside the candidate, symlink traversal, path escape, case collision, overwrite, and group/world-writable paths.
- [ ] Use atomic create-new writes, bounded counts/sizes, canonical JSON, explicit modes, and durable rename where needed.
- [ ] Share one source descriptor: full commit/tree, clean/committed flags, source archive digest, policy and toolchain digests.
- [ ] Test stale SHA, dirty source, mutable/missing attachment, duplicate ID, prohibited status, synthetic metric, NaN/infinity, and path substitution.
  - [x] Close this adversarial set for the authoritative xtask command wrapper: a distinct
        post-publication verifier reopens the exact external inventory, recomputes attachment
        bytes/SHA-256, requires canonical strict JSON and exact command/manifest/producer/source
        bindings, rejects metrics outside the closed coverage inventory, and is now mandatory for
        ordinary and coverage dispatch success. Focused Python, Rust, and shared-workspace suites
        pass 23/23, 35/35, and 12/12 respectively on native macOS without fuzz or soak execution.
        The unchecked parent remains open for equivalent negative proof across every other release
        producer and verifier.
- [ ] Prove a full source gate leaves a read-only checkout byte-identical and clean.

### LAUNCH-002 — Implement the authoritative PRD command plane

Dependencies: LAUNCH-001
Executor: Codex
Release blocking: yes

Replace unavailable placeholders, aliased suites, and ignored flags with strict parsing and real dispatch.

- [x] Harden the currently implemented `bootstrap`, `generate`, `vectors`, `fmt`, `lint`,
      `architecture-check`, `conformance`, `test`, `docs`, and help routes so trailing, unknown,
      and duplicate arguments are rejected instead of ignored. Placeholder routes remain open
      below until they have real gates.

- [ ] Implement and receipt-test every interface:

  | Interface | Required real gate |
  |---|---|
  | `cargo xtask bootstrap --verify` | Verify every pinned required tool; reject drift |
  | `fmt --check` / `generate --check` / `lint` / `docs --check` | Full formatting, generated drift, all-target/all-feature lint, docs/command checks |
  | `test unit` / `vectors` / `compatibility` / `integration` / `conformance` / `e2e` / `security` / `offline` | Distinct enumerated suites; no alias to generic workspace test |
  | `fuzz smoke` | Fourteen-target smoke only, never RC accumulation |
  | `test sanitizers` / `models` / `coverage --verify` / `mutations --verify` / `chaos` / `migrations` | Real specialized gates and raw evidence |
  | `bench micro --verify` / `macro --verify` / `efficacy` | Candidate-bound micro, installed performance/scale, qualified CIGARBench |
  | `package --all` / `package --smoke dist/` | Produce complete matrix; contract/install smoke exact files |
  | `release reproduce` / `sbom` / `sign` / `attest` / `verify dist/` | Existing fail-closed release tools; nested verify is the single technical go/no-go |

- [x] Reject unknown/duplicate/unused flags, missing required values, path escapes, and incompatible
      combinations across implemented and fail-closed placeholder routes. Incomplete PRD routes
      parse their exact interface and then return an explicit unavailable error; they never report
      placeholder success.
- [x] Ensure `test property` reaches the independent `tests/properties` workspace and is not
      silently `test unit`; the separate locked Proptest/Loom workspace passed on native macOS
      arm64 in this execution cohort.
- [x] Add table-driven dispatcher tests for all 29 PRD section 28.1 commands. The executable
      manifest is checked against the PRD section itself and exercises exact routes, required
      arguments, duplicates, unknown input, incompatible combinations, and unsafe/ambiguous path
      forms without executing fuzz or soak.
- [x] Centralize those 29 routes in `PRD_28_1_COMMANDS` and generate the checked
      `crates/xtask/prd-28.1-command-manifest.v1.json` inventory from it. The inventory records
      28 implemented receipt-producing gates and only the intentionally deferred `fuzz smoke`
      route as unavailable/non-release-eligible rather than promoting placeholder success.
- [x] Fail any required route that returns success without a non-empty source-bound receipt/raw
      attachment. Every implemented exact route now preflights a distinct absolute external empty
      workspace, requires native macOS arm64 and a clean committed source, rechecks the source after
      execution, and requires exactly one positive-length SHA-256-bound raw result before publishing
      its create-new `0400` wrapper receipt. These unsigned local receipts remain explicitly
      non-release-eligible and cannot replace candidate/archive/artifact/signature bindings.
- [x] Bind standard command execution to the v2 per-route reviewed-tool authority. The checked
      `crates/xtask/route-tools.v1.json` policy declares one sorted, exact least-privilege tool set
      per command ID; wrong-route, omitted, extra, relative, symlinked, group-writable, replaced,
      or digest-mismatched executables fail closed. The owner-private external authority document
      is source-bound and must match the independently supplied
      `CIGAR_XTASK_TOOL_INPUTS_SHA256`; its own internally computed digest is not approval.
- [x] Remove the fixed Homebrew Python assumption from native routes. Operators must supply an
      external canonical `CIGAR_XTASK_NATIVE_PYTHON_PATH` and independently reviewed executable
      SHA-256. Every ancestor is protected, Python must report exactly `3.14.6`, and both the Rust
      launcher and Python adapter bind the exact version-probe output. Runtime hashing uses a
      no-follow descriptor and compares named/opened identity before and after the bounded read, so
      pathname replacement cannot validate different bytes. Hosted-toolcache-style protected paths
      pass; a wrong digest, mid-read replacement, or user-owned `0770` ancestor fails.
- [x] Preserve the distinct Apple system-Python evidence lane. Rust launches source snapshot,
      record, verification, coverage, and mutation orchestration through root-owned
      `/usr/bin/python3`; the macOS 15 baseline is Python `3.9.6`. The complete xtask helper/import
      closure and all 83 xtask Python tests now run under that exact interpreter without 3.10-only
      pathlib or evaluated-typing APIs. Native delegated execution remains independently pinned to
      reviewed Python `3.14.6` and cannot fall back to the system runtime.
- [x] Remove recursive xtask execution from the compatibility matrix. The former aggregate vector
      case lost its evidence selector under the matrix runner's intentional child isolation. Rust,
      TypeScript, Python, and Go are now four explicit cases, preserving all language coverage while
      keeping one evidence owner and preventing a nested route from bypassing or mismatching the
      outer `test-compatibility` authority.
- [ ] Bootstrap the pinned macOS CI runner's externally reviewed per-route executable digests,
      draft one owner-private v2 authority per invoked route, and export both authority path and
      independently approved digest. This is an external operator/repository-configuration action;
      the current checkout cannot manufacture approval for its own tool bytes. Until configured,
      hosted xtask command receipts are not launch evidence.
- [ ] Execute at least one complete route from a clean committed checkout under the same external
      authority and configured-interpreter policy used by CI, then independently reopen its raw
      result and receipt. Focused hostile/unit coverage is green, but the shared development
      checkout is dirty and therefore correctly cannot produce this clean-source evidence.
- [x] Generate PRD/README/CI/release command inventories from one manifest to prevent drift.
      `cargo xtask generate` projects the 29-route authority into the complete manifest, a 29-row
      README table, an 18-route implemented CI inventory, and a complete 29-route release inventory;
      focused Rust tests reject byte or count drift across all four artifacts.

### LAUNCH-003 — Freeze v1.0.0, ABI, platform, feature, and installer scope

Dependencies: LAUNCH-002
Executor: Codex plus release owner for public naming
Release blocking: yes

- [x] Select `1.0.0` as WP22 requires and use `1.0.0-dev.1` while the release remains
      unpublished development work. Never ship `0.1.0` bytes under `v1.0.0`.
- [x] Implement one strict version generator/checker for 63 exact workspace/internal-package,
      lock, SDK, plugin, documentation, contract, artifact-filename, qualification-tool, demo, and
      test consumers. Python distribution paths derive PEP 440 `1.0.0.dev1`; release records keep
      SemVer `1.0.0-dev.1`. Exact legacy/beta/fixture domains are separately allowlisted.
- [x] Preserve `cigar-aws-creds 0.39.1-cigar.1` and `cigar-rust-s3 0.37.2-cigar.1`; the version
      authority structurally excludes both patched forks and its legacy scan distinguishes their
      third-party lock data from CIGAR product identity.
- [ ] Freeze Context ABI `cigar.context.v1`, protocol min/max, schemas, errors, operations, and vectors.
- [x] Add the development-only `cigar.development.protocol-baseline.v1` drift sentinel for
      LAUNCH-003/FULL-100. It binds 82 exact authority, generated schema/OpenAPI/Proto/wire, SDK
      mapping, interface-projection, error, fixture, and vector files across nine closed groups by
      path and SHA-256; proves 45-operation,
      70-nominal-payload, 34-error, four-SDK, canonical/replay/conformance parity; and keeps
      `release_claimed=false` and `candidate_frozen=false`. This does not complete the clean
      candidate freeze above.
- [x] Add `COMPAT-SURFACE-001`, a separate fail-closed 27-source semantic projection for this
      native macOS-arm64 development cohort. It verifies all 45 HTTP, gRPC, Rust typed, dashboard,
      and four-SDK operation contracts; the closed CLI/MCP projections; the corrected exact
      eight-field OpenAPI Problem and 34-error catalogs; the single request-log identity; and the
      bounded aggregate 43-family/137-series metric policy. Its report is explicitly source-only,
      non-release-eligible, and not candidate-frozen, so the clean candidate freeze remains open.
- [x] Freeze this execution cohort to native macOS arm64 only. Linux x86_64/aarch64 GNU,
      macOS x86_64/Rosetta, Windows x86_64 MSVC, and OCI remain separate unqualified profiles.
- [x] Add the strict `cigar.development.local.macos-aarch64.v1` projection: 17 selected/planned
      artifacts and five foreign-platform artifacts deferred, with no missing selected producer or
      contract. MCP and the Claude hook are required members of the selected native-runtime
      artifact; the added conformance runner and CIGARBench tool are internal, unqualified harness
      artifacts only. No build, benchmark-efficacy, qualification, publication, or support state
      is implied.
- [x] Compile the current `cigar` and `cigard` development sources with locked dependencies in the
      optimized `aarch64-apple-darwin` profile and verify both outputs are thin native arm64 Mach-O
      executables reporting `1.0.0-dev.1`. This is compile evidence only: the linker-generated
      ad-hoc signatures are not Developer ID signatures, and packaging, qualification,
      notarization, publication, and support remain open.
- [ ] Implement the initial installer scope as an Apple-silicon Homebrew formula/bottle and signed,
      notarized arm64 archive. Intel Homebrew, WinGet, Linux archives, deb/rpm/MSI, and OCI remain
      outside this cohort until separately profiled and fully qualified.
- [ ] Give each installer/formula/manifest an artifact ID, exact filename, contract, producer, signature purpose, install target, and evidence map.
- [x] Define the development-only `macos-homebrew-formula-arm64` tap archive and
      `macos-installer-arm64` Apple-silicon bottle rows with exact filenames, closed contracts,
      producer, signature purpose, install target, and evidence map. Both remain planned with
      `built=false` and `qualified=false`; this does not complete the release installer scope.
- [x] Add a deterministic local Homebrew producer that requires the exact unclaimed native-build
      receipt, emits a Cellar-layout `arm64_sequoia` bottle with parseable `INSTALL_RECEIPT.json`,
      embedded formula and source-bound SPDX, and emits a tap formula bound to the bottle digest.
      Protected-output, contract, Ruby-syntax, Homebrew read-only parsing, deterministic-pair, and
      prepublication-mutation tests pass. Signing, notarization, clean install, upgrade, uninstall,
      publication, support, and release claims remain open.
  - [x] Fail closed before output unless the producer host is exactly Apple-silicon macOS 15.6,
        matching the deterministic `arm64_sequoia` bottle and `INSTALL_RECEIPT.json` identity.
  - [x] Add an independent source-only verifier that securely rereads the native archive, native
        receipt, bottle, tap, and Homebrew receipt; revalidates all three package contracts;
        reconstructs the exact bottle/tap bytes; and rejects digest drift, host substitution, or
        claim escalation. The focused Homebrew producer/verifier suite passes 8/8 tests. Installed
        lifecycle evidence and every external trust/publication gate remain open.
- [ ] Remove unsupported public claims/reachable paths rather than marking them tested.
- [ ] Keep matrix `release_state` as development until every producer/evidence exists.

Checks:

```sh
cargo xtask generate --check
cargo xtask fmt --check
cargo xtask lint
python3 sdk/generate_clients.py --check
python3 scripts/release/validate_metadata.py
```

### LAUNCH-004 — Build merge, nightly, weekly, and RC CI

Dependencies: LAUNCH-002, LAUNCH-003
Executor: Codex; repository administrator for protections
Release blocking: yes

- [x] Implement the bounded development CI slice for this run on native `macos-15` arm64 only.
      Fast CI now asserts the host/toolchain identities, hydrates locked dependencies before the
      offline phase, runs generated-source/vector/docs checks and supported Rust lint
      compositions, and runs the workspace Rust suite with the strict `macos-qualification`
      profile while explicitly excluding `cigar-soak`. Actions and tool versions are pinned,
      checkout credentials are not persisted, permissions are read-only, jobs have timeouts and a
      concurrency lock, and neither fuzz nor soak executes. The workflow configuration passes
      actionlint locally; an authoritative remote run and required-check protection remain open.
- [x] Add a manual macOS arm64 development archive diagnostic with no artifact upload, release
      publication, external secrets, signing, or notarization path. It builds offline with the
      native producer, then independently requires the event SHA/clean source, exact two-file
      owner-only evidence workspace, archive digest and size, contract pass, `built-unqualified`
      status, and false signing/notarization/qualification/publication/support/release claims.
      This workflow is diagnostic only and does not satisfy candidate qualification.
- [x] PR: format, generation, lint, unit, vectors, docs, dependency/static security.
      For the initial Apple-silicon macOS cohort, `fast-ci.yml` runs the source-quality and complete
      non-soak Rust lanes on every pull request, while `security.yml` runs dependency, secret,
      static-analysis, SDK-audit, and source-bound coverage lanes. Actions and tools are pinned and
      checkout credentials are not persisted. An authoritative hosted run and required-check
      protection remain repository-administrator work below.
- [x] Main/merge: native cross-platform unit/integration/compatibility/conformance/matrices.
      The supported cohort is intentionally `macos-15` arm64 only. Pushes to `main` run the same
      strict source/Rust gates plus all nine local matrix suites through separate external
      content-free evidence workspaces: compatibility, integration, end-to-end, security, offline,
      models, chaos, migrations, and installation. Dependencies are hydrated first and execution is
      locked/offline; fuzz and soak are excluded. No Linux/Windows runtime claim is made.
- [x] Nightly: sanitizers, models, adversarial/security, migration, chaos, package smoke.
      The scheduled/manual native lane runs source-bound models, security, migrations, and chaos,
      followed by the non-publishing macOS archive, Homebrew, qualification-tool, and development
      assembly producer/verifier tests. A dedicated `macos-15` Apple-silicon job now installs and
      verifies the exact pinned nightly/LLVM toolchain, executes the LAUNCH-104 production
      sanitizer manifest and runner, independently verifies its source-bound receipt, wraps it in
      the immutable GitHub run/attempt/job envelope, and retains only content-free receipts with a
      validated upload-service digest. Neither fuzz nor soak is scheduled in this bounded cohort.
      Local actionlint and hostile workflow-policy tests pass; an authoritative hosted nightly run
      remains external evidence.
- [ ] Weekly: mutation, cumulative fuzz workers, effect RC faults, scale, performance.
  - [x] Add bounded weekly/manual native macOS lanes for the full non-fuzz mutation route, the exact
        1,000-repetition/24,000-process-kill effect RC campaign, a reduced physical
        backup/recovery diagnostic plus 300-GiB capacity preflight, and diagnostic CIGARBench
        replay/canary/profile checks. Every lane hydrates before its offline phase, emits an exact
        event-SHA/builder-bound content-free receipt, and validates the artifact-service digest.
  - [ ] Execute and retain authoritative hosted results. Cumulative fuzz workers remain explicitly
        deferred for this run, and the 100-GiB physical scale gate remains separately authorized
        installed-candidate work; neither is represented by the bounded diagnostic lanes.
- [ ] RC/manual/tag: immutable source archive, native builds, installed qualification, 24-hour soak, CIGARBench, reproducibility, SBOM, scans, signing, offline verify, approval-gated promotion.
  - [x] Add manual local-authority diagnostics for source-bound security plus reproducibility and
        for the unsigned native archive -> Homebrew bottle/tap -> independent reconstruction
        verifier chain. The workflow uploads only content-free prerequisite receipts and carries
        false signing, notarization, qualification, publication, support, and release claims.
  - [ ] Execute the hosted manual diagnostics and implement the external-trust cohort: installed
        byte qualification, full release CIGARBench, 24-hour soak, candidate SBOM/scans, Developer
        ID signing, notarization, approval environment, offline install verification, and promotion.
- [ ] Pin actions/images, use read-only defaults, per-job elevation, protected environments, OIDC where supported, concurrency locks, timeouts, and artifact digest verification across handoffs.
  - [x] The new nightly, weekly/manual, and RC-diagnostic jobs use `macos-15`, full action commit
        pins, read-only contents, no persisted checkout credentials, no secret inputs, explicit
        timeouts, non-cancelling concurrency, and fail-closed upload digest validation.
  - [ ] Protected environments, OIDC, immutable image provenance beyond the hosted `macos-15`
        label, and repository-level required checks remain administrator/external configuration.
- [ ] Bind receipts to event SHA and immutable builder identity. Fail if a claimed platform/environment is absent.
  - [x] `ci_workflow_receipt.py` publishes create-new outer receipts bound to the clean event
        commit/tree, native Darwin arm64 host, exact GitHub repository/run/attempt/job, command
        digest, and protected external attachment digests; verification reopens and rechecks every
        binding and rejects stale builders, platforms, source, commands, aliases, or claim drift.
  - [ ] Apply equivalent immutable builder/environment bindings to every remaining external release
        receipt and obtain hosted evidence; the diagnostic envelopes are never release eligible.
- [ ] Keep production keys out of repository and ordinary Actions secrets.
  - [x] The bounded native workflows have no secret context, key input, write permission, signing,
        notarization, publication, or promotion command.
- [ ] Configure an authoritative remote, protected default branch, signed-tag policy, required checks, and release triggers for main/tag/manual exact commits. Disable force-push/deletion on protected release refs.

---

## Phase 1 — Candidate-bound WP19 quality and security

### LAUNCH-100 — Repair and run all integrated matrices

Dependencies: LAUNCH-000 through LAUNCH-004
Executor: Codex
Release blocking: yes

- [ ] Create a detached fresh checkout; verify `git fsck`, commit/tree, source archive, clean status, and toolchain pins.
- [ ] Prepare Cargo cache separately, then validate all five matrices:

  ```sh
  python3 tools/quality/run_matrix.py \
    --matrix tests/security/matrix-v1.json --prepare-cargo-cache
  for matrix in \
    tests/security/matrix-v1.json \
    tests/compatibility/matrix-v1.json \
    tests/chaos/matrix-v1.json \
    tests/migration/matrix-v1.json \
    tests/installation/matrix-v1.json
  do
    python3 tools/quality/run_matrix.py --matrix "$matrix" --validate-only
  done
  ```

- [x] Reproduce and fix the stale failures with private logs:

  ```sh
  cargo nextest run --locked -p cigar-cli --lib
  cargo nextest run --locked -p cigar-store --lib
  ```

  The native macOS rerun exposed and fixed the S3 path-style test misuse, removed two accidental
  local ignored tests with deterministic fixtures, and isolated two unchanged resource-sensitive
  acceptance gates from scheduler contention. A later 32-way run passed every test body but
  produced seven arbitrary leaked-handle attributions because Rust 1.92 macOS creates capture pipes
  before applying `CLOEXEC`; focused and bounded stress runs proved that one victim creates no
  process. The new `macos-qualification` profile inherits strict CI leak failure and serializes
  process launches rather than retrying, extending timeouts, or exempting tests. The complete
  non-soak selection then passed 809/809 on native arm64 macOS; 21 separately credentialed or
  destructive external-provider integrations remain explicitly ignored and unqualified.

- [x] Add `SEC-MCP-001` for `cargo nextest run --locked -p cigar-mcp --all-targets`.
      The exact case is now part of the validated 11-case security matrix and passed all 30 active
      MCP unit/process/main tests on native Apple-silicon macOS through the strict serial
      `macos-qualification` profile. Bounded string/safe-integer request IDs, cancellation
      predicate equivalence, silent notifications, recursive non-finite/overflow backend-number
      rejection, parseable errors, and content-free diagnostics remain active; release-profile
      candidate-bound matrix evidence is still open below.
- [x] Run the bounded native Apple-silicon macOS `local` profile across the nine source-tree
      chaos, compatibility, end-to-end, installation, integration, migration, models, offline,
      and security matrices. Fifty-eight of 59 selected cases pass and no test assertion remains
      failing: chaos 6/6, end-to-end 3/3, installation 6/6, integration 7/7, migration 12/12,
      models 1/1, offline 4/4, security 11/11, and compatibility 8/9. `COMPAT-VECTORS-001` is the
      sole blocker because its command-evidence source snapshot correctly requires a fresh clean
      committed checkout while this integration checkout is concurrently modified; the underlying
      Rust, TypeScript, Python, and Go implementations each independently verified 363 canonical
      vectors and 100,000 differential records. These dirty-source local receipts are not
      release-eligible and do not close the clean-candidate release-profile or installed-byte
      tasks. Fuzz, soak, shared-only, and release-only cases were explicitly not run.
- [ ] Run each matrix with `--profile release` into external evidence. Require all selected cases/canary scans pass, no missing environment, `source.clean=true`, `source.committed=true`, and revision equal to `CANDIDATE_SHA`.
- [ ] Run applicable cases on native Linux, macOS, and Windows. Windows must prove catalog link/traversal defenses, token ACLs, and SQLite main/WAL/SHM owner ACL/link checks. macOS must prove OS-enforced replay no-egress.
- [ ] Run direct auth/TLS regressions:

  ```sh
  cargo nextest run --locked -p cigar-api --test transport_conformance
  cargo nextest run --locked -p cigar-daemon --lib
  cargo nextest run --locked -p cigar-store --lib
  ```

Done when security is 10/10 plus MCP on every applicable platform and all compatibility/chaos/migration/installation release cases pass.

### LAUNCH-101 — Complete normative traceability and conformance

Dependencies: LAUNCH-100
Executor: Codex
Release blocking: yes

- [x] Generate stable IDs/source locations for every normative MUST/SHALL, release gate, and security invariant in `prd.md`; prohibit silent omission.
  - Evidence: extraction contract `cigar.prd-requirement-extraction.v1` re-extracts and exact-compares 142 ordered PRD spans (30 uppercase normative occurrences, 62 release-gate spans, and 76 security-invariant spans), including source text, section, line range, SHA-256, classification, deterministic ordinal ID, and complete-surface digest. Focused extractor tests passed 2/2; traceability omission/addition/relocation/tamper tests passed.
- [ ] Expand `conformance/profiles/requirements-v1.json` and `tests/invariants.yaml` so every normative requirement maps to an existing active test and exact evidence.
  - [x] The v2 registry accounts for 142 source spans plus 35 derived conformance requirements; the v2 manifest resolves all 177 through active exact-command mappings and reports mapped fraction 1.0 with inactive count 0.
  - [ ] Replace source-kind aggregate mappings with reviewed requirement-by-requirement behavioral mappings and bind each mapping to a clean-candidate command receipt. The current dirty-tree development run cannot honestly supply those candidate receipts.
- [ ] For each critical invariant require applicable positive contract/vector, negative/adversarial case, property/model, real process/fault case, cross-runtime differential, and installed-byte case.
  - [x] The validator requires positive, negative, and property/model coverage for every critical aggregate invariant and validates explicit process-boundary, cross-runtime, and installed-byte applicability with bounded rationales.
  - [ ] Add candidate-bound installed-byte evidence to every applicable invariant and split aggregate applicability into requirement-specific coverage. The current manifest explicitly records installed-byte non-applicability for source-only evidence and does not waive the package qualification gate.
- [ ] Reject duplicate IDs, nonexistent commands/fixtures, inactive mappings, skips/quarantines, stale evidence, and unmapped normative requirements.
  - [x] Negative tests reject duplicate/renamed IDs, duplicate selectors/producers, unknown fixtures/functions/profiles, exact-command substitution, inactive/skipped/quarantined tests, weakened thresholds, missing evidence files, stale evidence schemas, PRD surface changes, and unmapped source or derived requirements; the traceability suite passed 4/4.
  - [ ] Bind evidence freshness to the immutable clean candidate and its exact command receipt. Schema/vector/self-digest checks are implemented, but a prior-candidate report plus matching source metadata is not yet sufficient proof of a current release candidate.
- [x] Execute all supported profiles against reference and intentionally faulty implementations; every injected fault must be detected by its intended invariant.
  - [x] Native macOS development execution passed all eight supported profiles and all 24 required cases; the conformance behavior suite passed 11/11, including intentionally wrong and skipped adapters for every profile.
  - [x] Add a stable injected-fault registry that identifies the intended invariant for every fault and proves detection by that invariant, rather than only proving that each faulty adapter fails the aggregate run. The source-digest-bound registry covers eight fault modes across 22 profile bindings; the focused native macOS traceability suite passed 6/6, the conformance behavior suite passed 11/11, and the live validator mapped all 177 normative requirements to 21 active tests.
- [ ] Run cross-runtime identity under all supported OS/architectures, locale/timezone changes, input permutations, randomized scheduling/map seeds, and repeated processes.
  - [x] On native Apple-silicon macOS, the independent Rust, TypeScript, Python, and Go verifiers each passed 363 canonical vectors and 100,000 differential records; the canonical source vector check was current.
  - [ ] Add locale/timezone, input-permutation, randomized scheduling/map-seed, and repeated-process receipts for the supported macOS matrix. Other operating systems and architectures are outside the initial macOS-only scope.
    - [x] Add the active `INT-COMPILER-003` macOS matrix case. Its focused native diagnostic passed all six candidate permutations twice across 12 fresh processes, three locale/timezone pairs, and fresh per-process hash state; `INT-COMPILER-001` independently retains eight-way parallel scheduling coverage. The integration matrix validates with seven exact cases.
    - [ ] Execute that case through the release-profile matrix against the eventual clean immutable candidate and retain its source-bound receipt.

Development command note: `cargo xtask test vectors` and `cargo xtask test conformance` reached the command-evidence source-snapshot gate and correctly refused to issue receipts for the concurrently modified checkout. Their underlying native macOS vector, conformance, strict-run, result-verification, and traceability operations passed, but those are recorded only as development validation, not clean-candidate evidence. Fuzz and soak were intentionally excluded from this run.

Pass:

```sh
cargo xtask test vectors
cargo xtask test conformance
```

Required metrics: mapped fraction = 1.0; inactive = 0; required pass fraction = 1.0; skipped = 0; undetected faults = 0.

### LAUNCH-102 — Implement trustworthy full coverage

Dependencies: LAUNCH-101
Executor: Codex
Release blocking: yes

- [x] Make `cargo xtask test coverage --verify` cover all workspace packages/features/targets, branch data, and the independent property workspace using the pinned equivalent of:

  ```sh
  cargo llvm-cov nextest \
    --workspace --all-features --all-targets --branch \
    --lcov --output-path "$CIGAR_EVIDENCE_DIR/coverage/lcov.info"
  ```

- [x] Emit per-package candidate-bound line/branch/function JSON. The native macOS plan inventories every workspace package and target from locked offline Cargo metadata, covers every declared supported feature composition, includes the independent property workspace with production dependency coverage, and permits only the explicitly scoped `cigar-soak` and Windows-only package exclusions for this run.
- [x] Reject empty LCOV, missing branches/packages, malformed/NaN percentages, stale source, or unreviewed exclusions. The validator reconciles per-package JSON and LCOV totals, applies the 80% line/70% branch floor to every included package as well as the aggregate, and requires a clean unchanged source identity before publishing create-new read-only evidence; its focused suite passed 19/19.
- [ ] Add behavior-focused tests, prioritizing auth, isolation, canonicalization, effects, replay, storage, migrations, parsers, package verifier, and release verifier.

The full instrumented run remains open until a clean immutable candidate is available; no line or branch threshold is claimed from the current dirty integration checkout. Done when line >= 80%, branch >= 70%, and no release target is missing.

### LAUNCH-103 — Correct fuzz policy and complete the RC campaign

Dependencies: LAUNCH-100
Executor: Codex plus isolated long-running workers
Release blocking: yes

- [x] Fix `packaging/release-requirements.v1.json`: aggregate `sum(fuzz.total_seconds) >= 604800` is 14x too weak. Require exactly 14 targets and >= 604,800 clean CPU-seconds per target; aggregate >= 8,467,200.
- [x] Implement a crash-safe cumulative ledger keyed by candidate, target, binary/toolchain/sanitizer, target source, campaign policy, corpus lineage, and worker.
- [x] Reject overlapping time, duplicate receipt IDs, untrusted workers, clock reversal, mixed candidates, missing targets, and accumulation after a target crash.
- [x] Give each worker a private mutable corpus; periodically minimize into deterministic reviewed corpus. Never share writable corpus.
      `tools/quality/fuzz_accumulation.py` now verifies signed worker bundles, publishes immutable
      create-new hash-chained entries with fsync and bounded interrupted-append recovery, and
      reconciles exact per-target/aggregate metrics. It binds candidate/tree, target source,
      binary, toolchain, ASan policy, campaign, private corpus before/after lineage, worker and
      interval; a defect resets that target. The existing external-copy `corpus_manager.py`
      remains the reviewed deterministic minimizer. This implements accumulation only and did not
      execute any fuzzer in the current cohort.
- [x] Harden ledger filesystem authority with no-follow directory descriptors pinned across every
      root/entries/lock lookup and mutation. Every absolute ancestor, the owner-private root and
      entries directory, the empty single-link lock, immutable entries, and pending recovery files
      are opened no-follow relative to pinned parent descriptors and checked for exact case/Unicode
      name, owner, mode, type, link count, device, inode, size, and stable metadata. The same
      descriptor chain and flock remain held through reads, create-new link/unlink publication,
      recovery, revalidation, and fsync; every checkpoint independently rewalks the absolute chain
      and rejects rebound parents, roots, entries, locks, or files. Fifteen focused native-macOS
      tests pass, including deterministic parent/root/entries/lock/entry/pending swaps, aliases,
      symlinks, FIFO/device nodes, hard links, unsafe modes, create-new refusal, durable publication,
      and bounded crash recovery. No fuzzer or soak workload was executed to close this item.
- [ ] Run all 14 campaign targets with ASan/libFuzzer to threshold under bounded memory/time/output.
- [ ] On defect: minimize/preserve, reproduce, fix, add named regression, create new candidate, reset affected target accumulation, rerun invalidated gates.
- [x] Verify all historical crashes, including MCP ID/backend-number input, on applicable platforms.
      `fuzz/historical-crashes.v1.json` is a canonical, source-bound, closed-world inventory of
      the two preserved MCP regressions (non-finite backend number and out-of-range numeric ID),
      including immutable fixture bytes/digests and exact nextest selectors. The fail-closed
      verifier rejects missing, extra, tampered, duplicate, unmapped, aliased, or unsafe fixtures,
      weakened commands/selectors, and stale source bindings. Its 13-file source closure includes
      the workspace/toolchain resolution inputs and every compiled MCP module used by the exact
      selectors. Native Apple-silicon macOS replay passed 2/2; the 8/8 hostile suite and selected
      `SEC-MCP-002` diagnostic passed. The current manifest and ordered source-binding
      SHA-256 values are `043c2b25e98b14741a146a47198eab875aecf38c5d9814f1a9703bc9b43dd6f5`
      and `0a7151aa28489aa38e6b09acda486a9e08356ef6519af2342a2dad9389104026`.
      A clean-candidate receipt remains intentionally open.
      `effect_journal_recovery/crash-seed` remains explicitly classified as a hand-authored seed,
      not a historical crash. No fuzzing, soak testing, or mutation campaign was run for this item.
- [x] Add verifier negatives for aggregate-only evidence, under-time/missing target, stale binary, corrupt lineage, duplicate time, and crash followed by accumulation.
      Focused policy/ledger tests cover all listed failures plus duplicate/replayed receipts,
      canonical-content re-ID replay, untrusted workers, worker overlap, mixed candidates, clock
      reversal, broken hash chains, malformed signatures, post-defect entries, and immutable
      create-new recovery. The 14-target campaign remains open and unevidenced.

Done when each target independently has >= 604,800 clean CPU-seconds and unresolved crash/hang/OOM/sanitizer defects = 0.

### LAUNCH-104 — Complete sanitizers, properties, and concurrency models

Dependencies: LAUNCH-100
Executor: Codex plus supported Linux/nightly workers
Release blocking: yes

- [ ] ASan all 14 fuzz targets and applicable integration suites.
      The prior v1 native Apple-silicon diagnostic reported four ASan cases covering SQLite
      service CAS, SQLite effect recovery, the complete tree-sitter language matrix, and catalog
      SQLite invalidation, but its receipt is intentionally stale after the v2 verifier began
      requiring structured proof that each exact selector executed once. Matching LLVM 22.1.8
      Rust and C instrumentation is mandatory, and a fresh v2 run remains pending. The 14
      fuzz targets were deliberately neither built nor run in this cohort, so this aggregate box
      remains open and no fuzz qualification is claimed.
- [ ] TSan production concurrency paths: cache publication, snapshots, context revisions, outbox/fencing, subscription cursor, invalidation queue, shutdown, effects, store, shared coordination.
      The prior v1 run targeted six native Apple-silicon TSan cases for the production-linked direct-race and
      remaining-surface matrices, two-worker effect claiming, concurrent durable permit entry,
      daemon provider-state CAS, and retrieval generation publication. All run with the pinned
      `nightly-2026-07-13` Rust 1.99.0 toolchain, LLVM 22.1.8 instrumented standard library, one
      test thread, halt-on-first-error, no retries, and no exclusions. The fail-closed manifest,
      runner, negative tests, source/toolchain binding, and external mode-0600 receipt are under
      `tools/quality/production-sanitizers.macos-aarch64.v1.json` and
      `tools/quality/production_sanitizers.py`. Independent audit found that v1 accepted a zero-test
      exact selector because Cargo exits successfully when every test is filtered. Receipt v2 now
      requires exact JSON harness events, one selected and passed test, no sanitizer diagnostic,
      exact source/config/argv/environment authority, and binary/runtime digests. The old receipt at
      `/private/tmp/cigar-production-sanitizer-evidence-20260714-final/receipt.json` (18,665 bytes,
      SHA-256 `6d63188caaa1cc046b3e73793ac958ff0302d54905603c67ec2fac390383ded8`)
      is rejected as stale and is not current qualification evidence.
      The stale receipt recorded source inventory 433 and tree SHA-256
      `c8edc218b68e786a412eb9b2dad99f5e4167a8793fd65c84a02e6de451716b19`.
      It remains a dirty-checkout development diagnostic with
      `release_eligible=false`; it is not clean-candidate release evidence.
- [ ] Strict Miri on unsafe/sensitive portable code. Run UBSan or a documented supported equivalent for FFI/native undefined behavior; never claim an unexecuted sanitizer.
      Native `aarch64-apple-darwin` strict Miri now passes the focused canonical/identity memory
      model 1/1 with `zmij` 1.0.23, offline locked dependencies, strict provenance, and symbolic
      alignment checks. It uses the native ABI without target-feature changes or warnings. Rust's
      macOS sanitizer interface does not support `-Zsanitizer=undefined`; the compiler capability
      probe is retained and no Rust UBSan execution is claimed. The documented supported
      equivalent reviews the workspace-wide `unsafe_code = "forbid"` policy, finds no first-party
      macOS unsafe/FFI source, records the Windows-only FFI exclusion, locks the target-filtered
      native dependency inventory, and executes the four native-C integration paths under ASan
      using Homebrew clang 22.1.8 matched to rustc's LLVM 22.1.8. Details and the exact Miri command
      are in `tests/miri/README.md`; the Miri result remains valid, but the combined item stays open
      until the native review and four ASan paths are bound into a fresh v2 sanitizer receipt.
- [x] Keep seven semantic property families at substantial generated counts with seeds/shrinks.
      The native Apple-silicon macOS gate passes all seven families at 512 cases each with fixed
      seed `0x00c16a1900070512`, a 16,384-iteration shrink bound, and direct checked-in regression
      persistence. The same bounded run passed 15/15 tests, including all seven Loom models; this
      is local diagnostic evidence and does not substitute for clean-candidate release evidence.
- [x] Prove each of the seven existing Loom models refines/represents its production state machine; record schedules, bounds, branches, and configuration.
      The native Apple-silicon macOS models now execute the production compiler cache, MVCC store,
      context-space publication, durable worker fencing, event pages/cursor kernel, dependency
      invalidator, and daemon admission gate. The strict machine-readable
      `tests/properties/model-refinement-v1.json` binds production source/symbol anchors and records
      Loom 0.7.2, three threads, 1,000 maximum branches, preemption bounds two/four, no duration or
      permutation truncation, 132 exact schedules, 14 named branches, and seven divergence
      mutants. This is development diagnostic evidence, not clean-candidate release evidence.
- [x] Add production-linked Shuttle/Loom/model coverage where an abstract standalone model could diverge from real synchronization.
      All seven models use production types or the shared production `EventCursor::advance_to`
      kernel. Send/Sync store and space operations run without model-side serialization; a separate
      barrier-synchronized guard overlaps the real locks for 64 snapshot/worker rounds and 16
      context-publication rounds. Source/config binding and one rejected divergent trace per model
      raise the model suite to 10/10; the complete locked property workspace passes 18/18 on native
      Apple-silicon macOS. The six-case TSan gate and reviewed native UB-equivalent require a fresh
      v2 receipt after verifier hardening; clean-candidate execution remains open in its own task.
- [x] Run stable and pinned nightly without lint allowance drift.
      The native Apple-silicon macOS workspace passes `cargo +1.92.0 fmt --all -- --check`
      and the locked/offline `--workspace --exclude cigar-soak --lib --bins --tests` test and
      strict Clippy (`-D warnings`) surfaces under both stable Rust 1.92.0
      (`ded5c06cf21d2b93bffd5d884aa6e96934ee4234`, LLVM 21.1.3) and pinned
      `nightly-2026-07-13` Rust 1.99.0-nightly
      (`77cf889bc178ddb44d6a1c78e5a820b5abb31d8d`, LLVM 22.1.8). No lint allowance,
      warning cap, retry, fuzz target, or soak test was added or executed for this gate.

Required metrics: sanitizer defects = 0; model defects = 0.

### LAUNCH-105 — Run full RC mutation analysis

Dependencies: LAUNCH-102
Executor: Codex plus bounded workers
Release blocking: yes

- [ ] Resolve the policy mismatch between representative 90% and release 70%; select one reviewed RC threshold. Critical auth/isolation/effect/canonical/integrity code always requires zero viable survivors.
      The verifier policy now consistently selects the stricter 90% floor and additionally
      requires >= 14,400 seconds, every production package, zero timeouts, and zero critical viable
      survivors. Metadata validation and verifier unit tests pass, but human review and the actual
      RC campaign remain outstanding; no mutation result is claimed here.
- [x] Implement `cargo xtask test mutations --verify` across production Rust with exact generated/vendor/test exclusions and no package omission.
      The native macOS-arm64 command now selects all 24 production packages and the exact reviewed
      source exclusions, explicitly accounts for all five non-production/foreign workspace
      packages, pins cargo-mutants 27.1.0 plus the workspace Rust/nextest tools, runs locked/offline
      under a Darwin deny-network sandbox, and publishes create-new source-bound evidence. Its
      independent verifier reopens raw outcomes and recomputes the baseline, exact mutant/source
      scope, counts, viable denominator, score, raw/observed duration, timeout count, and critical
      survivors. Build scripts remain in scope. The zero-survivor set includes the complete
      canonical, catalog isolation/secret, compiler identity/delta, cryptographic, effect, policy,
      protocol identity, replay integrity, retrieval partition/integrity, space publication/isolation,
      and store packages plus API/daemon auth/effect and extension-host boundaries. No mutation
      campaign was executed in this implementation pass. An independent real cargo-mutants 27.1.0
      `--list-files --json` command passed locked/offline for all 24 governed production packages,
      enumerating 244 source files and 22,751 JSON bytes with no stderr; this was scope inventory,
      not a mutation campaign.
- [ ] Run a clean baseline and >= 4-hour campaign with bounded jobs/timeouts; record mutation list, classification, command/tool digest, and durations.
- [ ] Investigate every survivor/timeout; add behavioral tests or fix coupling. Never blacklist a viable mutant merely to improve score.
- [x] Reject representative-only scope, under-duration, missing package, timeout, critical survivor, malformed denominator, or stale source.
      Negative tests additionally reject duplicate or omitted mutants, source inventory escape,
      malformed phase/summary arithmetic, stale tool versions, duplicate/partial release receipts,
      unreviewed environment controls, command/sandbox substitution, and unexpected metrics.

Done when duration/scope/threshold pass, timeouts = 0, and critical viable survivors = 0.

### LAUNCH-106 — Finish effects, chaos, migrations, shared services, scale, and soak

Dependencies: LAUNCH-100, LAUNCH-104
Executor: Codex plus production-like service/native environments
Release blocking: yes

- [ ] Run the existing effect RC campaign:

  ```sh
  CIGAR_EFFECT_RC_REPETITIONS=1000 \
    cargo nextest run --locked -p cigar-effects --test wp12_faults
  ```

  Require EFX-C01..C24, 24,000 true-process-kill cases, and >= 100,000 possible-remote-commit logical operations.

  - [x] Complete the bounded current-tree native Apple-silicon macOS diagnostic. The exact
        `CIGAR_EFFECT_RC_REPETITIONS=1000 cargo nextest run --locked -p cigar-effects --test
        wp12_faults` command passed 6/6 in 576.089 seconds with zero skips: EFX-C01 through C24
        each ran 1,000 fresh checkpoint/process-kill/reopen/recovery cases (24,000 total), and the
        independent logical campaign verified 100,000 possible-remote-commit operations with zero
        duplicate logical effects and zero blind redispatches. A test-specific two-period 15-minute
        Nextest ceiling now makes the documented RC command executable while retaining a hard
        30-minute bound and discarded child output. This run overlapped unrelated source-tree work,
        so the aggregate release box stays unchecked pending the immutable candidate rerun.

- [ ] Prove durable intent/authorization before dispatch, stable idempotency, no duplicate logical effect, correct UNKNOWN/reconciliation, and compensation as a new linked effect.
- [ ] Close HTTP effect controls: destination allowlist, DNS/private-IP/rebinding, redirect/proxy, TLS identity, auth/response authenticity, deadlines/cancellation, bounded body, idempotency, ambiguous success.
- [ ] Close filesystem effect confinement with descriptor/handle-relative traversal and ancestor-swap resistance; test symlink/mount/rename/case/Unicode races and deployment ownership.
- [ ] Run all release chaos cases for SQLite, daemon, extension, object/blob, PostgreSQL, shared service, effects, and credentials. Run doctor, roots/hash chains, rebuild, and reconciliation after faults.
      The bounded local Apple-silicon macOS chaos profile passes its six applicable cases for blob,
      daemon, effects, extension host, and SQLite. PostgreSQL, shared-service, credential, and full
      release-profile coverage remain open, and the local dirty-source receipt is not release
      evidence.
- [ ] Re-run `tools/qualify-shared-profile.sh` and `tools/wp18-failover/qualify.sh`, then qualify managed private-CA PostgreSQL, external S3-compatible storage, and production CSI/RWX/POSIX locking. Emulators are not final evidence.
- [ ] Exercise OIDC/JWKS rotation/revocation, CA chains, mTLS identity, separate runtime/migrator credentials, and no plaintext/downgrade.
- [ ] Run every retained adjacent migration, interrupt every failpoint, restart, verify semantic roots/replay, and require journal RPO 0.
- [ ] Scale local through 1M atoms/10M edges/100GB referenced blobs and shared through 10M atoms.
      Shared PostgreSQL has physically reached 10,000,000 production projection rows, but its
      receipt must be regenerated after the final lock change. Local schema v4 now makes normalized
      revision-visible atoms/edges authoritative, retains only catalog-free residual revisions,
      performs indexed reads and incremental catalog writes, streams projection/integrity work, and
      binds an explicit immutable `large_local` profile. That native macOS-arm64 profile is bounded
      at 64 GiB database, 1.25M atoms, 12.5M edges, 128 GiB referenced blobs, 300 GiB initial free
      space, and a 16 GiB runtime reserve. The source-bound fixture model is now a 4,668,000,000-byte
      normalized-record lower bound and no longer reports the obsolete whole-state blocker. The
      physical gate was not run during implementation/audit: exactly 1,600 distinct 64 MiB encrypted
      objects are required for 100 GiB, and the installed-artifact run plus integrity and verified
      backup/restore still needs an immutable candidate and a private qualifying volume with at
      least 300 GiB initially free. Do not mark this item complete from preflight or modeled evidence.
      - [x] Implement the native Apple-silicon physical driver with an immutable exact profile,
        bounded atom/edge/blob publication, atomic root-bound recovery checkpoints, exact
        candidate/tool/source/profile binding, create-new private evidence, catalog/root/blob
        integrity, one-over-quota rejection, close/reopen, signed backup verification, restored
        semantic-root equality, and owned-only scratch cleanup.
      - [x] Exercise the driver with scaled physical fixtures and hostile post-binding mutation,
        interruption/resume, insufficient-space, symlink, hardlink, FIFO, device, alias, unexpected
        entry, and unowned-cleanup cases. Independent audit additionally proves a failed initial
        capacity check cannot create a marker and downgrade a retry to the 16-GiB resume floor,
        measures the selected scratch volume rather than the repository volume, binds a 100-file
        transitive source closure, and revalidates the exact SQLite runtime profile on initial,
        reopened, and restored stores. Driver tests pass 5/5, preflight tests 10/10, and native
        packaging tests 7/7. Fuzz and soak are intentionally excluded from this run.
      - [ ] Run the immutable installed release driver on the reviewed native host and retain a
        schema-valid `cigar.local-scale-result.v1` receipt proving 1,000,000 atoms, 10,000,000
        edges, 1,600 distinct 64-MiB encrypted objects, and verified backup/restore. This remains
        open pending the clean installed artifact, dedicated capacity, and full physical execution.
- [ ] Run installed daemon >= 86,400 seconds over 1..64 sessions with ingestion, compile/delta, spaces/handoff/events, effects/reconciliation, replay, backup, GC, and bounded dependency faults.
- [ ] Require no memory/FD/task trend, deadlock, lost commit, stuck lease, unbounded queue, unexplained UNKNOWN, unauthorized output, or reference digest drift.

Required: effect operations >= 100,000; soak/daemon soak >= 86,400 seconds; invariant/migration/scale failures = 0; max atoms >= 10,000,000.

### LAUNCH-107 — Close static, dependency, secret, and source security gates

Dependencies: LAUNCH-100
Executor: Codex
Release blocking: yes

- [x] Add only exact-rule, same-line Semgrep suppressions with adjacent rationale for:
  - `python.lang.security.audit.insecure-file-permissions.insecure-file-permissions` at `demos/claude-code/driver.py:34` (0700 executable);
  - the same rule at `demos/driver_support.py:359` (0700 private request directory);
  - the same rule at `scripts/release/qualify_install.py:265` (restore non-secret temp dir to 0755);
  - the same rule at `tools/quality/run_matrix.py:377` (0700 private log directory);
  - `go.grpc.security.grpc-server-insecure-connection.grpc-server-insecure-connection` at `demos/sdk-clients/go-workflow/main.go:337` (in-memory `bufconn`, custom dialer, no network listener).
- [x] Do not ignore whole paths or disable rules globally. Add tests preserving each suppressed security property.
      The one generated-notice exception is scoped to one rule and an exact size/SHA-256-bound
      upstream Rust legal file; every other rule still scans that file.
- [x] Pin/vendor the Semgrep ruleset and record its digest; `--config auto` alone is mutable. The
      hydration tool pins Semgrep 1.168.0, the 2,423,467-byte upstream ruleset digest, and the
      2,423,543-byte effective digest, rejects redirects or drift, and scans without registry
      access or metrics.
- [ ] Produce revision-bound reports:

  - [x] Run the complete supported-feature diagnostic on the combined native macOS working tree:
        the strict locked workspace profile plus all 16 mutually compatible feature profiles passed
        (17/17). Direct current-database diagnostics also passed `cargo audit`, `cargo deny`, the
        isolated audit-only pnpm 11.13.0 production-lock projection, pip-audit, and both Go
        vulnerability scans. The pnpm wrapper leaves the build contract pinned to 10.34.5, binds
        the complete Corepack distribution plus the exact signed official Darwin-arm64 Node
        executable, stages both into a private read-only runtime, installs no dependencies, and
        returned zero advisories at every severity for the one production dependency; its
        dirty-tree receipt remains
        diagnostic until rerun against the immutable candidate. Pinned Semgrep 1.168.0 scanned 12,992 targets
        with 603 effective rules and zero findings; Trivy 0.69.2 reported zero dependency findings
        but correctly labeled its receipt `diagnostic_dirty_source`. A later vulnerability-database
        refresh exposed ten HIGH findings in the unused
        `vendor/aws-creds-0.39.1/Cargo.lock`; that generated lock was not a workspace or SBOM input
        and was removed rather than waived. The fail-closed policy now proves its absence, the exact
        17-artifact macOS contract reachability, the reviewed source builder, locked offline Cargo
        resolution, and the real 659-component SBOM input union. A fresh Trivy 0.69.2 scan against
        the 2026-07-14 database reports zero findings across 36 detected dependency targets and
        remains `diagnostic_dirty_source`. These results do not close the unchecked parent:
        clean-commit, revision-bound external receipts still must be regenerated.

  ```sh
  # Runs the locked, strict 17-profile matrix of supported feature compositions.
  # `--all-features` is intentionally invalid because Cargo feature unification would combine
  # mutually exclusive CLI modes and synchronous/Tokio S3 backends.
  CIGAR_EVIDENCE_DIR="$CIGAR_EVIDENCE_DIR" cargo xtask lint
  cargo audit --deny warnings
  cargo deny check
  export CIGAR_AUDIT_NODE=/private/tmp/node-v24.10.0-darwin-arm64/bin/node
  export COREPACK_HOME="$CIGAR_EVIDENCE_DIR/security/pnpm-corepack"
  test ! -e "$COREPACK_HOME"
  mkdir -m 700 "$COREPACK_HOME"
  corepack prepare pnpm@11.13.0 --activate
  python3 tools/quality/pnpm_audit.py scan \
    --node "$CIGAR_AUDIT_NODE" \
    --pnpm-root "$COREPACK_HOME/v1/pnpm/11.13.0" \
    --receipt "$CIGAR_EVIDENCE_DIR/security/pnpm-audit.receipt.json"
  python3 tools/quality/pnpm_audit.py verify-receipt \
    --node "$CIGAR_AUDIT_NODE" \
    --pnpm-root "$COREPACK_HOME/v1/pnpm/11.13.0" \
    --receipt "$CIGAR_EVIDENCE_DIR/security/pnpm-audit.receipt.json"
  uv export --project sdk/python --no-dev --format requirements-txt \
    --no-emit-project --no-hashes | uvx --from pip-audit==2.10.1 \
    pip-audit --strict --no-deps -r /dev/stdin
  (cd sdk/go && govulncheck ./...)
  python tools/quality/semgrep_policy.py hydrate \
    --output "$CIGAR_EVIDENCE_DIR/security/semgrep-rules.yml"
  python tools/quality/semgrep_policy.py scan \
    --ruleset "$CIGAR_EVIDENCE_DIR/security/semgrep-rules.yml" \
    --report "$CIGAR_EVIDENCE_DIR/security/semgrep-$CANDIDATE_SHA.json" \
    --receipt "$CIGAR_EVIDENCE_DIR/security/semgrep-$CANDIDATE_SHA.receipt.json"
  ```

- [ ] Run gitleaks 8.30.1 with redacted output and actionlint 1.7.12. Record scanner/ruleset/advisory-DB digests and distinguish scanner failure from clean result.
  - [x] Run the pinned current-tree diagnostic: gitleaks 8.30.1 scanned 68.61 MB with full redaction
        and found no leaks (the configured 2 MB ceiling excluded the 3 MB LCOV report), while
        actionlint 1.7.12 accepted every workflow. Candidate-bound scanner/ruleset receipts and the
        authoritative hosted run remain open, so the parent task stays unchecked.
- [ ] Allow an advisory exception only when exact package/advisory scoped, proven non-reachable or mitigated by executable test, approved, and expiring before next release.

Done when secrets = 0, Semgrep unsuppressed = 0, scanners succeed, and unmitigated critical/high dependencies = 0.

### LAUNCH-108 — Deep-scan the candidate and close deferred surfaces

Dependencies: LAUNCH-100, LAUNCH-106, LAUNCH-107
Executor: Codex security workflow plus human reviewer
Release blocking: yes

- [ ] Run a multi-pass deep repository security scan on the exact clean candidate. Persist sanitized report, findings JSON, SARIF, coverage, threat model, fix ledger, and deferred inventory bound to `CANDIDATE_SHA`.
- [ ] Run a security diff scan after any later patch and revalidate affected attack paths.
- [ ] Implement/qualify or structurally disable with reviewed `not_applicable` evidence:
  1. production HTTP effect transport;
  2. filesystem ancestor swap/deployment ownership;
  3. broker ambiguous success/idempotency/UNKNOWN;
  4. protected-data handle scope/read-time revocation;
  5. retained/subprocess executable replacement lifecycle;
  6. remote gRPC DNS/TLS/mTLS/channel identity;
  7. broker/callback deadlines/cancellation;
  8. delegated-capability ancestor revocation/tenant binding;
  9. live replay provider/effect gate;
  10. Rust/TypeScript protocol-minor security intersection;
  11. remaining storage/secret lifecycle proof;
  12. remaining production transport proof.
- [ ] Keep live replay structurally disabled unless provider/effect gates are reviewed. Recorded replay must prove zero network/model/tool/connector/effect egress.
- [ ] Commit a sanitized maintained threat model linking trust boundaries to tests and operational controls.

Stop on any critical/high, unresolved medium crossing auth/tenant/effects/secrets/storage integrity/code execution, reachable deferred surface, or claimed-surface coverage below 100%.

---

## Phase 2 — Candidate-bound WP20 efficacy, performance, demos, and SDKs

### LAUNCH-200 — Build a qualifying CIGARBench corpus and evaluator lane

Dependencies: all LAUNCH-1xx tasks
Executor: Codex for tooling; independent data/evaluator owners for adjudication and key custody
Release blocking: yes

- [ ] Replace one-task-per-stratum dry run with >= 30 distinct independently adjudicated tasks in each of 9 strata: >= 270 independent identities.
- [ ] Define provenance, licensing/privacy review, immutable task/ground-truth digests, contamination/redaction controls, and train/test separation.
- [ ] Implement and run seven real baselines and five real ablations; recorded fixture consumers do not qualify algorithms.
- [ ] Build an installed candidate consumer and pin its artifact digest in the plan.
- [ ] Keep assignment seed and evaluator private key outside the repository, public artifacts, workers, and implementer custody.
- [ ] Run paired randomized execution with >= 30 post-warm pairs per stratum and 10,000 task-clustered bootstrap resamples.
- [ ] Run documented `plan`, `execute`, `attest`, `compare --bootstrap-repetitions 10000 --require-qualification`, `replay`, `canary-scan`, and `guard-profile` under enforced no-egress.
- [ ] Require report reproduction from raw events, matching plan/profile digests, no hidden-seed leak, no benchmark-only production configuration, and valid independent evaluator signature.

Outcome gates:

| Metric | Gate |
|---|---:|
| Median / p25 physical reduction | >= 40% / >= 25% |
| Cost improvement | >= 10% |
| Task-success regression | <= 2 percentage points |
| Critical recall / context precision | >= 99% / >= 90% |
| Context harm / unauthorized context | <= 1% / 0 |
| Strong-baseline gate | passed |
| Required strata | 9/9 passed |
| Bootstrap confidence | >= 95% |

Done when `reports/cigarbench/report.json` is eligible/passed and all strata have real independent task clusters, intervals, and evaluator attestation.

### LAUNCH-201 — Qualify installed-daemon performance and scale

Dependencies: LAUNCH-200 and preliminary native artifacts from LAUNCH-301
Executor: Codex plus dedicated pinned hosts
Release blocking: yes

- [ ] Run exact installed `cigard`/`cigar` bytes on pinned hosts with immutable kernel/CPU/memory/storage/power/network configuration.
- [ ] Collect >= 30 calibration and post-warm samples per case; require host coefficient of variation < 5%.
- [ ] Use `benches/cigarbench/PERFORMANCE.md` environment, attest, validate, 10,000-bootstrap compare, and replay flows.
- [ ] Exercise every operation/profile/load axis, 1..64 sessions, local 1K..1M scale, and shared through 10M atoms.
- [ ] Compare with frozen strong baseline; faster with changed digest, lower recall, weaker durability, or leakage is failure.

| Metric | Gate |
|---|---:|
| Warm-cache compile p95 | <= 15 ms |
| Delta compile p95 | <= 50 ms |
| Full compile p50 / p95 / p99 | <= 75 / 250 / 750 ms |
| Claude hook p95 / p99 | <= 150 / 1,000 ms |
| MCP summary p95 | <= 250 ms |
| Daemon ready p95 | <= 2,000 ms |
| Journal prepare p95 | <= 25 ms |
| Local / shared event p95 | <= 100 / 1,000 ms |
| Incremental reindex p95 | <= 500 ms |
| Ingestion | >= 250 atoms/s |
| Local sessions | >= 32 |
| Local scale | >= 1M atoms, 10M edges, 100GB referenced blobs |
| Shared scale | >= 10M atoms |
| Idle RSS | <= 300 MiB |
| Budget materializations/compliance | >= 1M / >= 99.99% |
| Significant p95 regression | <= 10% |
| Throughput / RSS regression | <= 15% / <= 15% |

Done when candidate/comparison reports pass, raw replay is exact, and all absolute/relative gates pass.

### LAUNCH-202 — Requalify demos and SDK workflows from distributions

Dependencies: LAUNCH-200, LAUNCH-301 through LAUNCH-304
Executor: Codex plus native install workers
Release blocking: yes

- [ ] Install exact packages into empty unprivileged environments with empty ecosystem caches and enforced no-egress.
- [ ] Run all seven demos and four Rust/TypeScript/Python/Go quickstarts through installed public APIs, never workspace paths or stubs.
- [ ] Execute twice and require byte-identical deterministic identities/records where specified.
- [ ] Verify daemon unavailable, unauthorized scope, prompt injection, malformed MCP, effect crash/UNKNOWN, corrupt replay, partial plugin install, and clean uninstall paths.
- [ ] Bind each receipt to every consumed package/archive/plugin/daemon digest.

Required: demo failures = 0; complete installed SDK/platform coverage; no canary or unauthorized leak.

---

## Phase 3 — WP21 build, packaging, and installed-byte qualification

### LAUNCH-300 — Implement the complete deterministic release build plane

Dependencies: LAUNCH-003
Executor: Codex
Release blocking: yes

- [x] Add development-only deterministic producer tooling for every one of the 17 rows selected by
      the macOS profile: six source-derived archives; the native Apple-silicon
      CLI/daemon/MCP/hook archive; Apple-silicon Homebrew tap/bottle pair; npm, Rust, Python
      sdist/wheel, and Go SDK artifacts; the Claude plugin; and internal macOS conformance and
      CIGARBench harnesses. The focused producer suite passes 70/70 tests. These tools emit
      contract-verified `built-unqualified` bytes and do not satisfy
      candidate build, signing, installed qualification, publication, or support gates. The Rust
      producer validates its complete 19-crate unpublished dependency chain through a private
      local registry but publishes only the matrix-selected canonical SDK crate.
- [ ] Add deterministic producers for the five matrix rows intentionally deferred from this run:
      four foreign native platform archives and the multi-architecture OCI layout. Promote every
      selected development producer into the clean-candidate build plane without rebuilding bytes
      downstream.
- [ ] Add producers/contracts for every installer frozen in LAUNCH-003.
- [ ] Assemble `release-build.json` requiring every release artifact ID exactly once, with relative path, SHA-256, bytes, contract/digest, version, ABI, platform, candidate SHA/tree, source archive, and `SOURCE_DATE_EPOCH`.
  - [x] Implement the bounded development-only Apple-silicon assembler for all 17 artifacts selected
        by `cigar.development.local.macos-aarch64.v1`. It consumes ten distinct protected producer
        workspaces, validates their exact canonical receipts, current authority/contract digests,
        source/version/ABI/target/host bindings, and Homebrew-native linkage, then creates an
        owner-only `release-build.json` using `cigar.local-archive-build.v1`. This does not complete
        the clean-candidate, foreign-platform, signing, installed qualification, or release manifest
        gate.
- [ ] Write canonical `SHA256SUMS` permitting exactly build-manifest artifacts and rejecting aliases/collisions/unreferenced files.
  - [x] Emit artifact-only canonical checksums after validation and add an independent reconstruction
        verifier. The focused adversarial suite passes 8/8 for exact-set determinism, missing/extra/
        colliding inputs, stale or overclaiming receipts, workspace alias/traversal, symlink/hardlink/
        FIFO inputs, in-flight replacement, post-manifest mutation, and unreferenced output. Final
        candidate checksums and signatures remain open.
        A combined 34-test dependency run completed 32 tests successfully; two Homebrew verifier
        fixtures stopped at their intentional immutable-source guard while other agents changed the
        shared checkout. Those two cases are recorded as aborted, not passed, and require rerun after
        source edits quiesce.
- [ ] Build from verified source archive with `CIGAR_SOURCE_REVISION`, locked dependencies, `CARGO_INCREMENTAL=0`, path remapping, deterministic archive/linker settings, and empty isolated homes.
- [ ] Test missing/duplicate ID, filename/case collision, stale revision, post-manifest mutation, symlink/hardlink/device/traversal, entry/size bomb, contract substitution, developer path, secret marker, unexpected executable, and unreferenced output.

Interfaces to implement:

```sh
python3 scripts/release/build_binary_archive.py --target "$TARGET" --out "$DIST"
python3 scripts/release/build_sdk_packages.py --out "$DIST"
python3 scripts/release/build_plugin_archive.py --out "$DIST"
python3 scripts/release/build_oci.py --out "$DIST"
python3 scripts/release/assemble_build_manifest.py \
  --dist "$DIST" --out "$DIST/release-build.json"
python3 scripts/release/write_checksums.py \
  --build-manifest "$DIST/release-build.json" --out "$DIST/SHA256SUMS"
```

Done when every matrix row has a tested producer and manifest set equals required set exactly.

### LAUNCH-301 — Build all exact candidate artifacts on native isolated builders

Dependencies: LAUNCH-300 and a new clean final candidate
Executor: isolated native build workers
Release blocking: yes

- [ ] Freeze `CANDIDATE_SHA`; derive `SOURCE_DATE_EPOCH` from commit time.
- [ ] Build six source-derived archives:

  ```sh
  python3 scripts/release/build_archives.py \
    --out "$DIST" \
    --source-date-epoch "$SOURCE_DATE_EPOCH" \
    --require-committed-clean
  ```

- [ ] Build native archives on x86_64/aarch64 Linux GNU, x86_64/arm64 macOS, and x86_64 Windows MSVC.
- [ ] Use two independent empty-cache builders per target. Record image/VM, compiler/linker/system pins, command, environment allowlist, network mode, source/archive and unsigned payload digests.
- [ ] Package only allowlisted binaries, metadata, licenses/notices, man pages, completions, and checksums at contract paths/modes.
- [ ] Build SDK, plugin, installer, and OCI artifacts from the same source archive/version manifest; verify every contract before install/sign/publish.

Required base set, with filenames updated to frozen version:

1. source, docs, schemas, conformance, benchmark-fixture, and license archives;
2. five native CLI/daemon archives;
3. npm package and Rust SDK crate/package set;
4. Python sdist and wheel;
5. Go module;
6. Claude Code plugin;
7. Linux amd64/arm64 OCI index;
8. all claimed installer/formula/manifest artifacts.

### LAUNCH-302 — Make OCI production-grade

Dependencies: LAUNCH-300
Executor: Codex plus native amd64/arm64 image builders
Release blocking: yes

- [ ] Replace mutable base tags with reviewed digest pins.
- [ ] Build both architectures from source archive with version/revision/ABI/license/source annotations.
- [ ] Preserve numeric non-root `65532:65532`; test read-only root, dropped capabilities, state ownership, signals, health/readiness, and no egress.
- [ ] Verify OCI descriptors, sizes/digests, diff IDs, bounded safe layers, modes/owners, architectures, and non-root config.
- [ ] Run native smoke/load/chaos on amd64 and arm64.
- [ ] Scan packed layout, layers, and rootfs for vulnerabilities, malware, secrets, developer paths, and endpoints.
- [ ] Sign index/image digest, record transparency evidence, deploy only by digest.

```sh
python3 scripts/release/verify_package.py \
  "$DIST/cigar-cigard-1.0.0.oci.tar" \
  --contract packaging/contracts/oci-image.v1.json \
  --expected-version 1.0.0 \
  --expected-abi cigar.context.v1 \
  --source-date-epoch "$SOURCE_DATE_EPOCH"
```

### LAUNCH-303 — Qualify SDK packages and publication chain

Dependencies: LAUNCH-301
Executor: Codex locally; approved owners publicly
Release blocking: yes

- [ ] Re-run all 19 Rust packages after version/final commit. Require `.cargo_vcs_info.json` = candidate, no normalized path dependencies, reviewed Ring forks, exact `quick-xml 0.41.0`, and no Surf/async-std transport.
- [ ] TypeScript: frozen install, tests/typecheck/build, `pnpm pack`, contract, clean offline install.
- [ ] Python: tests/mypy/ruff, wheel+sdist, `twine check`, clean install from each.
- [ ] Go: test/vet/govulncheck, canonical zip, clean proxy/cache consumer.
- [ ] Rust: local registry chain, contracts, clean default-feature consumer on all five targets.
- [ ] Verify protocol identity and SDK capability parity across four runtimes.
- [ ] Obtain ownership for 19 crates, npm scope, PyPI, Go/tag namespace, OCI repository, Homebrew tap, and WinGet identity.
- [ ] Publish exact prequalified Rust packages in `sdk/rust/PUBLISHING.md` order; stop after any checksum/owner/feature/dependency mismatch.
- [ ] Publish other ecosystems without rebuild. Fetch each publicly and compare registry checksum/content with approved artifact.

```sh
REGISTRY="$(mktemp -d)"
cargo local-registry sync Cargo.lock "$REGISTRY"
python3 sdk/rust/qualify_publication_chain.py \
  --registry "$REGISTRY" \
  --report "$CIGAR_EVIDENCE_DIR/rust-publication-chain.json"
cargo audit --deny warnings
cargo deny check
```

### LAUNCH-304 — Run complete installed-byte platform matrix

Dependencies: LAUNCH-301 through LAUNCH-303
Executor: fresh native unprivileged VMs
Release blocking: yes

- [x] Implement the native Apple-silicon full-profile installed-byte driver, fail-closed runtime
      receipt/schema checks, and a content-free artifact/source/workflow binding. A diagnostic run
      against locally staged release binaries passed 23 offline, denial, provenance/disposition,
      exact-help, restart, backup/restore, and retained-upgrade checks under a real Seatbelt child
      boundary. It used an administrator-owned dirty checkout and unsigned, unnotarized staged
      bytes; it does not satisfy any clean non-admin packaged-candidate checkbox below.
- [ ] Qualify each native archive/installer with exact contract, artifact ID, target, version, ABI, and environment driver.
- [ ] Use VMs without compilers, unprivileged/non-admin identity, empty state/cache, and enforced no-egress.
- [ ] Exercise spaces, Unicode, long paths, read-only parent, case aliases, and non-admin/user-local paths.
- [ ] Verify version/ABI/source revision from `cigar`/`cigard` plus help, completions, man pages, daemon lifecycle, doctor, ingest/compile/explain, spaces/handoff, effect recovery, replay, backup/restore, restart, shutdown.
- [ ] Run installed conformance, demos, SDK quickstarts, security cases, and offline behavior.
- [ ] Upgrade every retained catalog/journal fixture; verify roots, replay, UNKNOWN safety, rollback.
- [ ] Uninstall installed files while preserving user data/config byte-identically unless explicitly deleted.
- [ ] Test ecosystem packages from empty caches and OCI on native amd64/arm64.

```sh
python3 scripts/release/qualify_install.py "$ARCHIVE" \
  --contract "$CONTRACT" \
  --qualification-tool-archive "$QUALIFICATION_TOOL_ARCHIVE" \
  --qualification-tool-contract \
    packaging/contracts/macos-conformance-runner.v1.json \
  --expected-artifact-id "$ARTIFACT_ID" \
  --expected-target "$TARGET" \
  --expected-version 1.0.0 \
  --expected-abi cigar.context.v1 \
  --report "$CIGAR_EVIDENCE_DIR/install/install-$ARTIFACT_ID.json"
```

Required: install/uninstall/offline/upgrade failures = 0; every exact artifact covered.

### LAUNCH-305 — Execute installed docs and eight live runbooks

Dependencies: LAUNCH-304
Executor: Codex plus isolated operations environment
Release blocking: yes

- [ ] Execute installed/live documentation command manifests with explicit bounded variables:

  ```sh
  python3 scripts/release/check_docs.py \
    --execute installed-candidate \
    --variables /release/installed-variables.json \
    --report docs/installed.json
  python3 scripts/release/check_docs.py \
    --execute live \
    --variables /release/live-variables.json \
    --report docs/live.json
  ```

- [ ] Supply environment-owned drivers for backup, restore, key rotation, migration, index rebuild, unknown effect, journal quarantine, and adapter disable.
- [ ] Drivers verify complete build manifest first and bind their digest/every consumed artifact.
- [ ] Use real isolated PostgreSQL/object storage/TLS/OIDC/shared storage. Require bounded resources/output, safe stops, integrity roots, recovery evidence, no secret output, deterministic cleanup.

  ```sh
  python3 scripts/release/exercise_runbooks.py \
    --mode live \
    --candidate-manifest "$DIST/release-build.json" \
    --driver-directory /approved/runbook-drivers \
    --source-date-epoch "$SOURCE_DATE_EPOCH" \
    --out "$CIGAR_EVIDENCE_DIR/operations"
  ```

Required: docs failed commands = 0; live exercises = 8/8. Static validation is not sufficient.

### LAUNCH-306 — Resolve licenses and reconcile final-byte SBOMs

Dependencies: LAUNCH-301
Executor: Codex plus authorized license reviewer
Release blocking: yes

- [ ] Resolve all 20 `review-required` components from authoritative evidence. Remove only when artifact inventory proves non-distribution; never relabel `NOASSERTION` without proof.
  - [x] Source-tooling milestone (2026-07-14): the exact 19 foreign-platform TypeScript 7.0.2 npm archives and colorama 0.4.6 sdist now have lock-bound upstream metadata/archive/license-document evidence. The offline generator rejects duplicate, stale, substituted, unsafe, or locally conflicting evidence before fallback and canonically regenerates 629 components with zero technically unresolved policy expressions, including the six newly locked Playwright/axe/fsevents entries. The focused hostile suite passes 23/23, and a reviewed-license diagnostic emitted SPDX 2.3 and CycloneDX 1.6 documents for all 659 locked components with zero `NOASSERTION` or non-accepted policy result. This authority explicitly is not legal approval and does not reconcile final packaged bytes, so this parent gate remains open for the authorized reviewer and final-artifact inventory.
- [ ] Inventory every packed/unpacked native library, SDK dependency, extension, plugin executable, installer member, and OCI layer/rootfs.
- [ ] Run complete inventory on every final builder:

  ```sh
  python3 scripts/release/generate_license_inventory.py \
    --out "$CIGAR_EVIDENCE_DIR/licenses/third-party-inventory.json" \
    --require-complete
  ```

- [ ] Generate aggregate SPDX 2.3, CycloneDX 1.6, and artifact-binding documents from final bytes.
- [ ] Verify each component identity/version/license/source and each artifact/member appears in both SBOMs.
- [ ] Reject omitted artifact/layer/native library, unresolved license, duplicate alias, stale digest, or fabricated metadata.

Required: license and both SBOM unreviewed components = 0.

### LAUNCH-307 — Scan every exact final artifact

Dependencies: LAUNCH-301, LAUNCH-306
Executor: approved isolated scanner environment
Release blocking: yes

- [ ] Run pinned vulnerability, malware-indicator, secret, developer-path, and unexpected-endpoint scans on every packed artifact and safe unpacked form.
- [ ] Run native import/symbol scans and OCI descriptor/layer/rootfs/image scans.
- [ ] Record tool/ruleset/DB digests, source/artifact SHA-256, coverage map, times, and raw report digests.
- [ ] Treat scanner error/unsupported format as coverage failure.
- [ ] Reconcile with SBOM/deep source scan; any reachable critical/high requires fix/rebuild and downstream invalidation.

Required: critical = 0; high = 0; scan coverage = 100%.

### LAUNCH-308 — Prove reproducibility and apply platform signing

Dependencies: LAUNCH-301, LAUNCH-306, LAUNCH-307
Executor: two builders plus Apple/Windows signers
Release blocking: yes

- [ ] Rebuild every unsigned payload from the same source archive in two isolated empty-cache builders per target.
- [ ] Compare archives, native payloads, deterministic SDK packages, plugin, installer metadata, OCI descriptors/layers, manifests, and checksums.
- [ ] Compare unsigned macOS/Windows payloads before signing; prove signed envelopes contain them.
- [ ] Run:

  ```sh
  python3 scripts/release/check_reproducibility.py \
    --source-date-epoch "$SOURCE_DATE_EPOCH" \
    --report "$CIGAR_EVIDENCE_DIR/reproducibility.json" \
    --require-committed-clean
  ```

- [ ] Developer-ID sign/notarize/staple macOS and verify on clean Intel/arm64 including offline staple.
- [ ] Authenticode-sign Windows and verify chain/timestamp/revocation policy on clean Windows.
- [ ] Re-run contract, scan, and SBOM binding on exact distributed bytes where wrappers changed.

Required: reproducibility mismatches = 0; claimed platform signing/notarization present.

### LAUNCH-309 — Generate provenance and production signatures

Dependencies: LAUNCH-308
Executor: Codex orchestrator plus approved external signers
Release blocking: yes

External prerequisites: isolated Ed25519 signer; independently distributed trust roots/policy; Apple/Windows identities; immutable builder/workflow identities; no-egress attestation.

- [ ] Generate provenance for every artifact with source archive/revision, locks/materials, builder, workflow, command, network mode, and times.
- [ ] Treat `CIGAR_NO_EGRESS_ENFORCED=1` only as a marker accompanying real sandbox evidence.
- [ ] Sign every artifact (`release-artifact`), `SHA256SUMS` (`release-checksums`), SBOMs (`release-sbom`), provenance (`release-provenance`), conformance, benchmark, and required qualification attachments with scoped purposes.
- [ ] Verify each envelope immediately against independently provisioned roots and purpose/scope/time/status rules.
- [ ] Never generate/import/export a production private key in the workspace.
- [ ] Test wrong purpose, same-name swap, output alias, expired/revoked/untrusted key, malformed signature, and post-sign mutation.

Required: signature failures = 0; provenance missing subjects = 0.

---

## Phase 4 — WP22 final evidence, decision, and exact-byte promotion

### LAUNCH-400 — Close machine-recorded qualification gaps honestly

Dependencies: all LAUNCH-1xx, LAUNCH-2xx, and LAUNCH-3xx tasks
Executor: Codex plus external receipt owners
Release blocking: yes

- [ ] Regenerate `packaging/qualification-gaps.v1.json` from evidence and close with exact receipt references:
  - committed source revision;
  - external native builds;
  - production signer/trust roots;
  - third-party license review;
  - Rust and other SDK publication;
  - installer scope;
  - publishing/notarization/transparency;
  - final artifact security;
  - eight live operations;
  - installed/live docs;
  - final artifact SBOM reconciliation.
- [ ] Preserve gap history when schema requires records; set non-blocking only when closure evidence exists.
- [ ] Regenerate `IMPLEMENTATION_STATUS.md`, `docs/execution/work-packets.yaml`, and WP19-WP22 packet evidence from machine results.
- [ ] Require every packet commit to be an ancestor of `CANDIDATE_SHA` and every packet artifact/evidence digest to match.
- [ ] Mark WP19/WP20/WP21 complete only after exact exits. WP22 waits for LAUNCH-403.

### LAUNCH-401 — Assemble and sign complete release evidence

Dependencies: LAUNCH-400
Executor: Codex plus approved release signer
Release blocking: yes

- [ ] Require all 30 categories with real attachments and no prohibited status:
  `test`, `traceability`, `toolchain`, `work-packet`, `coverage`, `mutation`, `fuzz`, `sanitizer`, `model`, `chaos`, `migration`, `scale`, `soak`, `conformance`, `benchmark`, `package`, `install`, `uninstall`, `offline`, `upgrade`, `license`, `sbom-spdx`, `sbom-cyclonedx`, `signature`, `provenance`, `reproducibility`, `docs`, `demo`, `operations`, and `security`.
- [ ] Require signed `SHA256SUMS`, `release-evidence.json`, `sbom.spdx.json`, `sbom.cyclonedx.json`, `sbom-artifacts.json`, `provenance.json`, every artifact, and directly required report.
- [ ] Recompute every metric from raw attachments; never trust receipt prose alone.
- [ ] Set matrix to release state only now, then run:

  ```sh
  python3 scripts/release/validate_metadata.py --release
  python3 scripts/release/assemble_evidence.py \
    --dist "$DIST" \
    --build-manifest release-build.json \
    --evidence-directory evidence \
    --signature-directory signatures \
    --out release-evidence.json
  ```

- [ ] Never use `--allow-development`.
- [ ] Sign `release-evidence.json` with purpose `release-evidence`.
- [ ] Ensure final directory contains exactly allowlisted artifacts, referenced evidence/attachments, supply-chain documents, and signatures—no debug logs, keys, hidden seeds, caches, mutable aliases, or unreferenced files.
- [ ] Prove assembly fails after representative required artifact/report/signature deletion or tampering.

### LAUNCH-402 — Perform independent offline verification

Dependencies: LAUNCH-401
Executor: independent clean verifier/trust-root custodian
Release blocking: yes

- [ ] Transfer candidate directory and trust roots through independent channels; disconnect verifier from network.
- [ ] Verify safe/exact file set, checksums, contracts, source/artifact bindings, attachments, SBOM coverage, signatures/purpose/trust/time, provenance, metrics, platforms, and gaps.
- [ ] Run:

  ```sh
  python3 scripts/release/verify_release.py "$DIST" \
    --trust-policy /independent/root/release-trust-policy.json \
    --openssl /independent/tools/openssl \
    --openssl-sha256 "$REVIEWED_OPENSSL_SHA256" \
    --report /independent/reports/release-verification.json
  cargo xtask release verify "$DIST"
  ```

- [ ] If claimed, install the distributed CLI and independently run `cigar release verify "$DIST"`.
- [ ] Adversarially test removed report, stale candidate, swapped artifact, case/same-name collision, unreferenced payload, weakened policy, expired/revoked/wrong-purpose key, incomplete SBOM, missing provenance subject, and mutated byte.

Done when all verifier entry points agree on success for exact directory and failure for adversarial fixtures.

### LAUNCH-403 — Final human go/no-go and exact-byte promotion

Dependencies: LAUNCH-402
Executor: authorized release owners; Codex prepares/verifies but cannot invent approval
Release blocking: yes

- [ ] Obtain explicit two-person approval over `CANDIDATE_SHA`, `SHA256SUMS`, independent verification report, residual-risk record, and rollback plan.
- [ ] Publish only verified files—no rebuild, recompression, re-sign, manifest rewrite, or mutable “latest” before reconciliation.
- [ ] Finalize registry packages in approved dependency order; stop on first checksum/content/ownership mismatch.
- [ ] Publish OCI by digest, digest-pinned installer manifests, notarization/transparency receipts, archives, signatures, SBOMs, and provenance.
- [ ] Fetch every public package/image/installer/archive and compare to approved build manifest/`SHA256SUMS`.
- [ ] Run clean public-consumer smoke for crates.io, npm, PyPI, Go proxy, OCI, Homebrew, WinGet, and direct archives.
- [ ] Create and push signed `v1.0.0` tag pointing exactly to `CANDIDATE_SHA` only after offline verification and public checksum reconciliation.
- [ ] Publish release notes, supported platforms/runtimes, limitations, upgrade/rollback, checksums, trust-root retrieval, and security contact.
- [ ] Update `SECURITY.md` with a real private route, supported versions, response/disclosure targets, and advisory process. Remove “not released” warning only after promotion.
- [ ] Mark WP22 and final PRD checklist complete only after public readback passes.

### LAUNCH-404 — Post-release verification and rollback readiness

Dependencies: LAUNCH-403
Executor: operations/release owners
Release blocking for declaring launch complete: yes

- [ ] Monitor install/start/readiness, error classes, queue/lease age, UNKNOWN effects, auth failures, resource growth, and availability without collecting protected content.
- [ ] Re-run scheduled scans against published digests/SBOM; start advisory/patch flow for newly reachable issues.
- [ ] Exercise rollback/disable without unsafe retry, catalog/journal downgrade corruption, tenant bleed, or trust-root ambiguity.
- [ ] Preserve immutable evidence, public readback, tag/commit/signature identity, registry checksums, and incident contacts per retention policy.
- [ ] Convert accepted residual risks to owner/deadline/testable follow-up; never relabel a release blocker as residual risk.

---

## Final stop-ship checklist

Every box must be checked immediately before tag and promotion:

- [ ] Source is clean, committed, immutable, and identical to every source receipt.
- [ ] Every required xtask command is real, strict, and emits non-empty evidence.
- [ ] No result is failed, skipped, flaky, quarantined, waived, unknown, stale, partial, or synthetic.
- [ ] Security matrix/deep candidate review pass; no reachable deferred surface remains.
- [ ] Critical/high source, dependency, and final-byte findings = 0; scan coverage = 100%.
- [ ] Unauthorized content/existence/secret/project/tenant/purpose/processor leakage = 0.
- [ ] Canonical digests agree across all SDKs and claimed platforms.
- [ ] Mandatory context cannot be omitted/lane-promoted; selections/dispositions have provenance/reason.
- [ ] No semantic drift, silent truncation, unsafe retry, duplicate effect, or dispatch before durable intent/authorization.
- [ ] Non-live replay performs zero network/model/tool/connector/effect calls.
- [ ] No committed journal event is lost and no partial canonical state becomes visible.
- [ ] Coverage, full mutation, per-target fuzz, sanitizers, models, chaos, effects, migrations, scale, and 24-hour soak pass.
- [ ] All performance SLOs and CIGARBench outcome/confidence gates pass.
- [ ] Every demo and all four SDK workflows pass from distributed packages.
- [ ] Every native platform, installer, plugin, SDK package, and OCI architecture passes exact installed-byte qualification.
- [ ] Licenses are 100% reviewed; SBOMs cover every distributed byte/component/layer.
- [ ] Two-builder payloads match; platform signing/notarization and production signatures verify.
- [ ] Provenance includes every subject/material and binds source, workflow, builder, locks, commands, artifacts, and evidence.
- [ ] Installed/live docs pass and eight live operations pass.
- [ ] `release-evidence.json` is complete, signed, current, candidate-bound, and tamper-evident.
- [ ] Independent offline `cargo xtask release verify dist/` and installed `cigar release verify dist/` pass.
- [ ] Public registry/download bytes match `SHA256SUMS` exactly.
- [ ] Signed `v1.0.0` tag points exactly to verified evidence source commit.

If any box cannot be checked, record the blocker and continue independent work, but do not release.
