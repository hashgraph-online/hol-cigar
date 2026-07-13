# CIGAR v1 production launch backlog

Audience: Codex GPT-5.6 SOL and release operators
Generated from repository state: 2026-07-13
Observed commit: `0d8a8115b4fa1bedec534eeca497a157836ed6da` (`Initial Commit`)
Target: a clean, immutable CIGAR v1.0.0 candidate and exact-byte production release

## Launch verdict

**STOP-SHIP. The observed commit is a useful baseline, not a releasable candidate.**

Do not tag, publish, notarize, sign, or describe this revision as production-ready until every release-blocking item below is complete and the final offline verifier passes.

| Area | Observed state | Required state |
|---|---|---|
| Source | `HEAD` exists, but two WP19 receipts are modified, 25 tracked fuzz corpus entries are deleted, and 6,189 corpus entries are untracked | One later clean candidate commit; qualification writes outside the checkout |
| Command plane | `cargo xtask test all`, named suites, `bench`, `package`, and `release-verify` deliberately fail; some accepted flags are ignored | Every PRD section 28.1 command dispatches to a distinct real, fail-closed gate |
| Security | `reports/security-matrix.local.json` is stale and failed 8/10; Semgrep has five reviewed but blocking results | All release cases and pinned scans pass on applicable native platforms |
| Security review | Previous scan read 73/380 source-like files fully and retains 12 deferred proof gaps | Fresh deep scan of exact candidate, 100% claimed-surface disposition, zero critical/high |
| Coverage | Stale LCOV covers 642 lines, reports 36.449% line coverage, and no branches | All release code/targets; line >= 80%, branch >= 70% |
| Fuzz | 14 targets passed approximately 60 seconds each | Each target >= 604,800 clean CPU-seconds; aggregate >= 8,467,200; zero defects |
| Mutation | 42-second `cigar-canon` slice caught 10/10 viable mutants | Full production RC campaign >= 4 hours; critical survivors/timeouts = 0 |
| Traceability | Conformance is 24/24, but only 35 curated requirements, 4 invariants, and 17 tests are mapped | Every normative requirement maps to active candidate-bound evidence |
| WP20 | Seven demos, four recorded SDK workflows, and 540-event dry run pass local scope only | Installed-byte runs, real comparators, >= 270 independent adjudicated tasks, independent evaluator |
| Packaging | Six source-derived archives have producers; 12/18 matrix entries do not; no `dist/` exists | Every claimed artifact has a deterministic producer, contract, installed test, and final-byte evidence |
| Licensing | 568 components inventoried; 20 are `review-required` | Zero unreviewed distributed components |
| Metadata | Matrix is `0.1.0`/`development` while WP22 requires v1.0.0; 11 gaps remain | One version/ABI and every gap closed by exact evidence |
| Operations | Eight runbooks pass static validation only | Eight live exercises against exact installed bytes |
| CI/repository | Only fast and security workflows exist; no Git remote is configured in the observed checkout | Authoritative protected remote plus merge, nightly, weekly, RC, build, qualification, signing, and promotion workflows |

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
- [ ] Regenerate stale “unborn repository” content in `IMPLEMENTATION_STATUS.md`, `docs/execution/work-packets.yaml`, `packaging/qualification-gaps.v1.json`, and WP20/WP21 receipts without claiming completion.
- [ ] Commit the policy/corpus/status changes and record the later SHA. Prove a smoke gate leaves `git status --porcelain=v1` empty.

Done when the source/fixtures are intentional, no regression is lost, and the checkout is clean before and after testing.

### LAUNCH-001 — Add a first-class external evidence workspace

Dependencies: LAUNCH-000
Executor: Codex
Release blocking: yes

- [ ] Make every xtask, matrix, fuzz/mutation, benchmark, demo, and release script accept `--evidence-dir` or `CIGAR_EVIDENCE_DIR`.
- [ ] In release mode reject outputs inside the candidate, symlink traversal, path escape, case collision, overwrite, and group/world-writable paths.
- [ ] Use atomic create-new writes, bounded counts/sizes, canonical JSON, explicit modes, and durable rename where needed.
- [ ] Share one source descriptor: full commit/tree, clean/committed flags, source archive digest, policy and toolchain digests.
- [ ] Test stale SHA, dirty source, mutable/missing attachment, duplicate ID, prohibited status, synthetic metric, NaN/infinity, and path substitution.
- [ ] Prove a full source gate leaves a read-only checkout byte-identical and clean.

### LAUNCH-002 — Implement the authoritative PRD command plane

Dependencies: LAUNCH-001
Executor: Codex
Release blocking: yes

Replace unavailable placeholders, aliased suites, and ignored flags with strict parsing and real dispatch.

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

- [ ] Reject unknown/duplicate/unused flags, missing values, path escapes, and incompatible combinations.
- [ ] Ensure `test property` reaches the independent `tests/properties` workspace and is not silently `test unit`.
- [ ] Add table-driven dispatcher tests for all PRD section 28.1 commands and negative cases.
- [ ] Fail any required route that returns success without a non-empty source-bound receipt/raw attachment.
- [ ] Generate PRD/README/CI/release command inventories from one manifest to prevent drift.

### LAUNCH-003 — Freeze v1.0.0, ABI, platform, feature, and installer scope

Dependencies: LAUNCH-002
Executor: Codex plus release owner for public naming
Release blocking: yes

- [ ] Select `1.0.0` as WP22 requires, or amend the PRD before version work. Never ship `0.1.0` bytes under `v1.0.0`.
- [ ] Implement one version generator/checker for workspace packages/internal pins, all `release.json` files, locks, four SDKs, plugin, image labels, docs, contracts, filenames, installers, qualification tools, and tests.
- [ ] Preserve `cigar-aws-creds 0.39.1-cigar.1` and `cigar-rust-s3 0.37.2-cigar.1` unless intentionally revved and re-reviewed.
- [ ] Freeze Context ABI `cigar.context.v1`, protocol min/max, schemas, errors, operations, and vectors.
- [ ] Freeze Linux x86_64/aarch64 GNU, macOS x86_64/arm64, and Windows x86_64 MSVC.
- [ ] Implement minimum installer scope: Homebrew formula/bottles for both macOS architectures; WinGet portable manifests for signed Windows ZIP; signed tar archives for Linux. Add deb/rpm/MSI only with full qualification.
- [ ] Give each installer/formula/manifest an artifact ID, exact filename, contract, producer, signature purpose, install target, and evidence map.
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

- [ ] PR: format, generation, lint, unit, vectors, docs, dependency/static security.
- [ ] Main/merge: native cross-platform unit/integration/compatibility/conformance/matrices.
- [ ] Nightly: sanitizers, models, adversarial/security, migration, chaos, package smoke.
- [ ] Weekly: mutation, cumulative fuzz workers, effect RC faults, scale, performance.
- [ ] RC/manual/tag: immutable source archive, native builds, installed qualification, 24-hour soak, CIGARBench, reproducibility, SBOM, scans, signing, offline verify, approval-gated promotion.
- [ ] Pin actions/images, use read-only defaults, per-job elevation, protected environments, OIDC where supported, concurrency locks, timeouts, and artifact digest verification across handoffs.
- [ ] Bind receipts to event SHA and immutable builder identity. Fail if a claimed platform/environment is absent.
- [ ] Keep production keys out of repository and ordinary Actions secrets.
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

- [ ] Reproduce and fix the stale failures with private logs:

  ```sh
  cargo nextest run --locked -p cigar-cli --lib
  cargo nextest run --locked -p cigar-store --lib
  ```

  Fix a real defect or deterministic contention flaw; do not accept retry-only evidence.

- [ ] Add `SEC-MCP-001` for `cargo nextest run --locked -p cigar-mcp --all-targets`. Preserve bounded string/safe-integer request-ID tests, cancellation predicate equivalence, silent notifications, recursive non-finite/overflow backend-number rejection, parseable errors, and content-free diagnostics.
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

- [ ] Generate stable IDs/source locations for every normative MUST/SHALL, release gate, and security invariant in `prd.md`; prohibit silent omission.
- [ ] Expand `conformance/profiles/requirements-v1.json` and `tests/invariants.yaml` so every normative requirement maps to an existing active test and exact evidence.
- [ ] For each critical invariant require applicable positive contract/vector, negative/adversarial case, property/model, real process/fault case, cross-runtime differential, and installed-byte case.
- [ ] Reject duplicate IDs, nonexistent commands/fixtures, inactive mappings, skips/quarantines, stale evidence, and unmapped normative requirements.
- [ ] Execute all supported profiles against reference and intentionally faulty implementations; every injected fault must be detected by its intended invariant.
- [ ] Run cross-runtime identity under all supported OS/architectures, locale/timezone changes, input permutations, randomized scheduling/map seeds, and repeated processes.

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

- [ ] Make `cargo xtask test coverage --verify` cover all workspace packages/features/targets, branch data, and the independent property workspace using the pinned equivalent of:

  ```sh
  cargo llvm-cov nextest \
    --workspace --all-features --all-targets --branch \
    --lcov --output-path "$CIGAR_EVIDENCE_DIR/coverage/lcov.info"
  ```

- [ ] Emit per-package candidate-bound line/branch/function JSON. Exact generated/vendor exclusions require review; production code cannot disappear from the denominator.
- [ ] Reject empty LCOV, missing branches/packages, malformed/NaN percentages, stale source, or unreviewed exclusions.
- [ ] Add behavior-focused tests, prioritizing auth, isolation, canonicalization, effects, replay, storage, migrations, parsers, package verifier, and release verifier.

Done when line >= 80%, branch >= 70%, and no release target is missing.

### LAUNCH-103 — Correct fuzz policy and complete the RC campaign

Dependencies: LAUNCH-100
Executor: Codex plus isolated long-running workers
Release blocking: yes

- [ ] Fix `packaging/release-requirements.v1.json`: aggregate `sum(fuzz.total_seconds) >= 604800` is 14x too weak. Require exactly 14 targets and >= 604,800 clean CPU-seconds per target; aggregate >= 8,467,200.
- [ ] Implement a crash-safe cumulative ledger keyed by candidate, target, binary/toolchain/sanitizer, target source, campaign policy, corpus lineage, and worker.
- [ ] Reject overlapping time, duplicate receipt IDs, untrusted workers, clock reversal, mixed candidates, missing targets, and accumulation after a target crash.
- [ ] Give each worker a private mutable corpus; periodically minimize into deterministic reviewed corpus. Never share writable corpus.
- [ ] Run all 14 campaign targets with ASan/libFuzzer to threshold under bounded memory/time/output.
- [ ] On defect: minimize/preserve, reproduce, fix, add named regression, create new candidate, reset affected target accumulation, rerun invalidated gates.
- [ ] Verify all historical crashes, including MCP ID/backend-number input, on applicable platforms.
- [ ] Add verifier negatives for aggregate-only evidence, under-time/missing target, stale binary, corrupt lineage, duplicate time, and crash followed by accumulation.

Done when each target independently has >= 604,800 clean CPU-seconds and unresolved crash/hang/OOM/sanitizer defects = 0.

### LAUNCH-104 — Complete sanitizers, properties, and concurrency models

Dependencies: LAUNCH-100
Executor: Codex plus supported Linux/nightly workers
Release blocking: yes

- [ ] ASan all 14 fuzz targets and applicable integration suites.
- [ ] TSan production concurrency paths: cache publication, snapshots, context revisions, outbox/fencing, subscription cursor, invalidation queue, shutdown, effects, store, shared coordination.
- [ ] Strict Miri on unsafe/sensitive portable code. Run UBSan or a documented supported equivalent for FFI/native undefined behavior; never claim an unexecuted sanitizer.
- [ ] Keep seven semantic property families at substantial generated counts with seeds/shrinks.
- [ ] Prove each of the seven existing Loom models refines/represents its production state machine; record schedules, bounds, branches, and configuration.
- [ ] Add production-linked Shuttle/Loom/model coverage where an abstract standalone model could diverge from real synchronization.
- [ ] Run stable and pinned nightly without lint allowance drift.

Required metrics: sanitizer defects = 0; model defects = 0.

### LAUNCH-105 — Run full RC mutation analysis

Dependencies: LAUNCH-102
Executor: Codex plus bounded workers
Release blocking: yes

- [ ] Resolve the policy mismatch between representative 90% and release 70%; select one reviewed RC threshold. Critical auth/isolation/effect/canonical/integrity code always requires zero viable survivors.
- [ ] Implement `cargo xtask test mutations --verify` across production Rust with exact generated/vendor/test exclusions and no package omission.
- [ ] Run a clean baseline and >= 4-hour campaign with bounded jobs/timeouts; record mutation list, classification, command/tool digest, and durations.
- [ ] Investigate every survivor/timeout; add behavioral tests or fix coupling. Never blacklist a viable mutant merely to improve score.
- [ ] Reject representative-only scope, under-duration, missing package, timeout, critical survivor, malformed denominator, or stale source.

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

- [ ] Prove durable intent/authorization before dispatch, stable idempotency, no duplicate logical effect, correct UNKNOWN/reconciliation, and compensation as a new linked effect.
- [ ] Close HTTP effect controls: destination allowlist, DNS/private-IP/rebinding, redirect/proxy, TLS identity, auth/response authenticity, deadlines/cancellation, bounded body, idempotency, ambiguous success.
- [ ] Close filesystem effect confinement with descriptor/handle-relative traversal and ancestor-swap resistance; test symlink/mount/rename/case/Unicode races and deployment ownership.
- [ ] Run all release chaos cases for SQLite, daemon, extension, object/blob, PostgreSQL, shared service, effects, and credentials. Run doctor, roots/hash chains, rebuild, and reconciliation after faults.
- [ ] Re-run `tools/qualify-shared-profile.sh` and `tools/wp18-failover/qualify.sh`, then qualify managed private-CA PostgreSQL, external S3-compatible storage, and production CSI/RWX/POSIX locking. Emulators are not final evidence.
- [ ] Exercise OIDC/JWKS rotation/revocation, CA chains, mTLS identity, separate runtime/migrator credentials, and no plaintext/downgrade.
- [ ] Run every retained adjacent migration, interrupt every failpoint, restart, verify semantic roots/replay, and require journal RPO 0.
- [ ] Scale local through 1M atoms/10M edges/100GB referenced blobs and shared through 10M atoms.
- [ ] Run installed daemon >= 86,400 seconds over 1..64 sessions with ingestion, compile/delta, spaces/handoff/events, effects/reconciliation, replay, backup, GC, and bounded dependency faults.
- [ ] Require no memory/FD/task trend, deadlock, lost commit, stuck lease, unbounded queue, unexplained UNKNOWN, unauthorized output, or reference digest drift.

Required: effect operations >= 100,000; soak/daemon soak >= 86,400 seconds; invariant/migration/scale failures = 0; max atoms >= 10,000,000.

### LAUNCH-107 — Close static, dependency, secret, and source security gates

Dependencies: LAUNCH-100
Executor: Codex
Release blocking: yes

- [ ] Add only exact-rule, same-line Semgrep suppressions with adjacent rationale for:
  - `python.lang.security.audit.insecure-file-permissions.insecure-file-permissions` at `demos/claude-code/driver.py:34` (0700 executable);
  - the same rule at `demos/driver_support.py:359` (0700 private request directory);
  - the same rule at `scripts/release/qualify_install.py:265` (restore non-secret temp dir to 0755);
  - the same rule at `tools/quality/run_matrix.py:377` (0700 private log directory);
  - `go.grpc.security.grpc-server-insecure-connection.grpc-server-insecure-connection` at `demos/sdk-clients/go-workflow/main.go:337` (in-memory `bufconn`, custom dialer, no network listener).
- [ ] Do not ignore whole paths or disable rules globally. Add tests preserving each suppressed security property.
- [ ] Pin/vendor the Semgrep ruleset and record its digest; `--config auto` alone is mutable.
- [ ] Produce revision-bound reports:

  ```sh
  cargo clippy --workspace --all-features --all-targets -- -D warnings
  cargo audit --deny warnings
  cargo deny check
  corepack pnpm audit --prod --audit-level high
  uv export --project sdk/python --no-dev --format requirements-txt \
    --no-emit-project --no-hashes | uvx --from pip-audit==2.10.1 \
    pip-audit --strict --no-deps -r /dev/stdin
  (cd sdk/go && govulncheck ./...)
  semgrep scan --config auto --error --timeout 30 \
    --exclude target --exclude vendor --exclude node_modules \
    --exclude dist --exclude .venv \
    --json-output "$CIGAR_EVIDENCE_DIR/security/semgrep-$CANDIDATE_SHA.json" .
  jq -e '.results | length == 0' \
    "$CIGAR_EVIDENCE_DIR/security/semgrep-$CANDIDATE_SHA.json"
  ```

- [ ] Run gitleaks 8.30.1 with redacted output and actionlint 1.7.12. Record scanner/ruleset/advisory-DB digests and distinguish scanner failure from clean result.
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

- [ ] Add deterministic producers for 12 currently missing matrix entries: five native archives, npm package, Rust crate/SDK, Python sdist/wheel, Go module zip, Claude plugin, and multi-architecture OCI layout.
- [ ] Add producers/contracts for every installer frozen in LAUNCH-003.
- [ ] Assemble `release-build.json` requiring every release artifact ID exactly once, with relative path, SHA-256, bytes, contract/digest, version, ABI, platform, candidate SHA/tree, source archive, and `SOURCE_DATE_EPOCH`.
- [ ] Write canonical `SHA256SUMS` permitting exactly build-manifest artifacts and rejecting aliases/collisions/unreferenced files.
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
  --qualification-driver "$DRIVER" \
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
    --report "$CIGAR_EVIDENCE_DIR/docs/installed.json"
  python3 scripts/release/check_docs.py \
    --execute live \
    --variables /release/live-variables.json \
    --report "$CIGAR_EVIDENCE_DIR/docs/live.json"
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
