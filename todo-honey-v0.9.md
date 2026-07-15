# CIGAR Honey v0.9 reduced developer-preview release plan

Audience: GPT-5.6 SOL implementation agent, CIGAR maintainers, demo operators, and release reviewers.

Status: implemented through the Honey source-freeze gate. The checkboxes remain acceptance gates:
an item is complete only when its artifact or evidence is bound to the exact clean Honey candidate,
so source implementation alone does not close installed-byte or publication items.

Target: **CIGAR Honey `0.9.0-honey.1`**.

Execution record at source freeze:

- Honey authority, version propagation, runtime/SDK/plugin/demo producers, documentation, assembly,
  public verification, private evidence construction, and the bounded release orchestrator are
  implemented and covered by focused tests.
- The orchestrator builds exactly 13 public attachments from one clean commit and labels them
  `honey-built-unqualified`; candidate-only verification can prove artifact integrity but cannot
  promote installed qualification.
- Exact installed qualification must run as a standard non-admin Apple-silicon macOS user. The
  current release workstation account is an administrator, so this mandatory gate must remain open
  until rerun in the required account/environment; the guard must not be weakened or bypassed.
- Tagging, GitHub prerelease creation, and upload remain open and require explicit owner approval at
  the time of publication.

## 1. Release outcome

Ship a useful local developer preview that a new user can verify, install, and use without building
the repository or understanding the full v1 release program.

A successful Honey user can:

1. install CIGAR on Apple-silicon macOS from a GitHub prerelease archive;
2. initialize a workspace and ingest local filesystem or Git sources;
3. query the catalog and compile deterministic, provenance-bearing context;
4. use CIGAR from the CLI, local daemon, MCP, Claude Code, Python, Rust, or TypeScript;
5. delegate work from Agent A to Agent B through a scoped signed handoff;
6. return and merge a typed result without copying an unrestricted transcript;
7. prepare and recover a local reference effect;
8. inspect evidence and run non-live replay; and
9. follow packaged demos and documentation from installation through uninstall.

Honey is a developer preview, not CIGAR v1 GA. It must not claim production support, independent
security certification, public multi-tenant safety, public package-registry support, Apple
notarization, or completion of the deferred longevity and scale campaigns.

## 2. Fixed Honey scope

### 2.1 Identity and platform

- Marketing name: `CIGAR Honey v0.9`.
- Product version: `0.9.0-honey.1`.
- Git tag: `v0.9.0-honey.1`.
- Channel: `honey`.
- Release state: `developer-preview`.
- Context ABI remains `cigar.context.v1`.
- Protocol and schema major versions remain v1.
- GitHub release is always marked prerelease.
- Machine claims remain `prerelease=true`, `supported=false`, and
  `production_qualified=false`.
- Binary target: `aarch64-apple-darwin` only.
- Deployment modes: embedded and local sidecar only.
- Trust model: one local operating-system user and explicitly configured local agent principals.
- Default network posture: no network required for install, quickstart, demos, evidence replay, or
  SDK qualification.

### 2.2 Mandatory runtime surfaces

The runtime archive contains:

- `cigar` full CLI;
- `cigard` local daemon;
- `cigar-mcp` bounded MCP stdio server; and
- `cigar-claude-hook` for the packaged Claude Code adapter.

Honey keeps the seven generated protocol services because they form one coherent workflow:

| Service | Operations | Required Honey behavior |
|---|---:|---|
| `CatalogService` | 6 | discover, ingest, source status, query, batch atoms, tombstone |
| `ContextService` | 8 | plan, compile bundle/delta, lookup, explain, materialize, revalidate |
| `SpaceService` | 8 | create, fork, publish, log, events, checkpoint, conflicts, resolution |
| `HandoffService` | 6 | create, preview, accept, revoke, record result, merge |
| `EffectService` | 6 | prepare, authorize, dispatch, status, reconcile, compensate |
| `ReplayService` | 4 | create, observational run, live comparison contract, completeness |
| `OperationsService` | 7 | liveness, readiness, version, capabilities, configuration, diagnostics, metrics |

The live-comparison operation may remain present for protocol compatibility, but the Honey daemon
must be composed recorded-only by default. Live provider replay is not a Honey release requirement.

### 2.3 Mandatory integrations

- CLI and local Unix-domain daemon transport.
- MCP 2025-06-18 stdio facade.
- Claude Code plugin using the packaged MCP and hook bytes.
- TypeScript SDK npm tarball installed directly from the GitHub release attachment.
- Python SDK wheel and source distribution.
- Rust SDK distributed as a self-contained local-registry kit.
- Filesystem and Git source ingestion.
- Filesystem reference effect connector.
- Local structured diagnostics, content-safe metrics, and durable evidence/replay records.

HTTP/gRPC remain internal daemon transports needed by generated clients and may be documented for
loopback development. Remote service operation is not a Honey support claim.

### 2.4 Mandatory two-agent model

Honey supports two agents through the existing context-space and handoff protocols. It does not need
an autonomous swarm scheduler.

```text
Agent A (coordinator/parent)
  -> creates parent context space and checkpoint
  -> previews a recipient-bound handoff
  -> signs a reduced context/capability/budget capsule for Agent B

Agent B (worker/child)
  -> accepts under its own authenticated principal and current policy
  -> receives a recipient-specific compiled bundle
  -> works in a private overlay or fork
  -> records typed evidence and a HandoffDelta

Agent A
  -> verifies result, authority, evidence, and exact base
  -> merges independent changes or receives a typed conflict
  -> records the outcome and replay root
```

Required properties:

- distinct Agent A and Agent B principals;
- recipient, audience, tenant, nonce, expiry, and signature binding;
- capability, project, topic, and budget attenuation;
- no unrestricted transcript in the handoff capsule;
- independent reauthorization of every reference at acceptance;
- one-use replay protection and durable revocation;
- private overlay ownership and exact-base optimistic merge;
- typed conflict instead of last-writer-wins;
- idempotency key on every mutation exposed through MCP or an SDK;
- trace/run/task/agent/handoff correlation without exporting source or prompt content; and
- final content-addressed decision/evidence root covering the handoff, result, merge, effect, and
  verification records.

Use the existing SHA-256 and domain-separated deterministic identities. Poseidon is deferred unless
a future zero-knowledge proof profile specifically requires it.

### 2.5 Explicitly deferred

The following are not blockers for Honey:

- dashboard and browser sidecar;
- Go SDK;
- shared PostgreSQL/S3 service mode;
- Docker Compose and Kubernetes release bundles;
- OCI images;
- Linux, Intel macOS, and Windows binary distributions;
- Homebrew tap/bottle and other package-manager installers;
- public PyPI or crates.io publication;
- public npm registry publication;
- remote multi-tenant operation, OIDC, failover, autoscaling, and SLOs;
- HTTPS effects and arbitrary extension execution;
- vector retrieval when lexical/path/symbol retrieval is sufficient;
- live provider replay;
- remote OTLP export;
- CIGARBench efficacy claims;
- seven-day fuzz accumulation;
- four-hour mutation qualification;
- 24-hour soak;
- complete production chaos and platform matrices;
- million-atom, 10-million-edge, and 100-GiB scale tests;
- Developer ID signing and notarization;
- two-builder reproducibility and production supply-chain attestation; and
- production support or GA claims.

Deferred code may stay in the repository. It must not be selected by the Honey artifact profile,
advertised as Honey-supported, or required by Honey quickstarts.

## 3. Required artifact set

Honey intentionally uses a small GitHub-prerelease artifact set.

### 3.1 Public attachments

1. `cigar-0.9.0-honey.1-source.tar.gz`.
2. `cigar-0.9.0-honey.1-docs.tar.gz`.
3. `cigar-0.9.0-honey.1-schemas-conformance.tar.gz`.
4. `cigar-0.9.0-honey.1-aarch64-apple-darwin.tar.gz` containing the four runtime binaries,
   completions, man page, metadata, `LICENSE`, and `NOTICE`.
5. TypeScript SDK npm tarball using the centrally generated Honey package filename.
6. Python SDK wheel.
7. Python SDK source distribution.
8. `cigar-rust-sdk-0.9.0-honey.1-local-registry.tar.gz` containing the public SDK crate and all
   required unpublished internal crates, checksums, index, and consumer configuration.
9. `cigar-claude-code-0.9.0-honey.1.tar.gz`.
10. `cigar-honey-demos-0.9.0-honey.1.tar.gz`.
11. `honey-release-manifest.json`.
12. `SHA256SUMS`.
13. `RELEASE_NOTES_HONEY_v0.9.md`.

Licenses and third-party notices must be included where package contracts require them. A separate
license archive, benchmark archive, qualification-tool attachment, generic installer, or service
bundle is not required.

### 3.2 Internal evidence artifacts

- exact clean source descriptor and tree digest;
- producer receipt for each public binary/package archive;
- internal conformance/install-qualification tool archive;
- installed runtime report;
- TypeScript package clean-install report;
- Python wheel/sdist clean-install report;
- Rust local-registry clean-consumer report;
- Claude plugin lifecycle report;
- two-agent demo report;
- other demo reports;
- documentation command/link report;
- bounded test/safety report; and
- final Honey evidence ledger.

## 4. Execution rules

- Preserve unrelated user changes. Never reset or discard the current dirty worktree to manufacture
  a clean release candidate.
- Reconcile and commit the intended Honey source before building final artifacts.
- Build final artifacts only from one clean committed tree.
- Use an external owner-only evidence root under canonical `/private/tmp` on macOS.
- Bind all reports to the exact source descriptor and artifact SHA-256.
- Never substitute source tests for installed-artifact checks.
- Never mark an omitted longevity or production gate as passed.
- Do not loosen safety semantics to make a demo pass.
- Do not publish, tag, upload, or otherwise mutate GitHub without explicit owner approval at that
  time.
- Use existing release producers and contracts where possible. Add Honey projections rather than
  weakening the v1 release policy.

## 5. Dependency order

```text
HNY-000 profile and version
  -> HNY-100 clean baseline and protocol freeze
  -> HNY-200 local runtime
  -> HNY-300 two-agent support
  -> HNY-400 TypeScript/Python/Rust/MCP/Claude integrations
  -> HNY-500 docs and demos
  -> HNY-600 artifact producers and assembly
  -> HNY-700 bounded installed qualification
  -> HNY-800 evidence and GitHub prerelease
```

## HNY-000 — Create the reduced Honey authority

Owned paths:

- `packaging/product-version.v1.json`
- new `packaging/honey/`
- `packaging/schemas/`
- `scripts/release/product_version.py`
- new `scripts/release/honey_profile.py`

Tasks:

- [ ] Create `packaging/honey/capability-profile.v1.json` and a strict schema.
- [ ] Record the exact platform, deployment modes, seven services, operation inventory/digest,
      integrations, two-agent profile, artifact set, mandatory gates, and explicit deferrals.
- [ ] Create `packaging/honey/artifact-matrix.v1.json` selecting only the 13 public attachments and
      internal qualification inputs defined above.
- [ ] Create `packaging/honey/release-requirements.v1.json` with a `developer-preview` evidence class
      and prohibited production claims.
- [ ] Add `scripts/release/honey_profile.py generate|check`; require `check` to be non-mutating.
- [ ] Extend `scripts/release/product_version.py` to accept `0.9.0-honey.1` and derive valid
      TypeScript, Python, Rust, plugin, and archive identities.
- [ ] Propagate the Honey identity through workspace crates, TypeScript/Python/Rust SDKs, Claude
      plugin, generated release records, and package contracts using the closed authority script.
- [ ] Preserve `cigar.context.v1`, schema v1 identities, historical fixtures, and beta artifacts.
- [ ] Create a capability ownership ledger mapping every selected surface to implementation, package,
      guide, demo, and fast acceptance test.
- [ ] Add tests rejecting unknown capabilities, duplicate artifacts, operation drift, deferred
      platform leakage, and any true production-support claim.

Exit gate:

- [ ] One non-mutating command verifies Honey version, profile, artifact, and requirement authority
      with zero drift.

## HNY-100 — Freeze a clean baseline

- [ ] Inventory modified, deleted, and untracked files as Honey work, later-v1 work, generated output,
      external evidence, or unrelated user work.
- [ ] Obtain owner direction for overlapping changes; preserve unrelated work.
- [ ] Reconcile all selected generators and run their check modes.
- [ ] Require generated CLI, HTTP/gRPC, MCP, TypeScript, Python, Rust, and protocol surfaces to match the
      authoritative 45-operation/70-payload inventory unless the authority is intentionally updated.
- [ ] Verify service counts remain 6/8/8/6/6/4/7 for Catalog, Context, Space, Handoff, Effect,
      Replay, and Operations.
- [ ] Freeze Honey's protocol compatibility window and unknown-field behavior.
- [ ] Verify retained SQLite migrations and document the oldest supported local state version.
- [ ] Run formatting and focused baseline tests before committing.
- [ ] Create one baseline commit and record commit ID, tree ID, lockfile digests, toolchains, and
      `SOURCE_DATE_EPOCH`.
- [ ] Require a clean `git status --short` before every final producer runs.

Exit gate:

- [ ] Every final producer rejects a changed or dirty source tree and binds the same source
      descriptor.

## HNY-200 — Finish the local runtime

Owned paths: `crates/cigar-cli/`, `crates/cigar-daemon/`, `crates/cigar-api/`, selected catalog,
compiler, policy, retrieval, store, space, effects, and replay crates.

### HNY-210 — CLI and daemon

- [ ] Build `cigar` with default features disabled and the explicit `full` feature enabled.
- [ ] Make the installed full help match `crates/cigar-cli/assets/cigar-help.txt` byte-for-byte.
- [ ] Verify init, source/ingest/catalog, project/focus, context, space, handoff, effect, replay,
      policy, backup, GC, diagnostics, doctor, serve, MCP, plugin, completion, man, and version
      surfaces.
- [ ] Start `cigard` over owner-only Unix-domain IPC with bounded liveness/readiness.
- [ ] Open readiness only after ordered durable recovery.
- [ ] Verify embedded and local-sidecar modes produce canonical equivalent semantic identities.
- [ ] Verify two daemon restart cycles preserve catalog, spaces, handoffs, effects, replay, and
      migration state.
- [ ] Keep loopback API transport explicit and reject unconfigured remote administration.
- [ ] Ensure errors and logs never reveal prompt/source content, credentials, signatures, nonces, or
      raw private paths.

### HNY-220 — Governed context pipeline

- [ ] Verify filesystem and Git discovery/ingestion use explicit roots and preserve ignore,
      symlink, secret-quarantine, immutable-version, and provenance rules.
- [ ] Verify exact/lexical/path/symbol retrieval supports the Honey quickstart with vector retrieval
      disabled.
- [ ] Verify policy filters happen before context inclusion and denial is content-free.
- [ ] Verify plan, compile, manifest, explain, materialize, revalidate, and exact-base delta flows.
- [ ] Run deterministic compile twice across fresh processes and require identical semantic roots.
- [ ] Verify every selected block has provenance and every considered candidate has a disposition.
- [ ] Verify restart and signed backup/create/verify/restore for local state.

### HNY-230 — Effects, evidence, and replay

- [ ] Package only the local filesystem reference effect path as Honey-supported.
- [ ] Require durable intent, current authorization, expected revision, idempotency key, and fence
      before connector invocation.
- [ ] Preserve explicit `UNKNOWN` on ambiguous completion; reject blind retry.
- [ ] Verify reconciliation and linked compensation.
- [ ] Capture task, plan, manifest, bundle, materialization, invocation, policy/index fingerprints,
      observations, evidence, effects, and verification into the final decision root.
- [ ] Keep evidence/invocation reproduction structurally unable to call providers or tools.
- [ ] Keep observational replay recorded-only and no-egress.
- [ ] Keep live comparison unavailable without an explicit non-Honey profile.

Exit gate:

- [ ] The installed runtime completes the offline context, two-agent, effect recovery, and replay
      workflows using only packaged public surfaces.

## HNY-300 — Prove two-agent support

Owned paths: `crates/cigar-space/`, handoff protocol/adapters, telemetry correlation, demo driver,
and multi-agent guide.

- [ ] Define `cigar.honey.two-agent.local.v1` as Agent A plus Agent B under one authoritative local
      daemon.
- [ ] Configure two distinct principals and effective capability sets without deriving authority
      from prompt text.
- [ ] Let Agent A create a parent space/checkpoint and preview the exact accepted/rejected handoff
      scope before signing.
- [ ] Let Agent A create one recipient-bound handoff with task, success criteria, projects,
      capabilities, topics, references, target, bundle, budget, nonce, and expiry.
- [ ] Let Agent B accept under current policy and receive a recipient-specific compiled bundle.
- [ ] Let Agent B work in a private overlay/fork and return a typed `HandoffDelta` with evidence.
- [ ] Let Agent A merge independent changes against the exact base.
- [ ] Demonstrate a same-key divergence produces a typed conflict and requires explicit resolution.
- [ ] Reject recipient mismatch, expired capsule, replayed one-use nonce, revoked capsule, revoked
      ancestor authority, inaccessible reference, stale base, and capability amplification.
- [ ] Restart after acceptance and prove the acceptance, revocation/replay guards, result, and base
      remain authoritative.
- [ ] Route one local reference effect through the shared journal and prove duplicate delivery does
      not produce a second logical mutation.
- [ ] Emit content-safe trace correlation for Agent A, Agent B, task, handoff, result, merge, effect,
      and replay without exporting task/source text.
- [ ] Produce one final evidence root containing typed references to the complete two-agent workflow.

Exit gate:

- [ ] The installed two-agent demo passes twice from clean state with identical semantic roots and
      all negative authority assertions passing.

## HNY-400 — Package TypeScript, Python, Rust, MCP, and Claude Code

### HNY-410 — MCP

- [ ] Preserve exactly ten bounded MCP tools and eight resource families unless the authority is
      intentionally updated.
- [ ] Verify duplicate JSON keys, unknown fields, requests over 256 KiB, invalid output budgets,
      expired result handles, and unknown methods fail closed.
- [ ] Require idempotency keys for every mutation.
- [ ] Preserve cancellation and mark uncertain mutations for inspection rather than retry.
- [ ] Verify degraded mode fabricates no data and effect operations fail closed.
- [ ] Run MCP process tests against the exact installed `cigar` and `cigard` bytes.

### HNY-420 — Python SDK

- [ ] Regenerate Python types/methods and require generator check mode to pass.
- [ ] Map the Honey product identity to a valid PEP 440 package version through the central authority.
- [ ] Build wheel and sdist with fixtures, release record, Context ABI, license, and notices.
- [ ] Validate wheel `RECORD`, sdist inventory, metadata, unsafe paths, duplicate members, and
      version/ABI consistency.
- [ ] Install wheel and sdist separately into clean offline environments.
- [ ] Run the same five-operation semantic workflow from both installations.
- [ ] Add a packaged Agent B handoff example.
- [ ] Verify cancellation, streaming, typed errors, idempotency, and no automatic effect dispatch
      retry.

### HNY-425 — TypeScript SDK

- [ ] Regenerate TypeScript types/methods and require the central client generator check to pass.
- [ ] Build one deterministic npm tarball containing compiled code, declarations, release record,
      Context ABI, fixtures, license, and notices.
- [ ] Validate exact npm package inventory, metadata, dependency pins, unsafe paths, install scripts,
      duplicate members, and Honey version/ABI consistency.
- [ ] Install the exact `.tgz` into a new offline project with lifecycle scripts and network access
      disabled.
- [ ] Run the same five-operation semantic workflow used by Python and Rust and compare the canonical
      semantic bundle digest.
- [ ] Add a packaged TypeScript two-agent observer/example that inspects the handoff and result
      without receiving authority it was not granted.
- [ ] Verify cancellation, streaming, typed errors, idempotency, and no automatic effect dispatch
      retry.

### HNY-430 — Rust SDK

- [ ] Regenerate Rust types/methods and require protocol-vector parity.
- [ ] Build every required unpublished internal crate into a private local registry in dependency
      order.
- [ ] Package the public `cigar-sdk` crate plus the complete local registry, index, checksums,
      configuration template, fixtures, and examples as one Honey kit.
- [ ] Reject a kit missing any transitive dependency or checksum.
- [ ] Create a new consumer outside the repository, configure only the packaged local registry,
      disable network, and run `cargo check`, `cargo test`, and the semantic workflow.
- [ ] Add a packaged Agent A coordinator example.
- [ ] Verify Context ABI/version, cancellation, streaming, typed errors, idempotency, and no automatic
      effect dispatch retry.

### HNY-440 — Claude Code

- [ ] Build the plugin from the exact Honey runtime's `cigar-mcp` and `cigar-claude-hook` bytes.
- [ ] Bind plugin commands to plugin-root executables, never ambient `PATH`.
- [ ] Freeze one exact Claude Code compatibility cohort for the developer preview.
- [ ] Verify install, doctor, schema probes, bounded bootstrap, checkpoint/resume, degraded marker,
      and uninstall using isolated roots.
- [ ] Keep default qualification model-free and network-denied.
- [ ] Retain any paid live smoke as optional, separately reported, and non-blocking.

Exit gate:

- [ ] MCP, TypeScript, Python, Rust, and Claude workflows run from their exact packaged artifacts
      against the installed local daemon.

## HNY-500 — Write user docs and package four demos

### HNY-510 — Documentation

Required documents:

- [ ] `README_HONEY.md`: status, supported platform, five-minute path, artifact verification,
      features, limitations, and links.
- [ ] `docs/guides/honey-install.md`: SHA-256 verification, extraction, PATH, state locations,
      upgrade/backup, Gatekeeper warning for unsigned bytes, and complete uninstall.
- [ ] `docs/guides/honey-quickstart.md`: init, source, ingest, query, plan, compile, explain,
      materialize, provenance, and checkpoint.
- [ ] `docs/guides/honey-two-agent.md`: identities, handoff, acceptance, child work, result, conflict,
      merge, effect, evidence, and trace correlation.
- [ ] `docs/guides/honey-python.md`: install wheel/sdist locally and run quickstart/Agent B example.
- [ ] `docs/guides/honey-typescript.md`: install the GitHub-attached `.tgz` locally and run the
      quickstart/two-agent observer example.
- [ ] `docs/guides/honey-rust.md`: unpack local registry kit and run quickstart/Agent A example.
- [ ] `docs/guides/honey-mcp-claude.md`: MCP configuration, tools/resources, idempotency,
      cancellation, degraded mode, Claude install/doctor/use/uninstall.
- [ ] `docs/guides/honey-effects-replay.md`: effect lifecycle, `UNKNOWN`, reconciliation,
      compensation, evidence replay, observational replay, and live replay limitation.
- [ ] `docs/guides/honey-troubleshooting.md`: doctor, daemon, migration, stale index, denial, MCP,
      plugin mismatch, SDK install, diagnostic bundle, and safe state cleanup.
- [ ] `docs/guides/honey-security-limitations.md`: local-user trust, unsigned/unnotarized artifacts,
      no production support, omitted longevity/scale work, content-safe telemetry, and vulnerability
      reporting.
- [ ] `RELEASE_NOTES_HONEY_v0.9.md`: features, attachment table, upgrade notes, known limitations,
      deferred work, and feedback channel.

Documentation gates:

- [ ] Register executable commands in `docs/commands.v1.json` or label them illustrative.
- [ ] Add Honey pages to `docs/site-manifest.v1.json`.
- [ ] Use only generated artifact filenames and selected capability inventories.
- [ ] Include execution, two-agent, effect-recovery, and evidence/replay diagrams.
- [ ] Distinguish telemetry, durable evidence, provenance, replay, and evaluation.
- [ ] Explain that CIGAR stores typed records and not hidden chain-of-thought.
- [ ] Run deterministic docs build, link checks, artifact-name checks, and installed command checks.

### HNY-520 — Four headline demos

1. **Offline context quickstart**
   - [ ] ingest local sources, plan/compile twice, inspect provenance, explain, materialize, and
         verify deterministic root/delta round trip.
2. **Two-agent handoff**
   - [ ] run the complete Agent A/Agent B flow from HNY-300, including conflict/resolution and final
         evidence root.
3. **Effect recovery and replay**
   - [ ] record durable intent, simulate lost response, recover `UNKNOWN`, restart, reconcile,
         prevent blind retry, compensate, and run no-egress observational replay.
4. **Claude/MCP experience**
   - [ ] install plugin, start daemon, invoke bounded MCP context workflow, checkpoint/resume, inspect
         manifest/evidence, show degraded behavior, and uninstall cleanly.

Demo gates:

- [ ] Keep fixtures deterministic, bounded, network-free, and credential-free.
- [ ] Include prompt-injection and secret-canary assertions in the offline demo or fast safety suite.
- [ ] Include project non-disclosure and handoff authority negatives in the two-agent demo.
- [ ] Add installed-artifact mode to the demo harness.
- [ ] Bind reports to Honey version, source tree, artifact digest, fixture/driver digest, fixed seed,
      evidence class, and assertion results.
- [ ] Run each installed demo twice from clean state and compare semantic identities.
- [ ] Build one strict no-extra-member demo archive.

## HNY-600 — Build and assemble exact artifacts

### HNY-610 — Adapt producers

- [ ] Make `scripts/release/build_archives.py` consume the Honey profile and emit source, docs, and
      combined schema/conformance archives.
- [ ] Make `build_macos_aarch64_archive.py` consume the Honey matrix and build the exact four runtime
      binaries from the clean tree.
- [ ] Make `build_typescript_sdk.py` consume Honey version/profile authority and retain its offline
      clean-consumer workflow.
- [ ] Make `build_python_sdk_artifacts.py` consume Honey version/profile authority.
- [ ] Extend `build_rust_sdk_crate.py` to output the complete local-registry kit rather than an
      unusable lone public crate.
- [ ] Make `build_claude_code_plugin.py` consume exact runtime bytes and Honey authority.
- [ ] Add `build_honey_demos.py` with a strict package contract and receipt.
- [ ] Add or adapt package contracts for Honey filenames, required members, executable identities,
      licenses, internal checksums, and version/ABI records.
- [ ] Make every producer reject dirty/changed source, stale authority digests, unsafe output roots,
      overwrite, path traversal, absolute paths, links, duplicate/colliding names, unsafe modes,
      extra members, and invalid receipts.

### HNY-620 — Build in separate external workspaces

Use the candidate commit epoch and a new owner-only evidence root:

```sh
export SOURCE_DATE_EPOCH=<candidate-commit-epoch>
export HONEY_EVIDENCE_ROOT=/private/tmp/cigar-honey-0.9.0-honey.1
```

- [ ] Build source/docs/schema-conformance archives.
- [ ] Build Apple-silicon runtime archive.
- [ ] Build internal conformance/install-qualification tools.
- [ ] Build TypeScript npm tarball.
- [ ] Build Python wheel and sdist.
- [ ] Build Rust local-registry kit.
- [ ] Build Claude Code plugin.
- [ ] Build demo archive.
- [ ] Record exact host/toolchain identities and producer source digests.

### HNY-630 — Assemble the candidate

- [ ] Add `scripts/release/assemble_honey_release.py`; do not weaken v1 assemblers.
- [ ] Accept explicit producer workspaces and reverify every receipt and package contract.
- [ ] Copy existing bytes without rebuilding during assembly.
- [ ] Produce `honey-release-manifest.json` with filename, artifact ID, type, size, SHA-256, source,
      producer receipt, profile, and evidence status.
- [ ] Produce byte-sorted `SHA256SUMS` for every public attachment except itself.
- [ ] Reject missing, extra, duplicate, renamed, stale, or mismatched artifacts.
- [ ] Mark assembly status `developer-preview`; never reuse the v1 `release-qualified` state.

Exit gate:

- [ ] One immutable candidate directory contains exactly the selected Honey attachments and passes
      independent offline verification.

## HNY-700 — Run bounded functional and safety gates

These are release blockers. They are short functional/safety checks, not the deferred longevity
program.

### HNY-710 — Source and contract checks

- [ ] `cargo fmt --all -- --check`.
- [ ] strict Clippy for Honey-selected targets/features.
- [ ] focused unit/integration tests for catalog, compiler, policy, store, space, handoff, effects,
      replay, API, daemon, CLI, MCP, and Claude hook.
- [ ] generated protocol/operation/TypeScript/Python/Rust parity checks.
- [ ] existing 24-case conformance suite.
- [ ] canonical schema/vector verification.
- [ ] TypeScript, Python, and Rust producer/consumer tests.
- [ ] Honey release-script and verifier tests.

### HNY-720 — Installed-byte checks

- [ ] Verify checksums and contracts before extraction.
- [ ] Install runtime as a standard non-admin user from a path containing spaces and Unicode.
- [ ] Run help/version/schema probes for all four runtime binaries.
- [ ] Run init/ingest/query/compile/materialize/checkpoint workflow.
- [ ] Run daemon readiness plus two restart cycles.
- [ ] Run MCP workflow against installed daemon.
- [ ] Install/test the exact TypeScript `.tgz` from a new offline project.
- [ ] Install/test Python wheel and sdist separately.
- [ ] Install/test Rust local-registry kit from a new consumer directory.
- [ ] Run Claude plugin lifecycle.
- [ ] Run all four installed demos twice.
- [ ] Run backup/create/verify/restore into a new empty target.
- [ ] Uninstall without deleting retained user state unexpectedly.

### HNY-730 — Negative safety checks

- [ ] policy denial remains content-free and existence-hiding;
- [ ] secret and prompt-injection canaries never enter context or telemetry;
- [ ] handoff recipient mismatch, replay, expiry, and revocation fail;
- [ ] child result cannot amplify capability;
- [ ] stale merge base and stale lease fence fail;
- [ ] effect connector is unreachable before durable intent/current authorization;
- [ ] uncertain effect becomes `UNKNOWN`, and blind retry fails;
- [ ] duplicate logical delivery creates no second effect;
- [ ] malformed, oversized, duplicate-key, unknown-field, and cancelled MCP/API requests fail safely;
- [ ] package traversal, links, collisions, unsafe modes, and checksum mismatch fail verification;
- [ ] local defaults do not expose unauthenticated remote administration; and
- [ ] recorded demos and observational replay remain no-egress.

### HNY-740 — Record omitted gates honestly

- [ ] Mark fuzz accumulation, mutation duration, soak, performance/efficacy, full chaos, scale,
      cross-platform, public registry, signing/notarization, and production supply-chain gates
      `not-run-deferred`.
- [ ] Confirm no omitted gate is summarized as passed in human or machine release material.

Exit gate:

- [ ] Every mandatory check passes on the exact candidate bytes, and all deferred gates remain
      visibly deferred.

## HNY-800 — Evidence, release notes, and GitHub prerelease

### HNY-810 — Assemble evidence and offline verifier

- [ ] Create a strict `honey-evidence.json` schema and record source, profile, artifacts, installed
      workflows, integrations, demos, docs, tests, limitations, and deferred gates.
- [ ] Bind every installed result to the exact artifact and source digests.
- [ ] Generate a capability ledger with `specified`, `implemented_source`, `integrated`, `packaged`,
      and `honey_smoke_passed`; keep v1 qualification/support states false.
- [ ] Run license inventory, secret scan, and available offline dependency checks against source and
      final attachments; record tool/database freshness.
- [ ] Include informational SBOMs only when current tooling can produce them reproducibly; label them
      developer-preview evidence.
- [ ] Add `scripts/release/verify_honey_release.py` to validate schemas, inventory, SHA-256, package
      contracts, version/ABI consistency, receipts, prohibited claims, and evidence references
      without network access.
- [ ] Run the verifier from a clean checkout with only candidate bytes, trusted Honey policy, and
      source descriptor available.
- [ ] Obtain maintainer review of release wording, licenses, security limitations, and attachments.

### HNY-820 — Publish only after explicit authorization

- [ ] Tag the exact candidate commit `v0.9.0-honey.1`.
- [ ] Create a GitHub prerelease titled `CIGAR Honey v0.9 — 0.9.0-honey.1`.
- [ ] Upload only manifest-selected attachments.
- [ ] Download every public attachment into a new empty directory and compare filename, size, and
      SHA-256 with the release manifest.
- [ ] Run the offline verifier against downloaded bytes.
- [ ] Follow downloaded install/quickstart/two-agent/TypeScript/Python/Rust/MCP/Claude
      documentation on a clean standard-user Apple-silicon environment.
- [ ] Keep `supported=false` and `production_qualified=false` after publication.
- [ ] Never replace attachment bytes under the same version; withdraw and issue a new prerelease on
      material failure.

Final exit gate:

- [ ] A new user can verify and install the runtime archive, compile context, run the two-agent
      workflow, use TypeScript, Python, or Rust, use MCP/Claude, inspect evidence/replay, and
      uninstall using only downloaded Honey materials.
- [ ] Every public claim matches the bounded developer-preview evidence.

## 6. Recommended execution batches

1. **Authority:** HNY-000.
2. **Clean baseline:** HNY-100.
3. **Local runtime:** HNY-200.
4. **Two-agent behavior:** HNY-300.
5. **Integrations:** HNY-400.
6. **Docs and demos:** HNY-500.
7. **Packaging and assembly:** HNY-600.
8. **Installed qualification:** HNY-700.
9. **Candidate evidence:** HNY-810.
10. **Publication operation:** HNY-820 after owner approval.

Do not combine version propagation, unrelated behavior changes, new producers, and release-evidence
policy changes into one opaque commit.

## 7. Initial repository assessment

The repository already contains most core implementation:

- all 29 post-beta capabilities are marked implemented in source;
- the current conformance result records 24 required cases passed;
- deterministic source/recorded demos exist for context, multi-agent handoff, effect recovery,
  replay, prompt-injection defense, multi-project isolation, and Claude Code;
- spaces, signed handoffs, typed result merge, durable effects, replay, backup, and GC are integrated;
- Apple-silicon runtime, TypeScript, Python, Rust, Claude plugin, docs, package verification, and
  installation producer infrastructure exists; and
- a staged local runtime has previously passed a broad development diagnostic.

The authoritative version is still `1.0.0-dev.1`, the worktree is heavily modified, no Honey
profile exists, and the current official development artifact ledger does not record built/qualified
Honey bytes. The remaining work is therefore release integration and exact-byte proof, not a new
implementation of CIGAR's core protocols.

## 8. Reduced effort estimate

Planning estimate for one persistent implementation agent with maintainer review:

| Work area | Agent-hours | Tokens |
|---|---:|---:|
| Honey authority and clean baseline | 10–24 | 250k–550k |
| Local runtime closure | 10–24 | 250k–550k |
| Two-agent workflow and demo | 8–18 | 200k–450k |
| TypeScript, Python, Rust, MCP, and Claude packaging | 14–32 | 350k–800k |
| Documentation and remaining demos | 10–22 | 250k–550k |
| Producers, assembly, installed gates, evidence | 18–40 | 450k–1.0M |
| **Total** | **70–160** | **1.8M–3.9M** |

Recommended operating budget: **2.9 million tokens**, with review checkpoints after authority,
runtime/two-agent integration, artifact assembly, and installed qualification. The largest variable
is reconciliation of the existing dirty worktree into one clean candidate.
