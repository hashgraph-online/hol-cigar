# Deterministic demo execution harness

Each of the seven directories contains a digest-bound manifest and fixture plus
an explicit `driver.py`. The runner verifies the fixture, builds the public
product executables offline, materializes the declared scenario in an isolated
home, executes the driver and mapped product tests, performs teardown, bounds
and spools every subprocess output, and scans output, state, and records for all
registered canaries. On macOS, recorded drivers run under a `sandbox-exec`
profile that permits loopback and denies other networking. On a platform where
an OS no-egress boundary is unavailable, the record says `unavailable`; proxy
variables alone are never reported as no-egress enforcement.

Driver evidence has three grades:

- `product_observed`: the fixture step or assertion was observed through a
  public CIGAR surface.
- `fixture_observed`: the executable fixture driver observed it, while the
  matching product invariant is covered separately by the mapped product test.
- `not_observed`: the fixture-specific product behavior is still absent.

`release_demo_qualified` becomes true only when every setup and teardown step
ran, every flow and assertion is `product_observed`, and every mapped product
check passed under an enforced OS no-egress boundary. A partial driver or a
platform without that boundary cannot promote component evidence into a release
pass.

Every recorded scenario now executes its complete declared fixture flow through
a public product surface. The Claude Code scenario uses the public plugin, hook,
and MCP processes with a deterministic backend. The other six use the source
CLI or Python SDK against a bounded loopback recorded API. That API accepts only
the exact ordered operation, method, path, authorization, revision,
idempotency key, path binding, and canonical request payload declared by the
fixture; any difference fails closed. Contract-shaped responses then let the
real client transport complete without external services.

The resulting source-demo coverage includes offline ingest/plan/compile/delta,
multi-project focus creation, typed handoff results and merges, effect unknown
state and reconciliation, separate evidence/observational/live replay jobs, and
hostile-document ingest through governed materialization. The hostile-document
fixture places its registered canary inside untrusted source bytes and removes
all fixture state before the runner performs its final tree scan.

This qualification scope is deliberately narrower than installed-artifact or
live-service qualification. Recorded loopback orchestration proves the public
source client and fixture workflow, while the mapped product tests prove the
owning kernels. It does not claim that release archives were installed or that a
shared deployment was exercised; those remain separate release receipts.

Run all recorded scenarios and mapped checks:

```sh
python3 demos/run.py --output-dir reports/demos
```

Run one CI smoke scenario:

```sh
python3 demos/run.py \
  --scenario effect-crash-recovery \
  --output-dir reports/demos
```

For protected evidence, select one canonical absolute external directory and
keep `--output-dir` relative. Records and the run summary are then published
create-new at mode `0400`; selector conflicts, repository-local destinations,
unsafe traversal, aliases, and overwrite fail closed. Child product processes
do not inherit the evidence selector.

```sh
export CIGAR_EVIDENCE_DIR=/private/path/to/new-cigar-evidence
python3 demos/run.py --validate-only --output-dir demos/validation
```

`--validate-only` verifies the inventory, manifests, fixture digests, seeds, and
canary bindings without running drivers or product assertions. `--live` is
accepted only for a demo that explicitly declares a live check and all of its
required environment variables; the optional live result remains separate from
the deterministic recorded driver.

The Claude Code scenario includes an explicit paid live smoke. It requires an
installed `claude`, `ANTHROPIC_API_KEY`, and a pinned
`CIGAR_CLAUDE_LIVE_MODEL`; caps spend at USD 0.10, disables tools and session
persistence, and never writes model or credential content to its demo record:

```sh
python3 demos/run.py --scenario claude-code-experience --live \
  --output-dir reports/demos-live
```

The inventory is:

- `offline-context-compiler`
- `multi-project-isolation`
- `multi-agent-handoff`
- `effect-crash-recovery`
- `cross-runtime-replay`
- `prompt-injection-defense`
- `claude-code-experience`

## SDK quickstarts

The Rust, TypeScript, Python, and Go source examples execute the same recorded
five-operation workflow: source discovery, catalog ingest, context planning,
bundle compilation, and manifest inspection. Every runtime must print the same
fixture-bound bundle identity:

```sh
python3 demos/sdk-clients/run.py --output reports/demos/sdk-quickstarts.json
```

The SDK and installed-artifact drivers accept the same `--evidence-dir` or
`CIGAR_EVIDENCE_DIR` selector. When selected, `--output` is a safe relative path
inside that external workspace and is canonical, private, read-only, and
create-new. With no explicit SDK `--output`, protected mode uses
`demos/sdk-quickstarts.json`.

The source report uses
`qualification_scope: recorded-ingest-compile-manifest` and sets
`sdk_workflow_qualified: true` only when all four runtimes pass the exact
operation sequence and identities. It remains distinct from package release
qualification: `installed_artifact_qualified` and `release_qualified` remain
false until the clean installed-artifact run passes. The source runner disables
live endpoints and package-network resolution. The installed-artifact driver
takes an already built native binary and four SDK distribution archives,
installs each into a clean temporary root, and never falls back to source:

```sh
python3 demos/installed_artifact_test.py \
  --cigar-binary dist/bin/cigar \
  --expected-version 1.0.0-dev.1 \
  --rust-archive dist/sdk/cigar-sdk-1.0.0-dev.1.crate \
  --cargo-home dist/offline/cargo-home \
  --rustup-home dist/offline/rustup-home \
  --typescript-tarball dist/sdk/cigar-sdk-1.0.0-dev.1.tgz \
  --pnpm-store dist/offline/pnpm-store \
  --python-wheel dist/sdk/cigar_sdk-1.0.0.dev1-py3-none-any.whl \
  --python-wheelhouse dist/sdk/wheelhouse \
  --go-archive dist/sdk/cigar-go-sdk-1.0.0-dev.1.tar.gz \
  --go-mod-cache dist/offline/go-mod-cache \
  --output reports/demos/installed-artifacts.json
```

The installed-artifact driver rejects symlinks, hard links, special files,
absolute paths, traversal, oversized archives, dependency downloads, unexpected
versions, and cross-SDK identity differences. Its native probe runs the installed
binary's version, init, source-add, and source-list public surfaces in a fresh
project. A full clean-package run additionally requires the release SDK archives
and their complete explicit Cargo/Rustup, pnpm, Python wheelhouse, and Go module
stores; those artifacts are not checked into this source tree.
