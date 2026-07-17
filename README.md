# CIGAR

**Context Intelligence Graph Agentic Runtime**

CIGAR is a local-first runtime for giving AI agents governed, reproducible context and explicit
authority over external actions. It turns source material into versioned context artifacts, records
why information was selected or denied, coordinates bounded handoffs between agent principals, and
preserves evidence for audit and replay.

CIGAR sits between source systems and an agent or model runtime. It is not a model, a hosted agent
service, or an autonomous scheduler. It does not request or store hidden chain-of-thought; its
traceability model is based on observable inputs, policies, context, actions, outputs, and receipts.

```text
Filesystem / Git sources
          |
          v
Catalog -> policy and retrieval plan -> deterministic context compiler
                                              |
                                              v
                                  bundle + manifest + provenance
                                              |
                                              v
                                    agent or model consumer

Context spaces and handoffs     Effects and recovery     Evidence and replay
```

## Current state

The checked-in release identity is **CIGAR Honey v0.9**, version `0.9.0-honey.1`.

Honey is a bounded developer preview, not a production release:

- release state: `developer-preview`;
- prerelease: yes;
- published: no;
- supported: no;
- production-qualified: no; and
- artifacts: unsigned and unnotarized.

The release candidate has a closed, checksum-verifiable artifact inventory, but final qualification
evidence is not complete. Treat this repository and any Honey artifacts as evaluation software. Do
not infer release support from the presence of implementation code, tests, packaging logic, or
forward-looking deployment components.

The machine-readable authorities are the source of truth:

- [`packaging/product-version.v1.json`](packaging/product-version.v1.json) — version and publication state;
- [`packaging/honey/capability-profile.v1.json`](packaging/honey/capability-profile.v1.json) — selected capabilities and platform;
- [`packaging/honey/artifact-matrix.v1.json`](packaging/honey/artifact-matrix.v1.json) — exact Honey artifacts; and
- [`packaging/honey/release-requirements.v1.json`](packaging/honey/release-requirements.v1.json) — gates and prohibited claims.

## What CIGAR provides

| Area | Purpose |
|---|---|
| Catalog and ingestion | Observe filesystem and Git sources as versioned context atoms with provenance and lifecycle metadata. |
| Governed context | Plan, compile, explain, materialize, revalidate, and delta-update deterministic context bundles under policy and budget constraints. |
| Policy enforcement | Apply authority and disclosure policy before protected content reaches an agent. |
| Context spaces | Maintain agent working state as checkpoints, immutable bases, private overlays, typed changes, and explicit conflicts. |
| Agent handoffs | Create recipient-bound, attenuated, expiring, one-use handoffs with durable revocation and typed result merging. |
| Recoverable effects | Separate intent, authorization, dispatch, reconciliation, and compensation; preserve `UNKNOWN` when execution cannot be proven. |
| Evidence and replay | Bind decisions and observations to content-addressed evidence; support reproduction and no-egress observational replay. |
| Runtime interfaces | Provide a Rust core, CLI, local daemon, MCP server, Claude Code integration, and Python, TypeScript, and Rust SDK artifacts. |
| Operations | Expose bounded diagnostics, readiness, metrics, correlation identifiers, and content-safe telemetry. |

## Honey v0.9 scope

The selected Honey profile is deliberately narrow:

- Apple-silicon macOS (`aarch64-apple-darwin`);
- embedded and local-sidecar deployment modes;
- one local operating-system user with explicit CIGAR agent principals;
- filesystem and Git ingestion;
- a local filesystem reference effect;
- local CLI, daemon, MCP, and Claude Code workflows;
- Python wheel/source distribution, TypeScript tarball, and an offline Rust local-registry kit; and
- workflows that can run without a model provider or network connection.

Honey does **not** claim Linux, Windows, Intel macOS, remote multi-tenancy, shared PostgreSQL/S3,
containers or Kubernetes, public package registries, Homebrew, HTTPS effects, arbitrary extensions,
live-provider replay, remote OTLP, production support, or general benchmark efficacy. Vector
retrieval is not selected for this profile.

See [Honey security and limitations](docs/guides/honey-security-limitations.md) for the complete trust
boundary and deferred qualification work.

## Repository layout

- `crates/` — Rust protocol, catalog, compiler, policy, space, effects, replay, storage, API, daemon,
  CLI, MCP, and support crates.
- `sdk/` — Python, TypeScript, Rust, and Go SDK source and contract tests. The Go SDK is not selected
  for the Honey artifact profile.
- `adapters/` and `connectors/` — Claude Code and source-system integration code.
- `spec/`, `schemas/`, and `proto/` — versioned operation, payload, schema, and transport contracts.
- `conformance/` — conformance runners, vectors, and install qualification tools.
- `demos/` — deterministic Honey scenarios for context, handoffs, effects, replay, and injection
  defense.
- `packaging/` and `scripts/release/` — fail-closed product authority, artifact producers,
  verifiers, and qualification workflows.
- `docs/` — user guides, reference material, operations guidance, release verification, and design
  documentation.
- `artifacts/` and `reports/` — implementation and test records; these are not automatically release
  evidence for a later source revision.

The broader repository contains work toward CIGAR v1 beyond the Honey profile. Progress is tracked
in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) against [`prd.md`](prd.md). Those planning
documents do not override the narrower machine-readable Honey release authorities.

## Build from source

Install the exact tool versions declared in [`support.toml`](support.toml), then run:

```sh
cargo xtask bootstrap
cargo xtask test unit
```

`bootstrap` validates required tools and generated artifacts; it does not install software or fetch
missing dependencies for you. Tests are expected to remain hermetic and offline.

## Evaluate Honey

Start with:

1. [Honey installation](docs/guides/honey-install.md)
2. [Honey offline quickstart](docs/guides/honey-quickstart.md)
3. [Honey two-agent workflow](docs/guides/honey-two-agent.md)
4. [Honey effects and replay](docs/guides/honey-effects-replay.md)
5. [Honey MCP and Claude Code](docs/guides/honey-mcp-claude.md)
6. [Release verification](docs/release/verification.md)

The complete documentation index is in [`docs/README.md`](docs/README.md), and the artifact-oriented
entry point is [`README_HONEY.md`](README_HONEY.md).

## Security and license

Report vulnerabilities through the private process in [`SECURITY.md`](SECURITY.md). Do not publish
private source, prompts, credentials, handoff capsules, transcripts, or diagnostic archives.

CIGAR is licensed under the terms in [`LICENSE`](LICENSE).
