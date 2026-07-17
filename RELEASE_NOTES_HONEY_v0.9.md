# CIGAR Honey v0.9 release notes

Version: `0.9.0-honey.1`
Channel: `honey`
State: developer preview
Context ABI: `cigar.context.v1`

Honey is the first bounded CIGAR developer preview intended for installation and hands-on local use.
It packages deterministic context compilation, two-agent handoff, recoverable effects, evidence
replay, MCP/Claude integration, and Python, TypeScript, and Rust SDKs for Apple-silicon macOS.

## Attachments

| Attachment | Purpose |
|---|---|
| `cigar-0.9.0-honey.1-source.tar.gz` | Exact release source |
| `cigar-0.9.0-honey.1-docs.tar.gz` | Version-bound documentation site and Markdown |
| `cigar-0.9.0-honey.1-schemas-conformance.tar.gz` | Protocol schemas, vectors, and conformance inputs |
| `cigar-0.9.0-honey.1-aarch64-apple-darwin.tar.gz` | CLI, daemon, MCP server, Claude hook, man page, and completions |
| `cigar-sdk-0.9.0-honey.1.tgz` | TypeScript ESM SDK |
| `cigar_sdk-0.9.0.dev1-py3-none-any.whl` | Python wheel |
| `cigar_sdk-0.9.0.dev1.tar.gz` | Python source distribution |
| `cigar-rust-sdk-0.9.0-honey.1-local-registry.tar.gz` | Offline Rust registry kit |
| `cigar-claude-code-0.9.0-honey.1.tar.gz` | Claude Code plugin using matching runtime bytes |
| `cigar-honey-demos-0.9.0-honey.1.tar.gz` | Four deterministic installed-artifact demo stories |
| `honey-release-manifest.json` | Exact artifact, source, profile, and evidence inventory |
| `SHA256SUMS` | SHA-256 for every release attachment except itself |
| `RELEASE_NOTES_HONEY_v0.9.md` | This document |

## Highlights

- Governed filesystem and Git ingestion with immutable provenance.
- Deterministic plan, compile, explain, materialize, delta, and checkpoint workflows.
- Recipient-bound, signed, attenuated one-use handoffs between Agent A and Agent B.
- Typed result records, exact-base merge, and durable typed conflicts.
- Durable effect intent, approval, dispatch, `UNKNOWN` reconciliation, and compensation.
- Evidence reproduction, invocation reconstruction, and no-egress observational replay.
- Fixed bounded MCP tool/resource surface and a Claude Code lifecycle integration.
- Clean-consumer artifacts for Python, TypeScript, and Rust.

## Install and upgrade

Verify `SHA256SUMS` before extracting anything and follow `README_HONEY.md`. Honey has no privileged
installer. Install into a versioned user-owned directory. Before moving an existing local state
directory to Honey, create and verify a CIGAR backup. Downgrade and restore always target a distinct
empty directory; in-place state downgrade is blocked.

## Known limitations

Only `aarch64-apple-darwin`, embedded mode, and local-sidecar mode are selected. Archives are unsigned
and unnotarized. Honey does not support remote multi-tenancy, shared service deployment, Homebrew,
containers, public registries, live provider replay, remote OTLP, HTTPS effects, arbitrary
extensions, or production availability/security claims. Vector retrieval may be disabled.

The release includes bounded conformance, installed-byte, safety, canary, and recovery evidence but
not longevity, mutation, soak, large-scale, cross-platform, or efficacy qualification. See
`docs/guides/honey-security-limitations.md` for the exact trust and proof boundaries.

## Feedback

Use the repository discussion/issue channel for content-free product feedback and the private process
in `SECURITY.md` for vulnerabilities. Include the Honey version, attachment SHA-256, platform, and a
minimal reproduction. Never post private source, prompts, credentials, handoff capsules, or raw
diagnostic bundles.
