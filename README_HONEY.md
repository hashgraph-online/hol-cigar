# CIGAR Honey 0.9.4 candidate

CIGAR is an alpha project from [HOL.org](https://hol.org). CIGAR Honey `0.9.4` is a
functional developer preview of CIGAR's local context,
coordination, effect, and replay workflow. It is intended for developers evaluating CIGAR on
Apple-silicon macOS. Honey is not a production-supported or independently audited release.

## Five-minute path

1. Download `SHA256SUMS`,
   `cigar-0.9.4-aarch64-apple-darwin.tar.gz`, and
   `cigar-honey-demos-0.9.4.tar.gz` from the same GitHub prerelease.
2. Verify both archives before opening either one.
3. Extract the runtime into a new user-owned directory and add its `bin` directory to `PATH`.
4. Run `cigar --output json version` and require `0.9.4` and
   `cigar.context.v1`.
5. Run the packaged offline quickstart twice and compare its semantic identity.

<!-- docs-check: illustrative -->
```sh
grep '  cigar-0.9.4-aarch64-apple-darwin.tar.gz$' SHA256SUMS | shasum -a 256 -c -
grep '  cigar-honey-demos-0.9.4.tar.gz$' SHA256SUMS | shasum -a 256 -c -
mkdir -p "$HOME/.local/opt/cigar-honey-0.9.4"
tar -xzf cigar-0.9.4-aarch64-apple-darwin.tar.gz -C "$HOME/.local/opt/cigar-honey-0.9.4"
export PATH="$HOME/.local/opt/cigar-honey-0.9.4/bin:$PATH"
cigar --output json version
```

Detailed installation and verification instructions are in
[the Honey installation guide](docs/guides/honey-install.md). The
[Honey quickstart](docs/guides/honey-quickstart.md) continues from an empty repository.

## Included surfaces

- deterministic filesystem and Git discovery, catalog ingestion, retrieval, context planning,
  compilation, provenance, explanation, materialization, and deltas;
- local context spaces, checkpoints, scoped signed handoffs, typed child results, and optimistic
  merge;
- durable effect intent, approval, dispatch, `UNKNOWN` recovery, reconciliation, and linked
  compensation;
- evidence and observational replay without provider or effect egress;
- `cigar`, `cigard`, `cigar-mcp`, and `cigar-claude-hook`;
- Python wheel/sdist, TypeScript npm tarball, and Rust offline local-registry kit; and
- four installed-artifact demo stories: offline context plus prompt/secret defense, two agents,
  effect recovery/replay, and Claude/MCP.

## Supported Honey profile

Honey supports one local operating-system user, explicitly configured local agent principals,
embedded or local-sidecar execution, and `aarch64-apple-darwin`. The default demos are deterministic,
credential-free, and network-free. The local daemon may expose loopback or Unix-domain transports
for generated clients; that is not a remote-service support claim.

During candidate qualification, the absent-profile default remains `balanced_v3`. Select
`balanced_v4` explicitly to use 0.9.4 risk-aware evidence intake, exact-token marginal-utility
packing, and dense request-scoped ranking state. `balanced_v3` remains the 0.9.3 compatibility
profile, and `balanced_v1` remains the 0.9.2 replay profile.

The release is unsigned and unnotarized. Review the checksum and release manifest before extraction.
The bounded Honey verifier is `scripts/release/verify_honey_release.py` in the exact source archive;
run it against a directory containing all 13 attachments. Its
`passed-artifact-integrity` result is deliberately narrower than signed production verification.
If macOS blocks an executable, use the normal Privacy & Security review flow only after deciding to
trust the exact verified bytes. Do not disable Gatekeeper globally.

## Important limitations

Honey does not claim support for Linux, Windows, Intel macOS, remote multi-tenancy, shared
PostgreSQL/S3 deployment, Kubernetes, OCI, Homebrew, public package registries, live provider replay,
remote OTLP export, arbitrary extensions, or HTTPS effects. Vector retrieval may be absent; exact,
path, symbol, graph, and lexical retrieval remain usable.

The 0.9.4 candidate gate is deliberately bounded. The exact 13-file candidate must pass artifact
integrity, and `hol-cigar==0.9.4` must pass its package contracts, strict metadata checks,
Python 3.14 clean installs, imports, shared fixture, and entry points. Installed-artifact workflow,
upgrade/rollback, reproducibility, long-running fuzz/sanitizer/soak, signing, and notarization gates
are not represented as passed. See
[security and limitations](docs/guides/honey-security-limitations.md).

## Retained testing summary

The independent Hiero Pentest RC cohort ran 50 measured trials for each of five workflows and each
of the 0.9.2, 0.9.3, and 0.9.4 treatments. All 44 evaluated claims passed. Mean exact selected
tokens were 2,251.05, 1,251.78, and 625.40 respectively; 0.9.4 reduced mean internal CIGAR pipeline
latency by 59.627% versus 0.9.3. Completion, blocking/gold/citation coverage, replay, fail-closed
behavior, and all nine negative cases were 100% for 0.9.4.

Read the [full content-free comparison report](docs/release/honey-0.9.4-hiero-three-way-comparison.md).
The measurements are source-bound and recorded-provider only; they do not establish final installed
artifact identity, live-model efficacy, or production qualification.

## Start here

- [Install, verify, upgrade, and uninstall](docs/guides/honey-install.md)
- [Upgrade from Honey 0.9.2 or 0.9.3](docs/guides/honey-0.9.4-upgrade.md)
- [Honey 0.9.4 candidate release notes](RELEASE_NOTES_HONEY_v0.9.4.md)
- [Storage v5 migration, compaction, and telemetry](docs/guides/honey-storage-v5.md)
- [Offline quickstart](docs/guides/honey-quickstart.md)
- [Two-agent coordination](docs/guides/honey-two-agent.md)
- [Python](docs/guides/honey-python.md), [TypeScript](docs/guides/honey-typescript.md), and
  [Rust](docs/guides/honey-rust.md)
- [MCP and Claude Code](docs/guides/honey-mcp-claude.md)
- [Effects and replay](docs/guides/honey-effects-replay.md)
- [Troubleshooting](docs/guides/honey-troubleshooting.md)

Report suspected vulnerabilities through the private process in `SECURITY.md`; do not include
source content, prompts, credentials, handoff capsules, or diagnostic bundles in a public issue.
