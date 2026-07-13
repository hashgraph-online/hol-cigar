# CIGAR workspace-metadata beta user guide

This guide applies only to CIGAR `0.1.0-beta.1` under release profile
`cigar.beta.embedded-local.linux-x86_64.v1`. It is a prerelease for Ubuntu 24.04 on x86-64 with
glibc 2.39. It is not a general Linux, server, remote-service, SDK, plugin, or production release.

The beta executable maintains local workspace metadata in a private state directory. It does not
scan or ingest source contents, start a daemon, listen on a network socket, or contact a remote
service. The exact accepted commands and options are printed by `cigar help` and are also preserved
in `crates/cigar-cli/assets/cigar-help-beta.txt` in the documentation archive.

## Basic use

Initialize a workspace and register a source directory:

```text
cigar init /absolute/workspace/path
cigar source add source-id /absolute/source/path
cigar source list
```

Manage local project associations and focus state:

```text
cigar project attach project-id /absolute/project/path
cigar project switch project-id
cigar project link project-id related-project-id
cigar focus switch focus-id
```

Commands that change state support `--dry-run`, `--yes`, and `--non-interactive`. A
`--non-interactive` mutation fails unless it is also confirmed with `--yes`; use `--dry-run` first
when reviewing a change. `--output json` selects machine-readable output for operational commands
and `--explain-config`. Help is always text, while version metadata is always canonical JSON. Use
`--config /absolute/path/to/config.toml` only with a trusted, owner-controlled regular file.
Unknown commands, options, targets, and configuration keys fail closed.

The deadline and Ctrl-C cancel work only before state publication begins. If publication has won
the commit boundary, the command waits for durable settlement and may finish after the requested
deadline rather than report a false cancellation for a visible mutation. Error
`CLI_STATE_COMMIT_UNCERTAIN` (exit 75) means publication may be visible but durable settlement could
not be confirmed. Inspect the current state generation and intended operation before deciding what
to do; do not blindly retry an uncertain mutation.

## Filesystem and security boundary

Run the executable as an unprivileged user. Keep the workspace, configuration, and state directory
owner-controlled and do not replace them with links. The beta writes local metadata only; source
directories are recorded as paths and their contents are not indexed. Back up the state directory
before relying on its metadata, because this prerelease has no supported migration or recovery
guarantee beyond the exact beta profile.

Before extracting or executing the binary, obtain the beta verifier from a separately authenticated
source revision or trusted tool distribution, and obtain the trust policy through an independent
authenticated channel. Do not run a verifier taken only from the unverified candidate. From that
trusted verifier environment, perform the offline complete-set check:

```text
python3 scripts/release/beta_release.py verify --release /absolute/release-directory --trust-policy /absolute/beta-trust-policy.json --openssl /absolute/pinned/openssl
```

The command must report a passed final verification bound to the exact release directory and trust
policy before extraction. A checksum without a trusted beta signature does not authenticate a
download.

Report security concerns privately through the verified reporting channel named in the
authenticated release announcement. Do not publish exploit details, credentials, private paths, or
other sensitive evidence in a public issue.

## Explicitly unavailable surfaces

The beta does not include daemon, MCP, HTTP/gRPC service, remote/shared execution, catalog ingest or
query, retrieval, context compilation, effects, extensions, plugins, SDKs, installers, completion
generation, manual-page generation, macOS, Windows, ARM, backup, garbage collection, or diagnostic
bundle capabilities. The machine-readable capability policy in the documentation archive is the
authoritative closed list.
