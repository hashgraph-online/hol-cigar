# cigar-cli

`cigar` is the terminal boundary for the frozen CIGAR v1 operation contract. API-backed commands compile strict JSON into canonical CBOR, preserve the generated operation ID, and dispatch through one of three explicit targets:

- `embedded` composes the production daemon without listeners, derives the local identity from the configured project directory, calls the exact governed service facade, and performs ordered shutdown.
- `local` uses a permission-restricted Unix socket or Windows named pipe. A loopback HTTP fallback is accepted only with a permission-restricted bearer-token file.
- `remote` requires HTTPS and reads authorization from a file. Redirects, ambient proxies, URL credentials, and insecure remote HTTP are rejected.

The complete command list is available with `cigar help` and in `man/cigar.1`. Shell completion is emitted by `cigar completion bash|zsh|fish`.

## Build profiles

The default `full` feature preserves the complete CLI described below. The initial beta is a
separate compile-time composition and must be built without default features:

```console
cargo build --release -p cigar-cli --no-default-features --features beta-embedded
```

`full` and `beta-embedded` are mutually exclusive, and selecting both or neither fails at compile
time. This beta is a workspace-metadata administration preview, not the complete embedded CIGAR
runtime. The beta binary contains only `init`, source add/list/remove, project
list/attach/detach/switch/link/unlink, focus switch/close, help, and version. Those commands operate
in-process against owner-only embedded state. The daemon, network targets, shared storage, effects,
extensions, protocol operations, source discovery/ingest, catalog/index/retrieval, context
planning/compilation, spaces/handoffs/replay, vector retrieval, MCP, plugins, completion/man
generation, and their flags are not compiled into that binary. Adding a source records only a local
metadata reference; it does not inspect or ingest the directory. Its exact user-facing surface is frozen in
`assets/cigar-help-beta.txt`, and `cigar version` reports `0.1.0-beta.1`.
The release profile qualifies this binary only for `x86_64-unknown-linux-gnu`; successful source
compilation on another host is not a support claim. Embedded state uses owner-only files and a
directory lock so concurrent beta processes cannot lose read-modify-write updates.

An explicit beta configuration is intentionally smaller than the full configuration:

```toml
schema_version = 1
target = "embedded"
project_state_directory = "/absolute/project/.cigar"
```

Unknown fields and any target other than `embedded` fail closed.

## Configuration

CLI configuration precedence is compiled defaults, `/etc/cigar/cli.toml`, user configuration, project `.cigar/cli.toml`, explicit `--config`, `CIGAR_*` environment overrides, then CLI flags. `--explain-config` reports the winning source for every field and redacts authorization material. Because project configuration is loaded implicitly, it cannot select a credential file or retarget an inherited credential; using a project-sourced HTTP endpoint with authorization requires an explicit config, environment, or CLI credential override.

```toml
schema_version = 1
target = "embedded"
daemon_config = "/absolute/path/to/cigard.toml"
project_state_directory = "/absolute/project/.cigar"
```

For local IPC, select exactly one of `local_socket`, `windows_named_pipe`, or `local_endpoint`. `local_endpoint` additionally requires `authorization_file`. Remote endpoints must be HTTPS.

## Operation input and safety

POST operations accept a bounded duplicate-key-free JSON document with `--input`. Path resource IDs remain positional and are reconciled with any duplicate field in the document. Mutations receive a random idempotency key unless `--idempotency-key` is supplied; optimistic operations require `--expected-revision`.

Every mutation supports `--dry-run`. A committing mutation requires `--yes` or a positive terminal confirmation. `--non-interactive` never prompts and rejects an unconfirmed mutation. Dropping or interrupting a request cancels the client operation; effect retries still require inspection and reconciliation according to the public error remediation.

JSON output is one versioned line on stdout. Human progress appears only on an interactive stderr and is disabled by `--quiet`; text remains meaningful without color or Unicode. Configuration credentials are accepted only through bounded regular files and never appear in output or debug formatting.

Administrative source/project/focus state is written atomically beneath `project_state_directory`.

`cigar backup create <archive>` uses the explicit local daemon configuration to take a consistent SQLite snapshot, inventory encrypted blobs and key references, sign the canonical manifest with the single unambiguous active production operator, and verify the published archive. `cigar backup verify <archive>` performs offline signature, checksum, schema, revision, and database-integrity checks against the signer identity embedded in the archive. Retired signing keys remain valid for signatures made during their active lifetime, while current principal and key revocations fail closed. `cigar backup restore <archive> <empty-target>` applies the same current trust policy, verifies first, and atomically restores only into a nonexistent or exactly empty target.

`cigar gc plan` evaluates repository-owned live roots and reports tenant-qualified encrypted-blob candidates plus retention, legal-hold, and backup blockers. `cigar gc run` requires `--yes` and a strict input document such as:

```json
{"schema_version":"cigar.gc-policy.v1","retention_satisfied":true,"legal_hold":false,"backup_complete":true,"max_files":1000}
```

`cigar doctor --security` checks the protected production configuration, key and signing
authority, policy and connector registries, SQLite structure and migration ledger, and encrypted
storage roots. `cigar doctor --deep` additionally validates every retained state checksum, current
semantic record, context/effect journal chain, exact SQL and FTS projection, and every
metadata-referenced encrypted blob. Blob verification is read-only: corruption is reported without
repairing or quarantining the object.

`cigar diagnostics bundle <archive.tar> --yes` writes a deterministic, no-clobber USTAR support
archive. The archive contains only bounded build, platform, configuration-presence, capacity,
integrity-count, and digest inventory metadata; it excludes configured paths, identities,
credentials, source/catalog content, and blob plaintext. Use `--dry-run` to validate the same deep
checks and preview the archive digest without creating a file.

Production effect listing and policy checking read the explicitly configured local production store/profile; they are not aliases for diagnostics or configuration APIs and are unavailable over a remote surface that lacks an operation route. A command with no distinct public or durable implementation fails with `CLI_UNSUPPORTED_SURFACE` instead of borrowing another operation's identifier.
