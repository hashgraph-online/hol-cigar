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

### Frozen beta-state inspection and transition

The full CLI can validate an owner-only `0.1.0-beta.1` `state.json` without importing it:

```console
cigar state inspect-beta /absolute/path/to/state.json --local --output json
```

This command accepts exactly one bounded regular file, rejects symlinks, hard links, unsafe
permissions, duplicate JSON keys, unknown fields, malformed identifiers, unsafe stored paths, and
invalid project links. Its content-free result binds the exact input with SHA-256 and reports only
the generation and entry counts; it never emits stored identifiers or paths and never writes the
input.

On macOS, an operator can explicitly import those administrative records into a new full-only state
directory. The configured `project_state_directory` and backup directory must not exist, and both
parents must pass the owner and no-symlink checks. Review with `--dry-run`, then commit with `--yes`:

```console
cigar state import-beta /absolute/beta/state.json /absolute/new-transition-backup \
  --config /absolute/cli.toml --local --dry-run
cigar state import-beta /absolute/beta/state.json /absolute/new-transition-backup \
  --config /absolute/cli.toml --local --yes
```

Import first atomically publishes an owner-private backup containing the exact source bytes and a
content-free manifest, synchronizes it, reopens it without following symlinks, and verifies every
digest and semantic count. Only then does it atomically publish the new state directory. The target
uses `cigar.cli-administration.imported-beta.v1`, so the frozen beta decoder rejects in-place reuse;
identifiers, paths, links, active selections, and generation are otherwise preserved exactly.
Retries succeed only when the already-published backup and target are byte-identical.

Recovery verifies the backup again and restores the exact beta bytes only into a distinct new empty
directory. It never rewrites the configured active full directory:

```console
cigar state restore-beta /absolute/new-transition-backup /absolute/new-beta-recovery \
  --config /absolute/cli.toml --local --yes
```

Transition output is content-free and does not contain any supplied path or stored identifier.
Abandoned random staging directories from an actual process or machine crash are never trusted or
automatically executed; operators may remove them after confirming they are not a final backup or
state directory. This source-tested boundary does not claim installed crash/power-loss qualification.

## Configuration

CLI configuration precedence is compiled defaults, `/etc/cigar/cli.toml`, user configuration, project `.cigar/cli.toml`, explicit `--config`, `CIGAR_*` environment overrides, then CLI flags. `--explain-config` reports the winning source for every field and redacts authorization material. Because project configuration is loaded implicitly, it cannot select a credential file or retarget an inherited credential; using a project-sourced HTTP endpoint with authorization requires an explicit config, environment, or CLI credential override.

```toml
schema_version = 1
target = "embedded"
daemon_config = "/absolute/path/to/cigard.toml"
project_state_directory = "/absolute/project/.cigar"
```

For local IPC, select exactly one of `local_socket`, `windows_named_pipe`, or `local_endpoint`. `local_endpoint` additionally requires `authorization_file`. Remote endpoints require both HTTPS and an explicit `authorization_file`.

## Governed full-profile embedded workflow

The default `full` build can execute the local catalog and context pipeline without starting
`cigard` or opening a socket. Select `target = "embedded"` and provide an explicit validated local
daemon configuration. That production configuration—not `cigar source add`—owns the approved
filesystem/Git source registry, tenant/project authority, protected policy, encrypted keystore,
SQLite database, and blob roots. Every command reconstructs the production application over the
same durable state, invokes the frozen operation through `ProductionFacade`, then performs ordered
shutdown.

The offline sequence is:

1. `cigar source refresh --input discover.json` previews an already approved source and returns the
   exact `plan_digest` without returning source contents.
2. `cigar ingest --input ingest.json --yes` binds that digest, rechecks the source snapshot, and
   atomically publishes atoms, provenance, lineage, and index work.
3. `cigar catalog query --input query.json` returns authorized version identities only.
4. `cigar context plan --input plan.json --dry-run` previews a deterministic governed plan; repeat
   with `--yes` to persist its bundle and manifest.
5. `cigar context compile`, `explain`, `revalidate`, `materialize`, and `diff` consume retained exact
   identities. Each state-changing operation accepts an explicit idempotency key for restart-safe
   replay.

Ingestion handles only bounded internal compare-and-swap conflicts, rechecking the retained
discovery plan on every attempt. Strong reads use the tenant's catalog outbox causal watermark
rather than unrelated global service-record revisions, while all writes still compare against the
global store revision. The macOS source-tree process test runs this sequence in separate processes,
checks content-free policy denial and provenance, and proves that embedded mode never binds the
configured socket. Packaged installed-byte qualification remains a separate open release gate.

Operation inputs are the strict generated request DTOs documented by the JSON schemas. The embedded
target accepts no endpoint or authorization file, performs no remote fetch, and opens no listener.
An authority or policy denial occurs before catalog-derived body reads and is returned as a stable,
content-free public error. This full-profile workflow does not change the separately compiled
`beta-embedded` command table, help text, dependency graph, or capability policy.

## Operation input and safety

POST operations accept a bounded duplicate-key-free JSON document with `--input`. Path resource IDs remain positional and are reconciled with any duplicate field in the document. Mutations receive a random idempotency key unless `--idempotency-key` is supplied; optimistic operations require `--expected-revision`.

Every mutation supports `--dry-run`. A committing mutation requires `--yes` or a positive terminal confirmation. `--non-interactive` never prompts and rejects an unconfirmed mutation. Dropping or interrupting a request cancels the client operation; effect retries still require inspection and reconciliation according to the public error remediation.

JSON output is one versioned line on stdout. Human progress appears only on an interactive stderr and is disabled by `--quiet`; text remains meaningful without color or Unicode. Configuration credentials are accepted only through bounded regular files and never appear in output or debug formatting.

Administrative source/project/focus state is written atomically beneath `project_state_directory`.

`cigar backup create <archive>` uses the explicit local daemon configuration to take a consistent SQLite snapshot, inventory encrypted blobs and key references, and capture the external monotonic effect checkpoint while the SQLite writer exclusion and checkpoint lock are both held. The single unambiguous active production operator signs the complete format-two inventory, and the command verifies both cryptographic integrity and the exact one-to-one database/checkpoint relationship after publication. `cigar backup verify <archive>` repeats those checks against current trust policy. Retired signing keys remain valid for signatures made during their active lifetime, while current principal and key revocations fail closed. `cigar backup restore <archive> <empty-target>` verifies first, requires the archived checkpoint to equal current external truth exactly, holds that lock through restore, and atomically restores only into a nonexistent or exactly empty target. It rejects legacy format-one, newer, older, or substituted checkpoint state and never rewrites the live checkpoint; stop effect writers before activating the recovery target.

`cigar migration preflight <absolute-v4-source.sqlite3> <absolute-verified-backup> <absolute-new-v5-target.sqlite3>` is a read-only local offline preview. It re-verifies the signed format-two backup, authenticates the frozen v4 revision range and roots, hashes the exact source database, rejects aliases/symlinks/unsafe modes or an existing target, and checks a conservative no-compression free-space formula.

`cigar migration run <absolute-v4-source.sqlite3> <absolute-verified-backup> <absolute-new-v5-target.sqlite3> --yes` repeats preflight under an exclusive runtime lock, constructs and verifies the distinct v5 target, retains the v4 source, and writes a signed `<target>.cigar-migration-receipt.json`. It does not activate the target.

`cigar migration activate <absolute-v4-source.sqlite3> <absolute-verified-backup> <absolute-v5-target.sqlite3> <absolute-signed-receipt.json> <absolute-active-store.json> --yes` reauthenticates every migration binding under exclusive source and target locks, atomically replaces the owner-only checksum-protected descriptor, fsyncs its directory, and verifies a read-only v5 reopen through that descriptor. The v4 source and backup remain untouched.

`cigar migration cleanup <absolute-v4-source.sqlite3> <absolute-verified-backup> <absolute-incomplete-v5-target.sqlite3> <absolute-active-store.json> --yes` is the explicit interrupted-run cleanup path. It rejects a receipted or active target, reauthenticates the retained source and backup, and removes only the named target plus its closed sidecar set before proving the source bytes are unchanged.

`cigar compaction preview <absolute-v5-source.sqlite3> <absolute-migration-receipt.json> <absolute-new-target.sqlite3> <absolute-active-store.json> <absolute-new-preview.json> --yes` writes a 15-minute signed authorization bound to exact database, backup, descriptor, head, policy, pin, candidate, retained-range, and byte-estimate evidence. `cigar compaction execute <absolute-signed-preview.json> --yes` rejects any drift, constructs and verifies a distinct compacted target, emits a separate signed receipt, and atomically advances the descriptor while retaining the prior database. `cigar compaction status <absolute-active-store.json>` verifies the descriptor without running maintenance. These surfaces never invoke blob GC.

`cigar integrity deep <absolute-v5-database.sqlite3> --yes` runs the explicit retained-history verifier and publishes an owner-only purpose-signed `.cigar-verified-prefix.json` sidecar. A later run reuses that prefix only when its signature, database device/inode, retained origin, prefix chain head, policy digest, and verifier version remain valid; it then checks only the authenticated suffix plus the current projection. Add `--force-full` to ignore or replace the sidecar and authenticate every retained checkpoint and delta again. Ordinary v5 readiness uses only the latest checkpoint and its bounded delta suffix.

`cigar gc plan <new-plan.json> --input <gc-policy.json> --yes` evaluates repository-owned live roots under a locked SQLite revision and creates an owner-private, no-clobber signed plan. The signature binds the exact ordered tenant-qualified candidate set, candidate root, repository revision, file bound, retention decision, legal-hold decision, and backup-completeness decision. `cigar gc run <plan.json> --yes` verifies the current production trust policy, rejects a stale revision or any same-revision candidate drift before the first deletion, durably marks the exact database-and-plan execution boundary, and deletes only the authenticated candidates. Interrupted retries require that exact owner-private marker; newly discovered orphans are never substituted into the signed set. A policy document has this strict form:

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
