# CLI reference

The complete generated command list is in `crates/cigar-cli/assets/cigar-help.txt` and the packaged
manual page. Core groups are source, context, project, focus, space, handoff, effect, replay, policy,
backup, migration, revision compaction, integrity, garbage collection, diagnostics, daemon/MCP
service, plugin, and release verification.

Machine output is one `cigar.cli.output.v1` JSON object on stdout. Progress is restricted to an
interactive stderr and disabled by `--quiet`. Use `--authorization-file`; credentials in arguments,
URLs, project configuration, or debug output are rejected. Mutations require `--yes` unless
`--dry-run` is supplied, and `--non-interactive` never invents confirmation.

Targets are explicit: `--embedded`, `--local`, or `--remote URL`. Configuration precedence is
compiled defaults, system, user, project, explicit configuration, environment, then CLI flags.
`--explain-config` shows the winning source while redacting authorization material.
An authorization file is mandatory for remote HTTPS and authenticated loopback TCP targets;
embedded and owner-private IPC targets reject one instead of silently discarding it. Request input,
idempotency, expected-revision, and pagination flags are likewise rejected unless the selected
command has an exact consumer for that metadata.

The full-profile `--embedded` target is the offline governed application boundary, not an in-memory
or permissive fallback. It requires an explicit strict local production configuration, composes the
same durable SQLite/blob/policy/authority/source repositories used by the service, opens no
listener, invokes the frozen `ProductionFacade`, and shuts down after the command. Approved-source
discovery and status use `source refresh`/`source inspect`; publication uses `ingest`; authorized
metadata retrieval uses `catalog query`; deterministic context operations use `context plan`,
`compile`, `explain`, `diff`, `revalidate`, and `materialize`. Separate invocations reopen the same
durable state, so idempotency, retained plan/bundle/manifest identity, revalidation, and
materialization survive process restart.

Local `cigar backup create <archive> --yes` emits a signed format-two archive containing the
consistent SQLite database, encrypted blob inventory, and exact external monotonic effect
checkpoint. `backup verify` checks the current signer/key trust policy and then proves that the
checkpoint is a complete one-to-one semantic match for the protected effect records in the backup
database. `backup restore <archive> <empty-target> --yes` accepts only a nonexistent or exactly
empty target and requires the archived checkpoint to equal the current external checkpoint before
holding its lock through restore. Older/newer/substituted checkpoint state and legacy format-one
archives fail closed; restore never changes the live checkpoint and does not activate the target.

SQLite v5 maintenance is local and explicit. Migration constructs and activates only a verified
distinct target; revision compaction uses a separate signed preview/receipt and retains its source.
`cigar integrity deep <v5-database.sqlite3> --yes` checks retained history and writes a signed
verified-prefix sidecar so later checks can authenticate only a new suffix. `--force-full` ignores
that prefix and verifies every retained checkpoint and delta again. Ordinary readiness never uses
the full-history path: it authenticates the latest checkpoint and its bounded delta suffix, then
verifies or recovers only the current projection and revision anchor.

Local garbage collection is a signed two-step workflow. `cigar gc plan <new-plan.json> --yes`
creates an owner-private no-clobber document binding the current SQLite revision, exact ordered
candidate set and root, maximum candidate count, and retention/legal-hold/backup decisions.
`cigar gc run <plan.json> --yes` revalidates the current operator/key trust policy and rejects a
changed revision or any same-revision physical candidate drift before the first deletion. It then
durably records the exact database-and-plan execution boundary and deletes only the signed set. A
retry accepts an already-absent signed candidate only with that exact durable marker; any newly
visible orphan remains untouched. Legacy direct store GC remains preview-only; destructive calls
without opaque verified-plan evidence fail closed.

Ingestion retries only bounded optimistic-store conflicts and revalidates the retained discovery
plan before every publication attempt; a changed source still fails closed. Strong retrieval pins
the requesting tenant's latest catalog causal revision (`catalog.committed` or
`catalog.atom-tombstoned`), while writes continue to use the global store revision for compare and
swap. Unrelated service/idempotency records therefore cannot manufacture a permanently stale index,
and catalog commits cannot be skipped.

The macOS source-tree process qualification executes the full sequence as independent `cigar`
processes, including restart-safe idempotent replay, content-free denial, deterministic semantic
identities, provenance, materialization, and a distinct exact-base delta, without binding the
configured socket. This is not installed-archive evidence; installed-byte qualification remains a
separate release gate.

The initial `beta-embedded` artifact remains a different compile-time composition. It has no
catalog, context, policy, daemon, transport, effect, or plugin dependency or command, and its frozen
help/capability profile is not widened by the full-profile route wiring.

`cigar release verify <directory>` is the installed-binary offline gate. It must fail if any required
artifact, evidence receipt, SBOM, provenance statement, checksum, or detached signature is missing or
changed.
