# Operator runbooks

Run every exercise against the exact installed candidate in an isolated environment and store only
content-free receipts. Static validation checks that the procedures and stop conditions exist; it is
not a substitute for live execution.

- [Backup and restore](../runbooks/shared-backup-restore.md)
- [Daemon start, stop, and readiness](daemon-lifecycle.md)
- [Socket, TLS, and OIDC](transport-identity.md)
- [Key creation and custody](key-management.md)
- [Key rotation](key-rotation.md)
- [Rolling migration](../runbooks/shared-rolling-migration.md)
- [Index rebuild](index-rebuild.md)
- [Capacity scaling and high queue age](capacity-and-queue-age.md)
- [Unknown effect](unknown-effect.md)
- [Journal quarantine](journal-quarantine.md)
- [Blob corruption](blob-corruption.md)
- [Revocation propagation](revocation-propagation.md)
- [Degraded compiler](degraded-compiler.md)
- [SDK compatibility](sdk-compatibility.md)
- [Adapter disable](adapter-disable.md)
- [Local storage recovery](../runbooks/local-storage-recovery.md)
- [Shared deployment](../runbooks/shared-deployment.md)

<!-- docs-check: command runbook-live -->
```sh
python3 scripts/release/exercise_runbooks.py --mode live \
  --candidate-manifest dist/build-manifest.json \
  --driver-directory /approved/cigar-runbook-drivers \
  --out dist/evidence/operations
```

The release build manifest is used here because operation evidence is an input to the later
`release-evidence.json` assembly; pointing this step at the final evidence file would create a
circular dependency. Before invoking any driver, the orchestrator requires a release-state artifact
matrix, a committed clean source, the complete matrix artifact set, and matching artifact bytes,
digests, sizes, filenames, and contract bindings. Each live driver must validate preconditions,
exercise the failure and recovery path, assert semantic and integrity outcomes, and emit a bounded
content-free receipt bound to the candidate revision and complete artifact-ID set. The environment
must enforce isolation and set
`CIGAR_OPERATION_SANDBOX_ENFORCED=1`; this variable records an external control and does not create
the sandbox. The orchestrator stages each self-contained driver, records its SHA-256, rejects driver
or candidate-manifest mutation, and adds those bindings to every receipt. The release evidence
signature subsequently binds the summary and receipt digests.
