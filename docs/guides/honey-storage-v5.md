# Honey 0.9.1 storage migration and maintenance

Honey 0.9.1 uses SQLite repository format v5: ordinary revisions are authenticated typed deltas,
with bounded checkpoints for restart and exact-revision reconstruction. These are local offline
administration commands, not new v1 API operations. Atomic context compilation and remote retention
administration remain future proposals.

## Migrate v4 into a distinct target

Stop `cigard` and verify a complete signed backup first. Keep the v4 database, backup, v5 target,
activation descriptor, and receipts at separate canonical owner-private paths. The target must be
new and empty; migration never rewrites the v4 source.

`migration preflight` authenticates the source and backup and reports `source_database_bytes`,
`required_available_bytes`, `observed_available_bytes`, revision range, and capacity profile. There
is no safe universal duration estimate: time the same generated/copied workload on the intended
hardware and reserve a maintenance window longer than that observation. Do not run when available
space is below the reported requirement.

<!-- docs-check: illustrative -->
```sh
cigar migration preflight /absolute/state-v4.sqlite3 /absolute/verified-backup /absolute/state-v5.sqlite3
cigar migration run /absolute/state-v4.sqlite3 /absolute/verified-backup /absolute/state-v5.sqlite3 --yes
cigar integrity deep /absolute/state-v5.sqlite3 --force-full --yes
cigar migration activate /absolute/state/state-v4.sqlite3 /absolute/verified-backup /absolute/state/state-v5.sqlite3 /absolute/state/state-v5.sqlite3.cigar-migration-receipt.json /absolute/state/active-store.json --yes
cigar compaction status /absolute/state/active-store.json
```

Activation is allowed only after every retained revision/root, projection, signed migration receipt,
effect checkpoint, and revision anchor verifies. An interrupted run resumes its signed operation or
leaves v4 active. Keep v4 untouched until the new target has restarted and passed deep integrity.

Rollback does not open v5 with a v4 binary. Stop the daemon and restore the verified pre-migration
backup into another distinct empty target, verify it, and explicitly activate that target. Never
copy only a live database/WAL pair or downgrade in place.

## Select v5 for the local daemon

Keep `metadata_database` bound to the retained v4 source and add the owner-only descriptor emitted
by `migration activate`. Both the descriptor and every target it selects must remain under the
configured `state_directory`.

<!-- docs-check: illustrative -->
```toml
[production]
metadata_database = "/absolute/state/state-v4.sqlite3"
active_store_descriptor = "/absolute/state/active-store.json"
```

Restart `cigard` only after activation succeeds. With this field present, local startup verifies
the descriptor, opens only its activated v5 target, authenticates bounded replay and the catalog
projection, repairs an interrupted revision anchor if safe, reconciles encrypted blob roots, and
then admits work. A missing, malformed, outside-state, non-v5, wrong-capacity, or locked target
fails startup. Shared deployments reject this local descriptor setting.

## Retention and revision compaction

Compaction is separate from blob garbage collection. Preview binds the active descriptor, source,
migration receipt, exact revision/pin set, retention policy, expiry, and output target; execute
revalidates all of those values and performs post-verification. A missing trusted backup, legal hold,
active writer, insufficient space, expired preview, pin/policy/head drift, or failed verification
blocks the operation.

<!-- docs-check: illustrative -->
```sh
cigar compaction preview /absolute/state/state-v5.sqlite3 /absolute/state/state-v5.sqlite3.cigar-migration-receipt.json /absolute/state/compacted-v5.sqlite3 /absolute/state/active-store.json /absolute/state/compaction-preview.json --yes
cigar compaction execute /absolute/compaction-preview.json --yes
cigar compaction status /absolute/state/active-store.json
cigar integrity deep /absolute/state/compacted-v5.sqlite3 --force-full --yes
```

Do not use `VACUUM`, manual row deletion, blob GC, or a larger capacity ceiling as a substitute for
revision compaction. Keep the signed preview, execution receipt, prior source, and verified backup
until the new generation has passed restart and integrity checks.

## Content-free operational signals

OpenMetrics counters are cumulative; derive rates or per-commit values over the same observation
window. Useful closed families are:

- `cigar_repository_commit_duration_nanoseconds_total` and
  `cigar_repository_commit_phase_runs_total` for per-phase means;
- `cigar_repository_logical_bytes_total`, `cigar_repository_encoded_bytes_total`, and
  `cigar_repository_file_growth_bytes_total` for logical, encoded, and physical amplification;
- `cigar_repository_file_bytes` and `cigar_repository_retained_records` for current file/chain
  state;
- `cigar_startup_stage_duration_nanoseconds_total`, `cigar_startup_stage_runs_total`, failures, and
  outcomes for readiness; and
- `cigar_context_candidate_stage_total` and `cigar_context_compile_results_total` for reduction,
  uniqueness, displacement, and blocking-source coverage.

Labels are closed enums and contain no tenant, source, path, prompt, token text, credential, or
extension. Telemetry is diagnostic, not durable proof; signed receipts, roots, and the private
qualification report remain authoritative.
