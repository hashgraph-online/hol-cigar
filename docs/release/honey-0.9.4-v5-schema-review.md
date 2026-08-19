# Honey 0.9.4 v5 storage compatibility review

Status: closed; no storage schema change is required for Honey 0.9.4.

Review baseline: frozen Honey 0.9.3 commit
`a049fbc8ed81c9adc6b1a066ca053c5befc2578a`.

## Decision

The 0.9.4 context-workflow implementation persists a bounded, identity-only
`cigar.workflow-context-checkpoint.v1` document through the existing tenant-scoped
`ServiceRepository` record interface. It does not issue SQL, add a repository mutation kind, alter
the v5 envelope, or require a new table or column. `SqliteV5Store` already persists the existing
`ApplyServiceBatch` mutation through the authenticated v5 delta chain and recovers those records
after restart.

The following storage authorities are byte-identical to the frozen 0.9.3 baseline:

| Authority | SHA-256 |
| --- | --- |
| `migrate_v5.rs` | `cb42720e7b56bc1bb2834a1c6fc2fa402db1a3b3d42cee6795be8c59d3b603f1` |
| `revision_delta.rs` | `6aa5dfd1427571fdce4dc2317aea5a909c82b00fc1e18b849aeb2b6941eb3bff` |
| `service_repository.rs` | `b8d780c5e18076b72fc2e77d2e92fcad47bfe8510addeff38978c7c78ea3981d` |
| `sqlite_v5.rs` | `4ae54e9f05d2f827e4e775233f88d3e6ac3fa04a45e9771804b47bf99b10c075` |

The five-file SQLite migration inventory is unchanged. Its v5 authority remains
`0005_incremental_repository_state.sql` with SHA-256
`4600a510c1fb75dc47e26eb8f3faeb2197150455c216e612cef40b67fd16aff2`.
No `0006` migration or storage format v6 exists.

## Qualification

The release regression test
`scripts/release/tests/test_honey_094_storage_compatibility.py` pins the exact SQLite migration
inventory, migration hashes, and frozen v5 persistence-core hashes. It also proves that workflow
checkpoints remain on the existing service-record path and contain no SQL or storage-format
coupling.

Runtime qualification covers both sides of that composition:

- daemon workflow checkpoint create/save/load, exact CAS replay, every durable resume boundary,
  identity-only serialization, and fail-closed governance validation; and
- SQLite v5 service/worker commits, authenticated delta publication, process reopen, exact record
  recovery, and absence of v4-table growth.

Any future change to these frozen authorities fails the release sentinel and requires a separately
reviewed migration proposal. It must not be absorbed into the 0.9.4 iteration as an incidental
implementation change.
