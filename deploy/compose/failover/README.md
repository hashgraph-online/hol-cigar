# WP18 PostgreSQL failover qualification

This isolated Compose topology exercises one PostgreSQL 18 primary, one physical streaming
standby, and a HAProxy write router. HAProxy runs an authenticated SQL health check and admits a
backend only when `pg_is_in_recovery()` is false. It therefore fails closed between loss of the
primary and explicit standby promotion.

Both PostgreSQL nodes and operational clients attach only to the internal `failover` network.
HAProxy alone is dual-homed onto `host-edge`, and publishes only its PostgreSQL listener on the
IPv4 loopback address; this keeps the real host-side repository test on the same guarded endpoint
without publishing either database node.

Run the complete qualification from the repository root:

```sh
tools/wp18-failover/qualify.sh
```

The runner creates random, per-run hexadecimal passwords in memory when none are supplied. It
enables `synchronous_standby_names` only after the initial base backup is streaming and proves
`synchronous_commit=remote_apply`. Before failover it runs the required production
`PostgresStore` phase, pauses standby WAL replay, proves a router write remains in `SyncRep` for a
bounded window, resumes replay, and proves that exact commit LSN is applied before acknowledgement.

The runner then stops the primary, runs the required fail-closed production-client phase, promotes
the standby, verifies the acknowledged revision/effect, creates a fresh physical slot, and uses
`pg_rewind` to rejoin the former primary after removing a network-isolated target-only WAL
divergence. Once the former primary is a synchronous receiver, the final production phase proves
revision 1→2, idempotent effect retry, and exactly-once concurrent `SKIP LOCKED` wakeup claims.

Finally, `physical-backup` takes a `pg_basebackup` from the promoted primary with streamed WAL and
SHA-256 manifest checksums, and runs `pg_verifybackup`. The harness records the manifest digest,
manifest checksum, exact source/end LSNs, and source timeline. `physical-restore` copies that exact
verified base backup to a fresh volume, has no network device, enters targeted recovery at the
manifest `End-LSN`, and promotes only after replay reaches that point. Readiness requires a writable
non-recovery server. The harness then compares the restored timeline/replay LSN, migration shape,
qualification rows, repository revision, and a domain-separated CIGAR semantic root over migration
identity, latest tenant-state bytes/checksums, object metadata, and atom projection records.

The complete sanitized log and fail-closed JSON receipt are atomically published at
`artifacts/qualification/wp18-failover.log` and
`artifacts/qualification/wp18-failover.json`. The receipt contains a stable workspace digest,
exact pre/post/lag commit and replay LSNs, timeline change, fixed router port, required commands,
and zero-loss/zero-duplicate assertions. A run first replaces any older pass receipt with a
non-passing `running` receipt, and publishes `pass` only after all live phases finish without a
skip and Compose cleanup leaves no project containers, volumes, networks, or local image. Database
URLs and secrets are neither printed nor persisted.

Use `tools/wp18-failover/qualify.sh --syntax-only` for local Compose and shell parsing without
starting containers. Set `CIGAR_KEEP_FAILOVER_DEPS=1` to retain a failed or successful project for
inspection; otherwise all containers, networks, and volumes are removed.

## Input contract

All identities are qualification-only and fixed by the topology. The following optional variables
override generated values:

- `CIGAR_FAILOVER_OWNER_PASSWORD`
- `CIGAR_FAILOVER_REPLICATION_PASSWORD`
- `CIGAR_FAILOVER_REWIND_PASSWORD`
- `CIGAR_FAILOVER_ROUTER_PASSWORD`
- `CIGAR_FAILOVER_RUNTIME_PASSWORD`

Each override must contain exactly 64 lowercase hexadecimal characters. Values are passed as
environment-backed Compose secrets, never as image arguments or checked-in files. Do not reuse
production credentials. `CIGAR_FAILOVER_ROUTER_PORT` changes the loopback-only HAProxy port from
`55433`; both production test clients use that single primary-only endpoint.

`CIGAR_FAILOVER_PROJECT` may set a Compose project name and `CIGAR_KEEP_FAILOVER_DEPS=1` preserves
the topology. The operational services are behind the `operations` profile and are invoked only by
the runner. PostgreSQL nodes are not host-published.

This is a deterministic qualification topology, not a production failover controller. Production
promotion requires an external consensus/fencing authority; promoting both nodes is deliberately
outside this harness.
