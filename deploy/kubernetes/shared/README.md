# Shared Kubernetes profile

This base deploys three non-root `cigard` replicas, a one-shot owner migration Job, bounded
resources, zero-unavailable rolling updates, disruption protection, autoscaling, and default-deny
network policy. It deliberately does not create credentials or trusted policy. The referenced
Secrets must be supplied by the operator or an approved secret controller.

The operator must also provision the `cigar-effect-checkpoints-rwx` PersistentVolumeClaim before
creating the Deployment. It must support `ReadWriteMany` because every replica uses the same
monotonic effect checkpoint. Its storage implementation must provide coherent POSIX advisory file
locks across nodes and durable `fsync`, atomic same-filesystem `rename`, and parent-directory
`fsync` semantics. Object-backed mounts or network filesystems that emulate locks or acknowledge
non-durable flushes are not suitable for this security boundary. A per-pod `emptyDir` is never an
acceptable fallback.

Precreate the volume root as owner `65532:65532`, mode `0700`, and create the regular, single-link
`checkpoints.json` file as owner `65532:65532`, mode `0600`, with these exact initial bytes (no
trailing newline):

```json
{"schema_version":"cigar.effect-checkpoints.v1","generation":0,"checkpoints":[]}
```

The init container checks the path ownership, type, link count, non-empty state, and modes but does
not initialize or overwrite this security state. The daemon performs strict canonical JSON and
monotonic-content validation while holding the shared exclusive lock. Preserve and restore this
PVC in the same consistency boundary as PostgreSQL; never roll it back independently.

Before rendering, replace the three `example.invalid` endpoints in `configmap.yaml`, set the CIGAR
image to the exact release digest, and label only dependency/client namespaces that should cross the
network boundary:

```sh
kubectl label namespace identity object-storage postgres observability cigar.dev/dependency-access=true
kubectl label namespace ingress-system cigar.dev/client-access=true
kustomize edit set image cigar-daemon=registry.example/cigar/cigard@sha256:RELEASE_DIGEST
kubectl kustomize . > rendered.yaml
```

Create these inputs without putting secret values on a command line:

| Secret | Required keys |
|---|---|
| `cigar-shared-migrator` | `postgres-migrator-url` |
| `cigar-shared-runtime` | `postgres-runtime-url`, `object-access-key`, `object-secret-key`, `object-session-token`, `object-blinding-key` (exactly 32 raw bytes), `keystore-passphrase`, `keystore.cigar`, `cursor.key` |
| `cigar-shared-backup` | `postgres-backup-url`, backup-object credentials, inventory-signing capability |
| `cigar-shared-tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `cigar-postgres-tls` | `ca.crt` (the private/public CA that issued the PostgreSQL server certificate) |
| `cigar-shared-trusted` | `policy.json`, `authority.json`, `sources.json`, `effects.json`, `object-wrapping-keys.json` |

The wrapping-key document is strict JSON:

```json
{"schema_version":"cigar.object-wrapping-keys.v1","keys":[{"tenant_id":"01890f47-8e7d-7b42-a1d2-3c4d5e6f7890","key_ref":"key-example"}]}
```

Entries must exactly match active authority tenants in ascending tenant order. Raw projected
Secrets are group-readable only inside the pod. A non-root, capability-free init container copies
them into memory-backed owner-only files. Runtime credentials remain mode `0600`; the externally
provisioned keystore and cursor key become immutable mode `0400`, as required by shared bootstrap.
Failure to obtain the expected projected-volume group or immutable modes is a startup failure. The
runtime Deployment never mounts `cigar-shared-migrator`.

The separately scheduled backup controller mounts only `cigar-shared-backup`; neither the runtime
Deployment nor migration Job mounts it. Its PostgreSQL role is `NOSUPERUSER`, data-read-only,
`BYPASSRLS`, and has explicit `EXECUTE` on `pg_control_system()` and the migration-owned
`cigar_gc_lock_repository_revision()` function. The latter has a fixed system-only search path and
permits a revision-row lock without granting arbitrary table updates. These capabilities let inventory
capture derive a content-free cluster/database identity, enumerate the authoritative tenant set, and
safely exclude GC. Its object
identity can create and delete only dedicated backup prefixes. Do not reuse migrator, runtime, or GC
credentials for backup capture or activation verification.

Both PostgreSQL URL secrets must use exactly the `host` configured as
`shared_storage.postgres.server_name`; use `hostaddr` separately when a fixed network address is
needed. CIGAR overrides `sslmode` to `require`, loads only the bounded `cigar-postgres-tls` CA
bundle, and verifies that exact host name for runtime and migration connections. A plaintext-only
server, untrusted issuer, wrong name, or URL downgrade setting therefore fails before SQL runs.

After a `pg_restore --no-acl` drill, the target-role provisioning step must explicitly revoke PUBLIC
execution of `cigar_gc_lock_repository_revision()` and grant it only to the dedicated backup/GC role
before activation. Repository startup verifies this fail-closed invariant.

Apply the Namespace, configuration, and Secrets first. Run and inspect the migration Job before
creating the Deployment. Provision and validate the shared checkpoint PVC before that final step.
Do not give the runtime PostgreSQL role ownership, `SUPERUSER`, or
`BYPASSRLS`; it needs only DML grants created by the migrator role's default privileges.

The checked-in network policy assumes in-cluster HTTPS identity/object/telemetry services and an
in-cluster PostgreSQL service. For managed external dependencies, replace the selector policy with
an audited CNI FQDN/IP policy before enabling default deny. Never temporarily allow unrestricted
egress.
