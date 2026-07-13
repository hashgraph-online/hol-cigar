# Shared deployment runbook

## Preconditions

Use PostgreSQL and S3-compatible services in the same failure domain as the latency target. The
migrator and runtime URLs must name different roles. The migrator owns CIGAR tables; the runtime
role is `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` and receives only schema usage plus DML.
Require TLS verification on PostgreSQL, object storage, OIDC, OTLP, HTTP, and gRPC. Object runtime
credentials may create/read immutable final objects and clean staging/probe objects, but cannot
delete `*/objects/*`; a separately authorized GC/restore identity owns final deletion.
Provision one identical encrypted keystore and one exact 32-byte cursor key for every replica. The
serving identity must receive both as regular, non-symlinked, owner-read-only mode `0400` files;
shared bootstrap rejects missing, writable, generated, or per-replica key state.

Inventory the exact CIGAR image digest, configuration digest, migration checksums, authority/policy
digests, OIDC issuer/audience, certificate roots, PostgreSQL endpoints, object endpoint/bucket/prefix,
and backup recovery point in the change record. Never record credential values.

For PostgreSQL, provision the issuing CA as `cigar-postgres-tls/ca.crt`, set the configured
`server_name` to the certificate's exact DNS/IP identity, and keep that same value in each URL's
`host`. If routing needs a fixed IP, use a separate `hostaddr`; never replace the certificate name
with the address. Runtime and migration both force TLS and use the same explicit trust policy.

## Provision and migrate

1. Provision object versioning and a deny-overwrite policy. Confirm a conditional second PUT cannot
   replace an existing final key and an ordinary runtime DELETE is denied.
2. Create the owner role, then the runtime role and default privileges. Confirm
   `rolsuper = false` and `rolbypassrls = false` for runtime.
3. Prepare the strict object wrapping-key map. Its sorted tenant set must exactly equal active
   authority tenants; each referenced key must be an active tenant-scoped blob-encryption key.
4. Render `deploy/kubernetes/shared` only after replacing all `.invalid` endpoints and pinning the
   release image digest. Review the rendered Secret names, network policy, resources, and image list.
5. Apply Namespace/configuration/Secrets and the `cigard-migrate` Job. Read its content-free receipt;
   `latest_sequence` and `checksums_verified` must equal the packaged migration count. A failed or
   interrupted Job is rerun with the same image and owner credential; never edit an applied SQL file.
6. Verify every tenant table has both RLS and forced RLS:

   ```sql
   SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = current_schema() AND c.relname LIKE 'cigar_%'
   ORDER BY c.relname;
   ```

7. Start one replica. `/livez` must progress and `/readyz` must remain closed until PostgreSQL,
   migrations, object read/write verification, keys, policy, journal, index, and worker heartbeats
   are healthy. Exercise one authorized request and one wrong-tenant token; the latter must fail
   before domain dispatch.
8. Scale to three replicas, then run the 64-client shared conformance profile. Confirm no duplicate
   effect receipt, no lost revision, bounded pool wait, and drained outbox wakeups.

## Capacity and observability

Keep `replicas × maximum_connections` below the database connection budget after reserving
migration, backup, failover, and operator capacity. Scale workers only with matching database/object
throughput and queue-age evidence. Alert on queue saturation, any rejection, oldest work age,
listener failures, database pool wait, object integrity failures, outbox age, unknown-effect age,
and index lag. Labels remain closed (`worker`, operation class, result class); tenant, user, path,
prompt, source, and artifact identifiers belong only in access-controlled traces as blinded values.

## Fail closed

Do not bypass RLS, swap to owner credentials, enable ambient cloud credentials, disable TLS, widen
network egress, or allow object overwrite to recover availability. If PostgreSQL or object storage is
uncertain, stop new dispatch claims, keep readiness closed, preserve unknown effects, and reconcile
only after dependency integrity is restored.
