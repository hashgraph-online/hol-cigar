# Deployment profiles

**Embedded** composes the production runtime in the caller and opens no listener. **Local daemon**
uses a protected Unix socket or Windows named pipe; loopback HTTP requires an explicit protected
token file. **Shared service** uses TLS-authenticated HTTP/gRPC, PostgreSQL, immutable object storage,
OIDC authority, non-root containers, forced row-level security, and separate runtime, migration,
backup, and garbage-collection identities.

Start with the [shared deployment runbook](../runbooks/shared-deployment.md) and the assets under
`deploy/`. Pin the image by digest, replace every `.invalid` placeholder, provide one identical
protected keystore and cursor key to all replicas, and keep readiness closed until migrations,
storage, policy, journal, index, and worker checks pass.

Production rollout requires the [backup/restore drill](../runbooks/shared-backup-restore.md),
[rolling migration](../runbooks/shared-rolling-migration.md), and all other
[operation exercises](../operations/index.md).
