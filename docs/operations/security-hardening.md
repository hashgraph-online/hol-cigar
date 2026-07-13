# Security hardening

Run as a dedicated non-admin identity with least-privilege files, database roles, object policies,
network egress, and connector capabilities. Require TLS verification and explicit trust roots on
every remote dependency. Separate runtime, migration, backup, garbage-collection, and release-signing
identities. Keep production keys out of repositories, environment variables, arguments, logs, and
diagnostic archives.

Force tenant isolation in policy and storage, deny ambient credentials and proxies, cap all inputs,
keep effect dispatch closed until durable authorization, and preserve unknown outcomes. Verify
backups offline, practice restore, retain historical decrypt/verify keys, and rebuild disposable
indexes from durable state rather than repairing them in place.

Before release, require a clean committed source revision, locked tools, two independent payload
builds, archive scans, SBOM and license review, signed provenance, installed-byte platform evidence,
and offline release verification. Any high/critical vulnerability, content leak, integrity drift,
broken migration, skip, waiver, or missing evidence is stop-ship.
