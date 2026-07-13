# Configuration, errors, metrics, and extensions

## Configuration

Daemon and CLI configurations have a required schema version and reject duplicate or unknown keys at
security-sensitive boundaries. Secret values come from protected regular files or approved key
services, never ambient cloud credentials. Remote endpoints require TLS verification; redirects,
URL credentials, ambient proxies, and insecure HTTP are rejected.

## Errors

Problems carry a stable generated code, operation ID, retry class, safe remediation, and correlation
metadata. Messages are content-safe and not a compatibility surface. See the
[error registry](../../schemas/openapi/error-registry-v1.json).

## Metrics

Metrics use closed labels such as worker, operation class, and result class. Tenant, user, path,
prompt, source, atom, and artifact identifiers are prohibited labels. Alert on readiness failures,
queue saturation, oldest work age, pool wait, journal or object integrity, unknown-effect age, outbox
age, and index lag. Traces may use access-controlled blinded identifiers.

## Extensions and connectors

Extensions run through the bounded component host with explicit capabilities, fuel, memory, I/O,
deadline, cancellation, and output validation. Connector manifests declare operation class,
idempotency semantics, recovery behavior, and network destinations. Unknown or disabled adapters fail
before invocation. Use the [adapter-disable runbook](../operations/adapter-disable.md) during an
incident; never broaden capabilities to recover availability.
