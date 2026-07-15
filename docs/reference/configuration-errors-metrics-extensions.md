# Configuration, errors, metrics, and extensions

## Configuration

Daemon and CLI configurations have a required schema version and reject duplicate or unknown keys at
security-sensitive boundaries. Secret values come from protected regular files or approved key
services, never ambient cloud credentials. Remote endpoints require TLS verification; redirects,
URL credentials, ambient proxies, and insecure HTTP are rejected.
The normative macOS development precedence, profile ownership, secret-handle rules, and open
provider qualifications are in the [configuration authority](configuration-authority.md).

Local metadata uses `local_sqlite_capacity_profile = "standard"` when the key is absent. Native
macOS arm64 operators may explicitly select `"large_local"` before creating the database; the
profile is persisted as database authority and later opens must select the same value. Large-local
requires 300 GiB available at activation, maintains a 16 GiB reopen reserve, caps the SQLite file at
64 GiB, and enforces 1.25 million atoms, 12.5 million edges, and 128 GiB of logical blob references.
Shared mode, non-macOS targets, and profile changes on an existing database reject the setting.

## Errors

Problems carry a stable generated code, retry class, safe remediation, and correlation metadata.
The frozen problem body does not duplicate the operation ID: the validated request context and
transport route retain the one generated operation identity used by privileged correlation logs.
This avoids accepting a conflicting caller-authored identity on an error path. Messages are
content-safe and not a compatibility surface. See the
[error registry](../../schemas/openapi/error-registry-v1.json).

## Metrics

The daemon exports one shared, version-controlled schema through both `/metrics` and OTLP: 43
families and at most 137 series. Every family is declared in `cigar-observe`; the OpenMetrics
renderer, dashboard parser, and OTLP instruments consume that same authority. A scrape always
contains exactly one `HELP` and `TYPE` declaration for every family, every member of every closed
label domain, unsigned finite values, and the OpenMetrics EOF marker. Unknown families, labels,
label values, duplicate series, missing series, and inconsistent queue snapshots fail closed at the
dashboard boundary.

The implemented groups are:

- daemon authentication, listener failure, graceful shutdown, uptime, accumulated CPU time,
  resident and virtual memory, and open descriptors;
- published/tombstoned ingestion atoms, eligible bytes, parser failures, quarantines, mandatory
  index lag, invalidation fan-out, and oldest invalidation age;
- candidates, selected blocks, logical lane tokens, compile phase runs/time, conflicts, stale
  observations, cache outcomes, physical tokens, and provider cache read/write tokens;
- handoff acceptance outcomes and merge conflicts; effect state observations, oldest unknown age,
  and reconciliation outcomes;
- all nine queue depths, capacities, rejections, oldest ages, and durable lease times; blocking-pool
  occupancy, capacities, and outcomes; database-pool state/waits; blob integrity; governed API
  admission/failure events; and real bounded-stream open, full-buffer, and cancellation events.

The only label keys are `outcome`, `stage`, `lane`, `phase`, `kind`, `state`, `worker`, and `event`,
and every value is compiled into the schema. Tenant, workspace, principal, operation, trace, path,
prompt, source, atom, artifact, handoff, effect, and record identifiers are structurally unavailable
to metric entry points. Metrics are saturating process-lifetime counters or current unsigned gauges;
they accept no arbitrary strings. Traces may use access-controlled blinded identifiers, but the
broader semantic trace tree remains separately qualified.

Ownership is deliberately exact. The catalog/compiler, mandatory index, handoff, effect,
repository checks, transport buffers, durable worker supervisor, blocking pool, and process sampler
record only values they directly observe. The local SQLite profile has no connection pool, so its
database-pool series remain zero; the shared PostgreSQL composition is responsible for recording
live pool state and waits under FULL-500. Demo and benchmark outcomes are not running-daemon
metrics: CIGARBench and the release evidence assembler own them as signed, bounded result-document
fields so a benchmark identity or stratum can never become a daemon label.

Alert on readiness failures, queue or blocking-pool saturation, oldest work age, pool wait, blob
integrity failure, unknown-effect age, and index lag.

OTLP export is opt-in. Remote collectors require one canonical HTTPS origin plus an explicit
owner-controlled `otlp_ca_certificate_file`; the exporter loads no ambient platform roots or
credential/header environment variables. Local development may instead use explicit loopback HTTP
with a port and no CA field. The CA bundle is bounded, parsed as one or more usable trust anchors,
must contain no private key, and is applied to both trace and metric gRPC channels with hostname
verification and bounded exporter timeouts.
The native macOS development gate runs real bounded loopback-HTTP and private-CA-HTTPS gRPC
collectors, rejects an unrelated valid CA, and requires both trace and metric exports to contain
only the closed daemon signal and attribute vocabulary. The loopback collector requires exact
equality with all 43 families and all 137 closed series, not a representative subset.

## Extensions and connectors

Extensions run through the bounded component host with explicit capabilities, fuel, memory, I/O,
deadline, cancellation, and output validation. Connector manifests declare operation class,
idempotency semantics, recovery behavior, and network destinations. Unknown or disabled adapters fail
before invocation. Use the [adapter-disable runbook](../operations/adapter-disable.md) during an
incident; never broaden capabilities to recover availability.

The optional stock live-effect transport is local-macOS-only development source and remains
disabled unless the strict production effect registry names the exact v1 protocol, HTTPS endpoint,
public address pins, bounds, and owner-private scoped credential handle. It has no ambient DNS,
proxy, credential, project-file, CLI, or environment authority; shared mode rejects it. Its exact
contract and qualification limits are documented in the [effect journal](effect-journal.md).
