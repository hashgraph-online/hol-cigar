# Capacity scaling and high queue age

## Establish the bound

Scale from measured installed-candidate evidence. Record workload stratum, request concurrency,
worker classes, database and object limits, per-replica connection pools, CPU/memory/file-descriptor
limits, queue capacity, oldest-work SLO, and the artifact/configuration digests. Reserve capacity for
migration, backup, failover, reconciliation, and operators before assigning runtime capacity.

Keep `replicas × per-replica maximum connections` below the database budget. Worker concurrency must
also fit object-store, key-provider, connector, and downstream rate limits. A larger queue is not a
fix for sustained overload; queues remain bounded and admission returns an explicit retry class.

## Scale safely

Add one ready replica or one bounded worker increment at a time. Confirm stable pool wait, queue age,
outbox age, worker heartbeat, lease/fence behavior, object latency, journal commit latency, index lag,
and unknown-effect count before the next increment. Scale down only after draining claims and proving
that no worker remains active past its fencing token.

## High queue-age incident

First distinguish admission overload, a stalled dependency, lost wakeups, poisoned work, expired
leases, and inadequate capacity. Pause new risky effect dispatch if its reconciliation queue is
aging. Do not delete or reorder durable work, widen retry classes, bypass policy, extend leases
without fencing, or disable integrity checks.

Stop scaling and roll back the last change if pool wait, error rate, unknown effects, memory, file
descriptors, or queue age worsens beyond the recorded bound. Evidence records aggregate closed-label
metrics and configuration/artifact digests; tenant, user, source, prompt, and raw work payloads are
forbidden labels.
