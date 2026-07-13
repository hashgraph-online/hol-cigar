# Daemon start, stop, and readiness

## Preconditions

Operate the exact verified candidate image or binary. Record its artifact digest, configuration
digest, migration sequence, schema/Context ABI range, and protected key-file identities. Local mode
uses one owner-restricted Unix socket or Windows named pipe. Shared mode uses the dedicated runtime
identity and must never start with migration-owner credentials.

Before start, verify that the data directory, socket parent, configuration, authorization file, and
key files are regular non-symlink paths with the documented owner and modes. Confirm that no stale
process owns the endpoint. Do not delete a socket until the recorded owner process is proven absent.

## Start and verify

Start one instance and observe liveness separately from readiness. Liveness may become healthy while
readiness remains closed. Readiness opens only after configuration, key, migration, store, object,
policy, journal, index, and worker checks succeed. Exercise an authenticated read and an unauthorized
request; the latter must fail before domain dispatch. Then start the remaining replicas one at a time.

Record process/image identity, endpoint type, readiness transitions, dependency health, open-file
count, task count, queue age, index watermark, journal head, and content-free request correlation IDs.

## Graceful stop and recovery

Remove the instance from readiness, stop accepting new streams and dispatch claims, drain bounded
in-flight work, persist final worker heartbeats, and close listeners before the configured deadline.
An effect that crossed its dispatch boundary without a durable receipt remains unknown and follows
the [unknown-effect runbook](unknown-effect.md); shutdown never invents success or retries it.

Stop the rollout if readiness opens before dependencies are verified, the endpoint has the wrong
owner or permissions, shutdown loses a committed journal record, workers outlive fencing expiry, or
task/file-descriptor counts do not return to the documented steady state. Preserve logs and state,
keep traffic on the previous healthy replica set, and investigate without deleting durable records.
