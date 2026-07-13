# Revocation propagation

## Preconditions

Identify the exact principal, key, capability, handoff, connector, or policy grant being revoked and
the authoritative revision that contains the change. Record its scope and a content-free reason
digest. Revocation does not rewrite prior journal history; it advances the authority/revocation epoch
and invalidates dependent caches, sessions, handoffs, and queued operations.

## Exercise

Publish the revocation through the authoritative store, then observe every replica consume the same
revision. Force cache revalidation and prove the revoked subject fails authentication or authorization
at each relevant boundary: new requests, streams, handoff acceptance, expansion, effect approval and
dispatch, extension activation, and signature trust policy. Historical audit records remain readable
only to authorized operators and retain the original decision context.

Measure propagation from commit to the last healthy replica. Restart one replica from an older cache
snapshot and prove it cannot serve until it catches up. Exercise an in-flight request at the boundary;
operations that have not crossed their durable authorization/dispatch point fail, while an already
dispatched effect follows normal receipt or unknown-state reconciliation.

## Stop conditions and evidence

Close readiness on a replica that cannot reach the current epoch. Stop if any revoked credential,
grant, handoff, extension, or key remains usable after the configured bound, or if denial reveals a
private resource's existence. Do not recover by lengthening caches or restoring an old authority
snapshot. Evidence records the revocation revision/epoch, blinded subject class, replica counts,
maximum propagation time, boundary results, and raw report digest.
