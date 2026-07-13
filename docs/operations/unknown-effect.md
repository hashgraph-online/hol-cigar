# Unknown-effect recovery

## Preconditions

Freeze automatic retry for the logical effect. Preserve its intent, authorization, attempt,
idempotency key, connector version, and journal chain. Confirm the connector recovery contract and
current policy before contacting the external system.

## Exercise

1. Inspect the durable attempt and determine whether dispatch may have crossed the boundary.
2. Query the connector using the same stable idempotency key or provider receipt identifier.
3. If completion is proven, append the verified receipt; if non-execution is proven, authorize a new
   attempt under current policy; if neither is proven, keep the state unknown.
4. Run reconciliation and verify the journal chain, outbox, replay completeness, and downstream state.
5. Use a governed compensation only when policy and connector semantics explicitly allow it.

## Stop conditions

Never convert a timeout into failure, retry with a new logical identity, edit an old journal event,
or claim exactly-once behavior the provider cannot prove. Escalate unresolved unknown effects and
retain them through backup and migration.
