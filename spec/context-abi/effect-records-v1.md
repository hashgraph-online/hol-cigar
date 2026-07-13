# Effect records v1

The effect ABI is intent-first. `EffectIntent` binds connector, operation, normalized argument digest, protected arguments, target, preconditions, result schema, risk, source decision and bundle, capability, idempotency scope/key, retry policy, expiry, and optional compensation before any external action.

Approvals bind the exact intent, target, risk, bundle, conditions, approver, provenance, and expiry. High and critical risk require explicit human approval. Attempts have one-based numbers, monotonic fencing tokens, committed request digests, and positive deadlines.

The closed effect state graph is implemented by `EffectState::can_transition_to`; journal events reject shortcuts and enforce one-based hash-chain structure. Receipts make ambiguity explicit through `unknown`. Reconciliation requires evidence and keeps inconclusive results bounded by a certainty window. Compensation is always a distinct separately journaled logical effect.

Raw effect arguments, targets, operation names, remote IDs, and protected responses are excluded from debug output. JSON Schemas and Protobuf messages are generated or compiled as WP01 gates.

