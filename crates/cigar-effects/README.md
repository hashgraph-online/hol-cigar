# cigar-effects

Stability: kernel, pre-v1. Owns durable effect intent, approval, attempts, receipts, unknown states, reconciliation, and compensation.

The public `EffectEngine` is the only dispatch authority. It persists an intent before approval,
atomically journals each versioned transition with the current projection, and returns a sealed,
non-cloneable `DispatchPermit` only after a fenced attempt and outbox wakeup are durable. Connectors
receive that already-authorized context; they cannot approve work or turn ambiguity into success.

Compensation is always another ordinary, separately authorized effect. The original journal stores a
`CompensationLink` and projects the child outcome; there is no connector-side compensation bypass.

See `docs/reference/effect-journal.md` for state, recovery, retry, and connector contracts.
