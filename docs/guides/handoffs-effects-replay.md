# Handoffs, effects, and replay

A handoff capsule binds its issuer, exact base, selected delta, provenance, expiry, and attenuated
capabilities. Preview before acceptance. Acceptance rechecks current policy; possession of a capsule
never overrides a revocation or grants capabilities the issuer did not delegate.

The installed-candidate documentation gate runs this block through the two-agent story from the
digest-bound Honey demo archive. It uses the exact candidate runtime and Python wheel, requires two
identical semantic runs under the no-egress boundary, and rejects missing recipient, attenuation,
typed-result, or exact-base merge evidence.

<!-- docs-check: command handoff-flow -->
```sh
cigar --embedded handoff create --input handoff.json --yes
cigar --embedded handoff preview handoff-id
cigar --embedded handoff accept handoff-id --input acceptance.json --yes
cigar --embedded handoff merge handoff-id --input merge.json --yes
```

Effects use prepare, approve, dispatch, inspect, reconcile, and compensate. Durable intent and current
authorization precede dispatch. A timeout after dispatch can become **unknown**; do not retry blindly.
Inspect connector evidence and reconcile using an idempotency key or external receipt. Compensation
is a new governed effect, not history deletion.

For installed-candidate checking, the digest-bound packaged runner executes both the effect recovery
and observational replay components twice from the exact runtime archive. A successful process exit
without repeated semantic identities and enforced no-egress evidence fails qualification.

<!-- docs-check: command effect-replay-flow -->
```sh
cigar --embedded effect prepare --input effect.json --yes
cigar --embedded effect approve effect-id --input approval.json --yes
cigar --embedded effect dispatch effect-id --input dispatch.json --yes
cigar --embedded effect reconcile effect-id --input reconciliation.json --yes
cigar --embedded replay reconstruct --input decision.json --yes
cigar --embedded replay run --input observational.json --yes
```

Use [unknown-effect recovery](../operations/unknown-effect.md) before any retry and
[journal quarantine](../operations/journal-quarantine.md) for integrity failures.
