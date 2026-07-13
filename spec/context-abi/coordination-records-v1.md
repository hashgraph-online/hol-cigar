# Coordination records v1

The coordination ABI includes immutable context commits, private overlays, attenuable capability grants, signed handoff capsules, recipient-specific acceptance receipts, evidence-backed child-result deltas, and optimistically revised leases.

Capability delegation is intersection-only: a child must name the parent, be issued by the parent subject, remain within capability/project/processor sets, narrow time, and reduce delegation depth. Current policy still reauthorizes every use.

Handoff capsules contain typed references and never a parent transcript. They bind recipient, audience, project scope, attenuated and rejected capabilities, exact budget, topics, creation/expiry, replay nonce, signing key, and signature. Acceptance separately checks the actual recipient and cannot broaden delegation. Child prose remains typed evidence and cannot directly mutate canonical decisions or instructions.

Context commits require monotonic sequence/parent invariants and unique ordered events. Overlays name one immutable base and may be discarded without canonical mutation. Lease intervals are positive and all lease state is closed.

