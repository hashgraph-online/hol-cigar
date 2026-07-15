# cigar-space

Stability: kernel, pre-v1. Owns context spaces, branches, overlays, commits, handoffs, leases, and child-result merge.

`ContextSpaceService` maintains immutable commit history and serialized optimistic publication. Each
private overlay retains its exact base resource snapshot, so publication can deterministically merge
independent keys, deduplicate identical versions, or return typed base/current/proposed conflicts.
Owner checks intentionally make missing and inaccessible overlay lookups indistinguishable.
Complete strict snapshots preserve commit history, private overlays, leases and fences, event
cursors, focus branches, and federation links; restoration revalidates their semantic relationships.

Scoped at-least-once event pages scan contiguous private storage positions while the typed API exposes
only disclosure-visible immutable event IDs as resume tokens. Advisory leases carry monotonic resource
fencing tokens, focus branches retain checkpoint state across task switches and offline resume, and
project links are directional, disclosure-gated, and contribution-capped. Durable restart preserves
both the exact event resume position and the latest fence; an expired or superseded holder cannot
become current again after reopening the store.

`HandoffService` intersects issuer authority with requested and current handoff policy, signs a
transcript-free typed-reference capsule through the scoped key-provider boundary, and persists the
exact capsule. Recipient acceptance independently verifies signature, audience, recipient/role,
clock, nonce, revocation, project scope, target restriction, capabilities, and every reference before
compiling and persisting a recipient-specific bundle receipt. Child results remain evidence-backed
proposals and enter parent history only through ordinary typed overlay merge.
Handoff snapshots include signed capsules, acceptance receipts, subscriptions, and one-use replay
guards, and reject any inconsistent or duplicate-key state during restoration. Capsule revocation
also blocks use of already-created descendant acceptances and results, including verified parent
merge after restart.

See [`docs/reference/context-spaces.md`](../../docs/reference/context-spaces.md) and
[`docs/reference/handoffs.md`](../../docs/reference/handoffs.md).
