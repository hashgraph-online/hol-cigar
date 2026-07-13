# Context spaces, overlays, and coordination events

WP10 implements the tenant/workspace/project/branch/task/session hierarchy as metadata bound to one
context space. The canonical state is an immutable sequence of `ContextCommit` records. Creation
publishes sequence one; every later publication compares the caller's expected head while holding the
space write lock, derives a content-addressed root and commit identity, and advances the head exactly
once. History and per-commit resource snapshots remain immutable.

Only creation accepts a project selector from the request. Every operation on an existing space first
loads the persisted hierarchy and derives its authorization scope from that space's exact active
project. An ambient project grant, stale request field, overlay ID, checkpoint ID, or handoff ID cannot
substitute another project for policy evaluation. Denied and absent private resources retain the same
existence-hiding result.

## Private overlays and merge

An overlay belongs to one exact principal and one retained base commit. Unauthorized lookup returns
the same `NotFound` result as an unknown overlay, including for views, proposals, and discard. A view
contains one immutable base plus at most one owner-visible overlay. Discard removes only private state.

Proposals are keyed by normalized semantic resource keys. Publication performs a three-way comparison
of overlay base, current head, and proposed value. An unchanged head accepts the proposal; an already
identical value deduplicates; changes to different keys merge independently. Competing values at one
key produce a typed conflict retaining base, current, proposed, sorted evidence versions, and the
required typed-decision or exact-base resolver. Canonical state never uses semantic last-writer-wins.

## Events, leases, and focus branches

Every durable event has an immutable protocol identity and project disclosure scope. Polling filters
before assigning a visibility-relative cursor, so an A-only subscriber cannot infer Project B event
counts from cursor gaps. Pages are bounded and contiguous. Reconnecting from the last acknowledged
cursor resumes without a semantic gap; reconnecting from an older cursor safely repeats events.
Invalidation, revocation, and policy events sort ahead of ordinary events within an atomic batch.

Leases are advisory coordination records, not authorization. Each resource acquisition increments a
monotonic fencing token. Renewal and release require the exact holder, live token, current lease
revision, and unexpired interval. A released, expired, superseded, or wrong-holder token cannot pass
fence verification.

Focus branches retain their fork commit, optional checkpoint, and offline state. Task switching only
changes the active focus; it never deletes another branch. Resuming clears offline state while
preserving the exact checkpoint.

## Project federation

The active project is the default contribution domain. Links are explicit and directional, and both
endpoints must pass current disclosure checks before link creation or preview. Optional linked-project
contributions are admitted in deterministic version order up to the link's physical-token cap.
Mandatory dependencies may exceed that crowd-out cap only after the project itself is authorized.
Unlinked or unauthorized projects contribute nothing and receive no existence-revealing preview.

Durable daemon snapshots publish chunks before a canonical root manifest. The root is independently
authenticated over tenant, snapshot kind, generation, content digest, byte count, and ordered chunks.
Verification rechecks current tenant and signing-key authority, so coherently replacing both chunks
and repository checksums, presenting an unsigned legacy root, or using a revoked key fails closed.
