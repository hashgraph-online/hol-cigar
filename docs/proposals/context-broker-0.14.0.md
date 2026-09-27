# Local context broker implementation contract

Status: implementation contract for B1–B3/P1–P2; not a shipped capability.
The 0.13 views and ordinary 0.12 graph APIs remain available independently.

## Ownership and transport

One trusted host owns one graph per privacy domain. Independent agent processes
receive individual clients; they do not receive the host's worker pipes, root
graph, scope configuration, reviewer interface or checkpoint directory.

Implement the authority and scheduler once in Rust, behind an opt-in mode of the
existing packaged worker. Python and TypeScript supply typed host/client facades.
Keep the ordinary worker's stdio mode, protocol, constructor signatures and
execution behavior unchanged. Do not add a listener to ordinary graph creation.
The broker starts with an empty graph or an explicitly selected journal; it does
not silently import an existing application's worker state.

The host controls the worker through its private stdio connection. Agent clients
use a bounded length-framed protocol on an explicitly returned `127.0.0.1` port.
There is no hostname resolution, HTTP proxy, public bind, service discovery or
automatic fallback. Multi-host use continues to require an explicitly deployed
authenticated service; this transport does not invent a new remote TLS service.
No HOL account or external service is needed for this same-host broker.

Each host-created grant binds a cryptographically random credential to one agent,
one current view and explicit quotas. Requests carry the broker protocol, current
authority epoch, credential, request ID and a closed command shape. Authentication
is checked on every request; the server chooses the view from the grant. A client
cannot supply a different principal, view, reviewer verdict or root operation.
Return content-free errors and never log credentials or source/query text.
Host configuration/revocation is available only on the private stdio connection.

This boundary assumes protected host memory, pipes and files. It is not an OS
sandbox for hostile code running with the host's privileges. Use OS/container
isolation and separate brokers for unrelated hostile tenants.

## Agent and host surfaces

| Agent operation | Authority and result |
| --- | --- |
| Compile context | Server-owned view; caller can narrow it. Returns rendered evidence, the existing context shape and a bounded, owner-bound context ticket. |
| Resolve citation / revalidate | Requires the same caller's live ticket and current view/source authority. Cannot read a denied source through an old ticket. |
| Read source revision | Only an assigned readable/writable source; revision is scoped to the current epoch. |
| Propose source replacement | Requires a writable assignment and expected source revision. Stores an unverified bounded proposal; does not promote generated text to trusted evidence. |
| Submit answer draft | Binds exact displayed claims to a live context ticket. The generator cannot supply trusted reviews or release policy. |
| Inspect own proposal/result | Bound to the caller and epoch; exposes no global document counts or another agent's status. |

The host creates/revokes grants, ingests authoritative sources, admits or rejects
proposals, controls graph relationships, invokes a reviewer, assesses the exact
answer and decides whether to execute a tool. It supplies source identity/version,
observation/validity information, trust origin and derivation records at admission.
Existing trusted in-process `LocalContextView.replace_source` remains unchanged;
the new broker's model-facing proposal surface deliberately has less authority.

Context tickets are random, bounded and owner-bound; secrecy is not their only
authorization check. The broker retains their view/source bindings. Revalidation
checks scope/policy, source versions including unselected authorized evidence,
revocation, expiry and epoch. Unrelated out-of-scope changes preserve valid work.
Source locators and hashes are provenance links, not signatures or truth labels.

## Scheduling, quotas and write conflicts

Use a single graph owner with bounded per-agent queues and round-robin dispatch.
The host has a separately bounded queue so an agent cannot consume its entire
admission capacity. Bound active connections, handshake time, frame bytes, queued
bytes, jobs per caller, token budget, retained tickets, proposals and staged bytes.
Limits are validated before queue admission, then authorization and expiry are
checked again at dispatch. Existing graph/document/cache limits remain effective.

Operations are non-preemptive initially. Fairness guarantees a dispatch opportunity
between bounded operations, not equal completion time for differently sized work.
Report queue delay, service time, p95/p99 and each agent's completion count. Do not
claim parallel Rust reads without implementing and qualifying them separately.

Cancellation/expiry before dispatch means the operation did not start. After
dispatch, a broken connection or timeout can make a mutation's outcome unknown.
Clients never automatically retry writes or restart the broker. A caller queries
the retained proposal/receipt or reconciles through the host. A failed client
connection must not by itself kill every other agent's graph.

Every admitted source replacement carries an expected source revision. Versions
are monotonic for the epoch, including withdrawal and change-back (ABA); an empty
source does not reset to revision zero. Admission compares the proposal's expected
revision again immediately before commit. Exactly one competing replacement of
the same revision can win. Identical source bytes and unchanged admission metadata
may remain a no-op; changed provenance or policy must invalidate dependent work.

## Durable recovery

Persistence is explicit and host-owned. Reuse existing storage/locking primitives
where their contracts fit; do not create a competing Honey authority format.
A standalone journal records versioned source/provenance/edge mutations and their
expected/result revisions with bounded records, a sequence and hash chain. It
needs an exclusive writer lock, durable commit markers and atomic checkpoints.
Credentials and release permissions are never serialized as reusable authority.

No success response is emitted before a committed mutation is durable. A failed
durability step after in-memory mutation closes the broker rather than serving
ambiguous state. Recovery accepts only a complete committed prefix and either the
old or new complete checkpoint. It rejects corruption and unsupported versions;
it never silently drops a committed event. Retention and source withdrawal apply
to both current evidence and dependent derivations.

Every restart creates a fresh random authority epoch. The host re-establishes
current grants and reviewer policy; old credentials, tickets, proposals and
reviews do not regain authority by being replayed into a restored graph. Recovery
may restore evidence, not permission to release an answer or dispatch an effect.

## Review and execution integration

The reviewer is a host-supplied port with explicit supported, unsupported,
contradicted and unknown outcomes. The native review gate continues checking
exact claim bindings and current context; it does not become a semantic judge.
Release only the complete assessed claim set. Extra unreviewed prose and a
generator-supplied approval are rejected by the adapter.

Bind any execution handoff to the checked context/ticket, current source versions,
policy revision, authority epoch, complete displayed claims and exact operation
intent. Revalidate immediately before handing off to the existing Honey effect
authority. HUMIDOR owns orchestration and model routing. Existing effect journal,
idempotency and reconciliation rules remain authoritative; the broker never
turns a context assessment into a general tool grant or a blind redispatch.

## Required evidence

Tests must exercise actual independent Python and Node client processes, including
cross-language clients of the same broker. Run 1/5/12 agents with shared, private
and overlapping scopes; both readable and unreadable source updates; malformed
requests; identity/view spoofing; revoked grants; forged tickets; unreviewed
proposals; stale/competing writes; queue saturation; disconnect before/after
dispatch; killed worker; torn journal and checkpoint recovery; and old-epoch replay.

Short fault schedules precede a 24-hour 12-agent soak. A single scope leak, lost
authorized update, stale authority acceptance, silent journal loss or blind effect
retry blocks promotion. Preserve 0.12 API/fixture conformance and measure total
host-plus-worker memory and paired latency through the bound evaluation envelope.
The existing single-host shared-view smoke is useful groundwork and does not
satisfy these broker tests.
