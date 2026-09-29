# Local context broker implementation contract

Status: native authority, bounded scheduler and the explicit `--broker` worker
transport are implemented behind the opt-in `broker` Cargo feature. Python and
Node host/client facades have local source tests with independent 1/5/12-agent
processes, including mixed-language clients. Durable storage is implemented as a
Unix and Windows local-NTFS opt-in prototype; Windows runtime, platform/performance and installed
distribution qualification are pending; this is not yet a shipped capability.
The 0.13 views and ordinary 0.12 graph APIs remain available independently.
See the [development SDK guide](../../sdk/LOCAL_BROKER_GUIDE.md).

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

The separate `cigar.context-broker.v1` agent envelope carries a positive u32
request ID, requested queue deadline and a closed agent command. Its identity
comes from the authenticated connection and cannot be supplied in the envelope.
Host-only commands use a separate type and private channel. Agent
frames are capped at 2 MiB before decode; replies at 8 MiB. Private host limits
are 32/64 MiB. A malformed/truncated/oversized frame invalidates its connection;
the transport never scans onward to guess where the next request begins.

Each host-created grant binds a cryptographically random credential to one agent,
one current view and explicit quotas. The host distributes that credential through
protected application IPC, never arguments, environment variables or logs.
Each connection carries one command and begins with mutual HMAC-SHA256 proofs:

1. The client sends the expected epoch, public grant digest and a fresh 256-bit
   challenge. Each handshake message has a 1 KiB bound checked before allocation.
2. The broker returns a fresh server challenge and a server proof bound to the
   epoch, grant and both challenges. The client verifies it before sending any
   command or context. A process that reuses a stopped broker's port cannot prove
   possession of the former broker's grant secret.
3. The client returns a proof using a separate domain. The broker checks current
   grant expiry/revocation and the exact retained challenge before reading the
   command. It checks admission and source authority again at dispatch.

The grant secret never crosses the loopback connection. Fresh challenges reject
cross-connection proof replay; separate proof domains reject reflection. The
public test vector in `crates/cigar-context/fixtures/broker-authentication.v1.json`
was checked independently with Python and Node standard cryptographic libraries.
It fixes the exact transcript: lowercase 64-byte ASCII hex epoch, grant digest,
client nonce and server nonce after the NUL-terminated role domain. The HMAC key
is the raw 32-byte secret. The public grant digest is SHA-256 of
`cigar.broker-grant-id.v1\0` followed by the ASCII epoch and secret; server/client
proof domains are `cigar.broker-server-proof.v1\0` and
`cigar.broker-client-proof.v1\0`. The `\0` denotes one zero byte.
This same-host protocol does not provide encryption,
TLS channel protection or a boundary against host-privileged packet interception.

The server chooses the view from the authenticated grant. A client
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
The broker additionally binds its epoch and source revisions into the snapshot's
policy commitment. This keeps the existing claim-review keys tied to current
provenance, including when the document bytes themselves did not change.

The native core rejects stale or expired derivations conservatively: if a readable
source has a changed/withdrawn/expired transitive input, compilation and ticket
revalidation fail until the host refreshes or withdraws the derived source. The
agent does not receive hidden dependency locators through this failure. Declared
lineage is host metadata; the library cannot detect an omitted dependency.

## Scheduling, quotas and write conflicts

Use a single graph owner with bounded per-agent queues and round-robin dispatch.
The host has a separately bounded queue so an agent cannot consume its entire
admission capacity. Bound active connections, handshake time, frame bytes, queued
bytes, jobs per caller, token budget, retained tickets, proposals and staged bytes.
Limits are validated before queue admission, then authorization and expiry are
checked again at dispatch. Existing graph/document/cache limits remain effective.
The current transport defaults to 64 total connections, four authenticated
connections per grant, and separate 32 MiB input/output reservations. Input uses
one total deadline across handshake and command; slow partial writes cannot
renew it. Reply writes also have a total deadline. The active grant-connection
registry retains no idle grant records. Unauthenticated local connection flooding
can still consume the bounded listener capacity; these limits preserve resource
bounds and the private host channel, not availability against every local DoS.

Operations are non-preemptive initially. Fairness guarantees a dispatch opportunity
between bounded operations, not equal completion time for differently sized work.
Report queue delay, service time, p95/p99 and each agent's completion count. Do not
claim parallel Rust reads without implementing and qualifying them separately.

Cancellation/expiry before dispatch means the operation did not start. After
dispatch, a broken connection or timeout can make a mutation's outcome unknown.
Clients never automatically retry writes or restart the broker. A caller queries
the retained proposal/receipt or reconciles through the host. A failed client
connection must not by itself kill every other agent's graph.
Clients keep the duplex socket open until the reply. A half-close, reset or extra
request bytes cancel only that connection's queued work. Once dispatch has begun,
the caller must treat a lost reply as uncertain. Closing host stdin or sending
the private `close` command stops the owner and listener; no orphan service remains.

Every admitted source replacement carries an expected source revision. Versions
are monotonic for the epoch, including withdrawal and change-back (ABA); an empty
source does not reset to revision zero. Admission compares the proposal's expected
revision again immediately before commit. Exactly one competing replacement of
the same revision can win. Identical source bytes and unchanged admission metadata
may remain a no-op; changed provenance or policy must invalidate dependent work.
Source revision numbers use canonical decimal strings on the wire, preserving
all u64 values in Python and JavaScript. Numeric JSON versions, leading zeroes,
signs, whitespace and out-of-range values are rejected.
Host-declared edge changes also use source CAS and advance affected source versions.
An endpoint's source identity remains reserved while a relation still references
it, so another source cannot substitute a withdrawn dependency node. The host can
explicitly remove dangling relations; identity retention has its own byte bound.

## Durable recovery

The Rust broker now provides an evidence-only `BrokerCheckpoint` codec through
`host_checkpoint(max_bytes)` and `ContextBroker::from_checkpoint(...)`. The
caller selects a byte limit, capped at 512 MiB. Canonical versioned bytes carry a
content digest; unknown fields, duplicate/noncanonical members, altered bytes,
invalid graph structure and incompatible current limits are rejected. Checkpoint
bytes contain private source text and require protected storage. Their digest is
neither a signature nor protection against replacing a whole checkpoint.

Recovery preserves source versions, withdrawal tombstones, relation ownership and
declared lineage. It rebinds internal lineage to a fresh random authority epoch.
No grant, ticket, proposal, answer draft, review or effect permission is restored.
Expired evidence remains stale. Saved monotonic remaining life caps each source's
new deadline, and a wall clock preceding capture is rejected. Correct time still
depends on the host's clock. The codec performs no filesystem writes. The worker
now owns an optional persistent store, exposed through both SDKs' host options.

Persistence is explicit and host-owned. Reuse existing storage/locking primitives
where their contracts fit; do not create a competing Honey authority format.
A standalone journal records versioned source/provenance/edge mutations and their
expected/result revisions with bounded records, a sequence and hash chain. It
needs an exclusive writer lock, durable commit markers and atomic checkpoints.
Credentials and release permissions are never serialized as reusable authority.

The `broker-persistence` feature reuses the repository's pinned embedded SQLite.
The Unix prototype requires an absolute host-owned directory with mode
0700, protected ancestor directories, a regular single-link database with mode
0600, and verified sidecar identity.
It refuses symlinks, unexpected WAL sidecars, unsupported schemas and empty
existing stores; it does not chmod or reset them. An EXCLUSIVE connection retains
the acquired writer lock. Each transaction stores a whole bounded checkpoint plus
an expected/result source-revision receipt. Receipts use sequence numbers and a
hash chain, with an explicit rolling anchor when the configured history is pruned.
SQLite documents
[exclusive connection locking and durability settings](https://www.sqlite.org/pragma.html#pragma_locking_mode)
and its [atomic commit assumptions](https://www.sqlite.org/atomiccommit.html).
The worker reads back locking, DELETE journaling, EXTRA synchronization,
fullfsync, page-size and resource settings. Process-crash fixtures exercise before
write, between journal/checkpoint updates, before commit, and after commit. Power
loss and advertised-platform qualification remain required. Profile full
checkpoint rewrites against bounded source/document updates before selecting the
release path. Core graph use retains its existing dependency and I/O behavior.
Explicit `create_directory` can create only a final private directory component;
existing permissions are never repaired. The Windows adapter uses a protected
inheritable owner-only DACL, checks local fixed NTFS storage and pins every
directory component with directory-data read access and without write/delete
sharing. Attribute-only handles do not enforce that exclusion. Database handles prevent
replacement; sidecars must retain one owner ACE and a regular single-link identity.
It rejects UNC paths, reparse points and alternative streams. Windows raw APIs
remain inside `cigar-windows-ipc`; disabling its named-pipe feature keeps Tokio out
of the standalone worker dependency closure. An inherited sidecar may be owned
by the local Administrators group only if that is the launching process token's
default owner; its sole full-access DACL entry must still identify the exact
process user. Other group owners or added ACL subjects are rejected. This keeps
the existing trust boundary excluding privileged administrators, without changing
the credential-file ACL policy. Windows assigns new-object ownership from
[TOKEN_OWNER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner)
and inherits a default file ACL from its parent. Windows runtime tests are pending.
No persistence capability is advertised by an ordinary memory-only broker.

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

The native host now implements `host_bind_execution` and
`host_take_execution_handoff`, exposed through both SDKs only when the worker
advertises `execution_handoff.v1`. A binding retains the exact prepared effect
ID/intent multihash, ticket/submission/context/snapshot identities, epoch, source
authority digest and trusted review digest. The review input includes a host-owned
authority revision, verdicts and answer policy. Reviews are bounded before cloning
or hashing; retained bindings use the existing ticket quotas.

Take requires the entire retained binding and current host review input. It checks
freshness again and consumes the binding before returning; a lost reply cannot
justify taking/sending again. Agent commands cannot decode either host operation.
Replacing a submission invalidates its prior binding; a restart restores none.
This is a transient context precondition, not a Honey approval, journal or dispatch
permit. It establishes no cross-system lock or freshness guarantee after take.
The execution adapter must preserve the exact existing intent and authority checks;
its Honey/HUMIDOR integration and terminal-oracle tests remain required.

## Required evidence

Tests must exercise actual independent Python and Node client processes, including
cross-language clients of the same broker. Run 1/5/12 agents with shared, private
and overlapping scopes; both readable and unreadable source updates; malformed
requests; identity/view spoofing; revoked grants; forged tickets; unreviewed
proposals; stale/competing writes; queue saturation; disconnect before/after
dispatch; killed worker; torn journal and checkpoint recovery; and old-epoch replay.
Include an impersonating listener that fails the server proof, replayed and
reflected proofs, mid-handshake revocation, and one grant saturating its connection
allowance while another remains usable. The native worker tests exercise real
TCP connections from Rust driver threads; they do not substitute for independent
installed Python and Node agent processes.

Short fault schedules precede a 24-hour 12-agent soak. A single scope leak, lost
authorized update, stale authority acceptance, silent journal loss or blind effect
retry blocks promotion. Preserve 0.12 API/fixture conformance and measure total
host-plus-worker memory and paired latency through the bound evaluation envelope.
The existing single-host shared-view smoke is useful groundwork and does not
satisfy these broker tests.
