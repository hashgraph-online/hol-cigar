# Sharing one CIGAR graph across agent processes

Status: v0.14 candidate. Independent Python/Node process, load and fault studies
are recorded separately from the seven-platform installed archive tests. The
24-hour twelve-agent soak and remaining release gates are still pending. Use the
qualification receipt for exact artifact identities and scope. This guide does
not describe a published v0.14 package.

One trusted application owns a `LocalContextBroker`. Each agent receives its own
`LocalContextClient`, bound to sources and limits chosen by that application.
Five agents can use one graph and one native worker. They do not each need an
index or a HOL service. The existing `LocalContextGraph` and in-process views
remain available and do not open a listener.

## Host setup

Native candidate archives bundle a matching broker-capable worker, which the SDK
resolves automatically. A deliberate source/workerless build instead requires
an explicit trusted absolute `worker_path` in Python or `workerPath` in Node.

```python
from cigar_sdk import LocalContextBroker

with LocalContextBroker("project-run") as host:
    host.replace_source(
        "policy",
        host.source_revision("policy"),
        [{"id": "retry", "source": "policy", "text": "Retry at most three times."}],
        {
            "authority": "project-owner",
            "upstream_revision": "policy-v1",
            "observed_at_ms": 1,
            "valid_until_ms": None,
            "origin": "host",
            "derived_from": [],
        },
    )
    connections = [
        host.grant({
            "id": f"agent-{i}",
            "allowed_sources": ["policy", f"notes-{i}"],
            "writable_sources": [f"notes-{i}"],
            "policy_revision": "reviewed-policy-1",
        })
        for i in range(5)
    ]
    # Send each connections[i].export() only to that agent through protected IPC.
    # Keep the host alive until the agents finish. Never log these dictionaries.
```

Supply the real source observation time and upstream version in an application.
Provenance records are host assertions about evidence, not proof that it is true.
Declare derived inputs with their exact source revisions; changed, withdrawn or
expired transitive inputs make dependent evidence unavailable until refreshed.

Node uses the same native authority and wire contract:

```ts
import { LocalContextBroker } from "@hol-org/cigar/context";

await using host = await LocalContextBroker.create("project-run");
const connection = await host.grant({
  id: "agent-1", allowed_sources: ["policy"], policy_revision: "reviewed-policy-1",
});
// Pass connection.export() through protected application IPC, never a log,
// command-line argument, environment variable or shared public configuration.
```

Keep host objects and their worker pipes out of agent control. The host owns
source ingestion, grants, revocation, proposal admission, reviews and policy.
Clients cannot turn a request field into a different caller or a host operation.

## Agent setup

The host may pass the exported connection to a separately launched child over
its private stdin. The agent reconstructs only the restricted client:

```python
from cigar_sdk import LocalBrokerConnection, LocalContextClient

# config is the private connection dictionary supplied by the trusted host.
client = LocalContextClient(LocalBrokerConnection.from_config(config))
context = client.compile({"query": "retry policy", "max_tokens": 512})
client.revalidate(context["ticket"])
# context["rendered"] is evidence for the agent's prompt.
```

```ts
import { LocalBrokerConnection, LocalContextClient } from "@hol-org/cigar/context";

const client = new LocalContextClient(LocalBrokerConnection.fromConfig(config));
const context = await client.compile({query: "retry policy", max_tokens: 512});
await client.revalidate(context.ticket);
```

Workers advertising `selection_explanation.v1` also support
`client.explain(context["ticket"])` in Python and `client.explain(context.ticket)`
in Node. This revalidates the ticket's current authority and returns only selected
IDs and retrieval signals, with the original snapshot and exact tokenizer identity.
It is not truth confidence or permission for an effect. See
[selection explanations](SELECTION_EXPLANATIONS.md) for the record and cost.

Each operation uses a fresh authenticated connection to literal `127.0.0.1`.
There is no name lookup, remote service, credential discovery or worker download.
Both peers prove possession of the grant secret before context is transferred;
the secret itself is never transmitted on loopback. Connection representations
are redacted, but `export()` intentionally returns sensitive material.

Default grants last five minutes. The host can choose a lease and issue a new
grant; redefining a grant invalidates its old authority and tickets. This SDK
does not silently renew a lease. Revocation is immediate at the next authority
check. Construct new Python objects after `fork()`; inherited objects are rejected.

## Evidence writes and answer review

The host can preprocess parser-owned source with `broker.chunks_at_lines(document,
starts)` / `broker.chunksAtLines(document, starts)` when `document_boundaries.v1`
is advertised. This only partitions exact text; it does not admit evidence or
advance a source revision. See [parser integration](SYNTAX_INGESTION.md).

An agent calls `propose_source(request_key, source, expected, documents)` (Node:
`proposeSource`) for an assigned writable source. It cannot commit the source.
The trusted host inspects `proposal`, then admits it with provenance or rejects
it. Unadmitted text never becomes trusted evidence in the graph. Admission checks
the expected source revision again, so two competing replacements cannot both
overwrite the same version. Versions are decimal strings; do not convert them
to JavaScript numbers.

Host edge updates also require exact revisions. A directed edge's expected map
contains the source of its starting node. A contradiction contains both endpoint
sources because it is symmetric. Changes advance the affected versions, even if
an edge is later changed back.

For reviewed output:

1. The agent compiles context and submits a draft with `submit_answer` /
   `submitAnswer`, receiving a submission ID.
2. The host retrieves `submission(ticket)`, including the exact draft and its
   `review_keys`. A trusted reviewer evaluates those claims against the evidence.
3. The host calls `check_answer` / `checkAnswer` with that submission ID and the
   independently obtained verdicts. Missing review yields abstention. A replaced
   draft, changed source, expired grant or stale ticket prevents release.
4. The application displays only the assessed claims. Revalidate again at any
   later execution boundary; an answer assessment is not a tool-execution grant.

CIGAR verifies bindings, freshness and review coverage. It does not determine
semantic truth or remove the need for a trustworthy reviewer. Model-generated
review labels must not be treated as an independent correctness oracle.

## Replace a source across bounded batches

The development worker advertises `source_batches.v1`. The trusted host can
replace a source that does not fit one 32 MiB request while preserving one atomic
visibility point. The ordinary `replace_source` / `replaceSource` API remains
available. Neither interface reads files or invokes a parser/model automatically.

```python
expected = host.source_revision(source)
receipt = host.replace_source_batches(
    source, expected, document_batches, provenance, lease_ms=60_000
)
```

```ts
const expected = await host.sourceRevision(source);
const receipt = await host.replaceSourceBatches(
  source, expected, documentBatches, provenance, {leaseMs: 60_000},
);
```

Supply an iterable of nonempty document lists; Node also accepts an async
iterable. Generate bounded batches incrementally to avoid keeping the entire
source in the caller. An empty iterable withdraws the source. An empty batch
inside an iterable is an error. Documents must have unique IDs, the same source
locator and valid text/line bounds. Each complete document must still fit its
configured document limit; batching does not split a document.

The host stages the input privately. Existing context remains current during
staging, subject to normal grant, freshness and resource checks. Commit rechecks
the expected source revision, document ownership, provenance, derivation inputs
and graph limits. A competing source update therefore fails the commit with
`Conflict` and preserves the competing update. A validation failure publishes no
partial replacement. Commit consumes its handle even on definite validation
failure; obtain a new revision and start a new transaction when appropriate.

Applications needing explicit interleaving can use these host-only methods:

| Python | Node | Result |
| --- | --- | --- |
| `begin_source_replace(...)` | `beginSourceReplace(...)` | Expiring transaction handle |
| `append_source_documents(handle, documents)` | `appendSourceDocuments(handle, documents)` | Total staged document count |
| `commit_source_replace(handle)` | `commitSourceReplace(handle)` | Existing source replacement receipt |
| `abort_source_replace(handle)` | `abortSourceReplace(handle)` | Whether staging was discarded |

At most four staged replacements coexist. Leases default to one minute and may
be set from 1 to 300,000 milliseconds; appending does not extend the lease. Staged
input shares `retention.max_retained_bytes` with tickets and proposals. Reserve
sufficient capacity for active readers. The retention charge counts encoded
metadata/batches plus per-document overhead; it is not an exact heap bound or a
memory-zeroization guarantee. Source count, text, frame and graph bounds remain
enforced independently.

Durable mode writes one existing replacement checkpoint and receipt at commit;
staging is absent from recovery. The complete resulting graph must fit the
checkpoint bound, not just this source. `max_database_bytes` must be at least
twice `max_checkpoint_bytes` plus 65,536 bytes, with additional rollback-journal
disk space available. Batching does not eliminate full-checkpoint cost or stream
staged text to disk.

The convenience method attempts to abort on an input/append/commit error and
preserves the original exception if cleanup also fails. It never retries a
write. An unknown commit outcome still closes the owner; reconcile restored
source state before choosing a subsequent action. Expiry, consumption and restart
make old handles stale. A missing worker capability is rejected before consuming
the iterable or sending a batch command. Agents cannot use these host methods or
promote an unreviewed proposal by presenting a transaction handle.

## Bind context to an exact execution intent

The development host API advertises `execution_handoff.v1`. It can bind a current
reviewed submission to an effect already prepared by an execution authority.
It neither creates that effect nor approves or sends it. Agents have neither of
these methods. Local context use still requires no HOL service.

```python
review = {
    "authority_revision": "reviewer-policy-7",
    "reviews": trusted_reviews,
    "policy": {"min_sources": 1},
}
binding = host.bind_execution(
    ticket, submission_id, prepared.effect_id, prepared.intent_digest, review
)
# Resolve the current trusted reviewer revision, verdicts and policy again here.
handoff = host.take_execution_handoff(binding, current_review)
```

Node exposes `bindExecution(...)` and `takeExecutionHandoff(binding, currentReview)`.
The worker compares the complete retained binding and revalidates source versions,
provenance, view/grant authority, expiry, the exact submission and trusted review.
Changing the effect ID, intent digest, review authority revision, policy or verdicts
rejects the handoff. Unrelated out-of-scope source changes preserve valid work.
Repeated or competing takes cannot both succeed. A new submission invalidates an
older binding, and recovery restores no binding or consumption permission.

The review authority revision must come from current host policy; replaying a
cached value cannot prove the reviewer remains authorized. Review input has a
1 MiB accounting limit. Bindings consume the existing per-agent and total ticket
retention quotas. A worker lacking the advertised feature is rejected before
either command is sent.

Consume immediately before passing the exact effect ID/intent to a separately
authorized Honey dispatcher. Keep Honey's approval, expected revision, fencing,
idempotency and reconciliation checks. If a reply or send outcome is uncertain,
inspect/reconcile that existing effect; do not invent a new effect or retry blindly.
The handoff proves a context check at consumption time. It is not a signature,
execution grant, durable send receipt or lock spanning another system's send.

The optional Python `dispatch_context_effect` / Node `dispatchContextEffect`
adapter connects this primitive to an explicitly configured `CigarClient`:

```python
from cigar_sdk import dispatch_context_effect, ContextEffectDispatchUncertain

# effect_client is the application's existing authorized Honey/CIGAR client.
# Its prepare/authorize steps have already produced the exact bound effect.
try:
    result = dispatch_context_effect(
        host,
        effect_client,
        binding,
        resolve_current_trusted_review,
        idempotency_key=existing_dispatch_key,
    )
    # Often "dispatching": this is not yet a successful tool result.
    status = result.response.payload
except ContextEffectDispatchUncertain as error:
    # Retain this identity and use the existing status/reconciliation workflow.
    exact_effect = error.handoff["binding"]["effect_id"]
```

```ts
import { dispatchContextEffect } from "@hol-org/cigar";

const result = await dispatchContextEffect(
  host, effectClient, binding, resolveCurrentTrustedReview,
  {idempotencyKey: existingDispatchKey},
);
const status = result.response.payload;
```

The adapter reads the existing effect, verifies its ID/intent and authorized
state, resolves current trusted review, consumes the native handoff, then calls
the frozen `dispatchEffect` operation with the exact observed revision and supplied
key. Both HTTP calls use one attempt. A concurrent effect change fails Honey's
revision check; a context/reviewer change fails the native take. Every failure
after consumption preserves the handoff through `ContextEffectDispatchUncertain`;
no error makes that binding reusable. The adapter does not prepare, authorize,
poll, reconcile or retry automatically. An `authorized_for_retry` effect is only
eligible after Honey has separately established that state and the caller starts
a new explicitly reviewed context handoff for the same intent.

The resolver belongs to the trusted host and can be asynchronous in Node. It must
obtain current verdicts and reviewer authority, including all displayed claims;
an agent-provided verdict map is not a reviewer. The adapter accepts only the
existing generated effect port (`ContextEffectClient`), allowing an orchestrator
to pass its configured client without a new execution journal or service lookup.
Python's adapter is synchronous. Each HTTP call has a separate bounded timeout;
the host resolver and native channel retain their own deadlines.

This check occurs before admission to Honey's dispatch queue. A remote worker may
send later, so execution-critical freshness requirements must also be represented
in the effect's existing preconditions and enforced by the execution authority.
A local snapshot ID is not a governed remote bundle ID. The host must validate
the relationship between the reviewed claims and the prepared operation; this
helper does not infer it. The optional bridge needs the application's existing
effect service; all standalone context APIs remain service-free. This addition
does not enable HUMIDOR's excluded ContextGraph deployment profile.

## Limits, failures and shutdown

Agent frames are bounded at 2 MiB; replies at 8 MiB. Each client defaults to four
pending calls, a 30-second total timeout and a 30-second queue allowance. The host
also enforces per-agent quotas and fair, bounded queues. Native graph operations
remain serialized. Five clients do not imply five parallel compile operations.

`LocalBrokerError.dispatched` has three meanings:

| Value | Meaning |
| --- | --- |
| `False` / `false` | The operation was rejected before dispatch. |
| `True` / `true` | The broker reported a known failure after dispatch. |
| `None` / `null` | A sent operation's outcome is unknown after a transport failure. |

The SDK never automatically retries a command. After a lost proposal response,
inspect its retained status by request key and reconcile with the host. A missing
status while work may still be in flight is not proof that no write occurred.
A broken client connection does not close other agents' graph. A broken host
transport closes its worker because the host mutation may have completed.

The host must close the broker; Python context managers and Node `await using`
do so. Clients own no persistent worker or socket. Explicit ticket/proposal
forget operations release retained records, subject to their ownership checks.

This is a same-host application boundary. It does not encrypt traffic or sandbox
code with access to host memory, pipes or credentials. Separate unrelated hostile
tenants using OS/container isolation and distinct brokers. HUMIDOR owns model
routing and orchestration; its Honey execution integration remains separate.

## Optional local evidence persistence

The v0.14 worker can retain admitted evidence in an explicitly selected local
directory when built with `broker-persistence`, as the native candidate archives
are. Unix and local-NTFS Windows adapters are exercised by installed platform
tests. Process-crash tests do not establish power-loss durability, and the ongoing
soak is not yet completed evidence. The default broker remains in memory.

Pass an absolute directory on the host channel. Set `create_directory` to create
only its final component with private permissions; its parent must already exist.
Existing directories are validated without rewriting permissions. Unix requires
mode 0700. Windows requires a protected owner-only DACL with inheritance for
SQLite sidecars; ordinary temporary directories do not meet that contract.

```python
with LocalContextBroker(
    "project", storage={"directory": "/absolute/private/cigar", "create_directory": True}
) as broker:
    print(broker.capabilities()["storage"])
    # {"mode": "sqlite-checkpoint.v1", "restored": False} on first initialization
```

```ts
await using broker = await LocalContextBroker.create("project", {
  storage: {directory: "/absolute/private/cigar", create_directory: true},
});
```

On Windows use an absolute local drive path, such as `C:\private\cigar`.
UNC/network paths, non-NTFS volumes and junctions/reparse points are rejected.
Directory and database handles prevent replacement while the store is open.

Reopen the same directory and domain to restore committed source versions,
provenance, relations and withdrawal tombstones. Each evidence write commits its
checkpoint and revision receipt before success is returned. Concurrent owners,
wrong domains, unsupported schemas and inconsistent data are rejected. The SDK
checks the active storage mode so a worker cannot silently ignore this request.

Every restart creates a fresh authority epoch. Reissue grants, recompile context
and obtain fresh reviews. Agent credentials, proposals, context tickets, drafts,
review verdicts and execution permissions are never recovered. A storage failure
after a dispatched write closes the broker with an unknown outcome; inspect the
restored source revision before deciding what to do next. The SDK does not retry.

Options `max_checkpoint_bytes`, `max_database_bytes` and `max_journal_records`
default to 64 MiB, 256 MiB and 1,024 receipts. The database limit excludes its
temporary rollback journal: allow approximately another database's worth of disk
space. Receipts retain a bounded suffix and its chain anchor. Persistence writes
the full evidence image per mutation; budget for its cost as the graph grows.
A too-small limit fails closed and may require reopening with larger
bounds. Preserve all database sidecars after a crash so SQLite can recover them.

Stored checkpoints contain private source text. Their hashes detect inconsistent
bytes; they provide neither encryption nor protection against replacing the whole
store with an older valid copy. Use a protected local filesystem and a trustworthy
host clock. Withdrawal removes current evidence but does not promise physical
erasure from storage devices or backups. An existing empty or malformed store
requires host investigation; it is never automatically replaced by an empty graph.
