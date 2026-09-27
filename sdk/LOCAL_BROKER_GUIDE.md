# Sharing one CIGAR graph across agent processes

Status: v0.14 development source. Python and Node SDK tests cover independent
1/5/12-agent processes on macOS ARM64, including mixed-language clients. Durable
restart, installed artifacts, other platforms and sustained load qualification
are still pending. This guide does not describe a published v0.14 package.

One trusted application owns a `LocalContextBroker`. Each agent receives its own
`LocalContextClient`, bound to sources and limits chosen by that application.
Five agents can use one graph and one native worker. They do not each need an
index or a HOL service. The existing `LocalContextGraph` and in-process views
remain available and do not open a listener.

## Host setup

These examples require a matching broker-capable worker. During source testing,
pass its absolute path explicitly. Qualified bundled distributions will resolve
their own worker when the path is omitted.

```python
from cigar_sdk import LocalContextBroker

with LocalContextBroker(
    "project-run", worker_path="/absolute/path/to/cigar-context-worker"
) as host:
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

await using host = await LocalContextBroker.create("project-run", {
  workerPath: "/absolute/path/to/cigar-context-worker",
});
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

## Experimental evidence persistence

The v0.14 development worker can retain admitted evidence in an explicitly selected
local directory when built with `broker-persistence`. The development prototype
has Unix and local-NTFS Windows storage adapters. Windows runtime, hosted platform,
power-loss and performance qualification are pending. The default broker remains
in memory.

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
space. Receipts retain a bounded suffix and its chain anchor. The prototype writes
the full evidence image per mutation; its cost at large graph sizes is still under
evaluation. A too-small limit fails closed and may require reopening with larger
bounds. Preserve all database sidecars after a crash so SQLite can recover them.

Stored checkpoints contain private source text. Their hashes detect inconsistent
bytes; they provide neither encryption nor protection against replacing the whole
store with an older valid copy. Use a protected local filesystem and a trustworthy
host clock. Withdrawal removes current evidence but does not promise physical
erasure from storage devices or backups. An existing empty or malformed store
requires host investigation; it is never automatically replaced by an empty graph.
