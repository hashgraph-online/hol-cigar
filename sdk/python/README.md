# `hol-cigar`

Local context graphs, exact token budgets, source citations and reviewed answers for
Python applications. **No HOL service, account, API key, daemon or database is required.**
CIGAR owns a Rust graph in a persistent local worker process.

This 0.14.0 candidate contains a broker for independent agent processes. See the
packaged [broker guide](BROKER_GUIDE.md) for host/client authority, provenance,
reviews and failure semantics. Installed candidate tests have passed across seven
native targets; the 24-hour soak and remaining release gates are still pending.
Qualification applies to the exact artifacts named in their receipts.

## Install and check

The 0.14.0 candidate targets Python `>=3.14 <3.15`. The distribution is `hol-cigar`;
the Python import is `cigar_sdk`. The corresponding npm package is `@hol-org/cigar`.

```sh
python3.14 -m pip install /absolute/path/to/hol_cigar-0.14.0-py3-none-macosx_11_0_arm64.whl
python3.14 -m cigar_sdk.local_cli doctor
python3.14 -m cigar_sdk.local_cli demo
python3.14 -m cigar_sdk.examples.shared_views
```

Install the exact wheel and matching qualification receipt for your platform.
The example filename is for macOS ARM64; seven native targets are built. This
candidate is not a published PyPI release. Each native wheel bundles its worker;
no Rust compiler or separate worker installation is required.
See the bundled [changelog](CHANGELOG.md) for migration details. The supported
protobuf requirement is `>=6.33.5,<8`, qualified at minimum/current versions.
The environment also gets a `cigar-context` command. `doctor` verifies a real local
compile; `demo` runs the complete workflow. Add `--json` for machine-readable results.

## Five agents sharing one graph in one host

The trusted host creates one graph and gives each cooperating agent a scoped view:

```python
from cigar_sdk import LocalContextGraph

with LocalContextGraph("run-unique-domain") as graph:
    view = graph.create_view({
        "id": "agent-1", "allowed_sources": ["shared-policy", "agent-1"],
        "writable_sources": ["agent-1"], "policy_revision": "host-policy-1",
    })
    view.replace_source("agent-1", [{"id": "task-1", "source": "agent-1", "text": "Retry once."}])
    result = view.compile({"required": ["task-1"], "max_tokens": 512})
    # Bind a draft to result["context"]["snapshot"]["id"], obtain independent reviews,
    # then call view.check_answer(result["context"], draft, reviews).
```

Import `LocalContextGraph` as shown below. Create five views on the same graph;
each stores only its scope definition. The packaged `shared_views` example runs
five concurrent scripted agents, checks citations/budgets and tests reviewed release
and missing-review abstention without a model provider.

`allowed` in a view request can only narrow the host's source scope. Empty sources
deny all; writable sources must also be readable. Source replacement rejects ID
collisions with other sources. `graph.revoke_view(id)` or redefining the view
invalidates old handles. Changes anywhere in its readable sources/edges require a
new review; updates strictly outside the scope leave the review valid. The returned
`checked_graph_revision` records when assessment occurred, not permission for a
later external action. The host must coordinate revalidation with effect execution.

Keep the root graph, view definitions and reviewer verdicts outside agent control.
Views are logical host scopes, not a sandbox or authenticated capability. Sharing
one process is appropriate only inside a trusted application/privacy domain. Use
a host-owned `LocalContextBroker` and one `LocalContextClient` per agent for
separate processes; never share Python objects through `fork()`. The broker can
persist admitted evidence in an explicitly configured local directory. Recovery
creates a new authority epoch: reissue grants, recompile and obtain fresh reviews.
Ordinary graph views remain in-memory handles. Native graph calls remain serialized.
HUMIDOR remains responsible for scheduling and recovery; adopting the optional
context-to-Honey bridge requires its separate integration qualification.

Existing root methods retain their exact 0.12 behavior, including conservative
global-revision stale-review rejection. New view methods require a worker advertising
`context_views.v1`; unsupported workers fail with `IncompatibleWorker`.

## Previous improvements from 0.11.0 to 0.12.0

Version 0.12.0 strengthens integrity checks and worker lifecycle handling while
reducing Python startup cost. Existing valid bundle IDs, context snapshots,
`cigar.context.v1`, the worker protocol and all 69 Python public exports are preserved.

| Measure | 0.11.0 | 0.12.0 |
| --- | --- | --- |
| Local graph API import, median | 59.06 ms | 6.50 ms (89% lower) |
| Import plus first graph, median | 109.72 ms | 62.83 ms (43% lower) |
| Worker-hashing peak Python allocation | 7.29 MB | 1.18 MB (84% lower) |
| First-graph Python peak RSS, median | 46.28 MB | 31.06 MB (33% lower) |
| Ambiguous non-string/NFC-colliding mapping keys | Could lose entries before hashing | Rejected before conversion |
| Protobuf dependency | Exactly 6.33.5 | `>=6.33.5,<8`; qualified with 6.33.5 and 7.36.2 |

The performance comparison used installed packages on one macOS ARM64 host,
Python 3.14.7, protobuf 6.33.5 in both environments, warm filesystem and bytecode
caches, and 25 fresh-process samples per startup case. MB means 1,000,000 bytes;
Python RSS excludes the child worker. Steady-state compile performance was
essentially unchanged. These are measured results, not guarantees for every host.

Worker cleanup is now bounded and idempotent, preserves the original timeout or
transport error, and exposes `cleanup_complete`. Inherited graphs fail promptly
after `fork()`; create a new graph in the child. Worker verification still hashes
the complete executable on every launch, using a bounded buffer.

The comparison also recorded tradeoffs: some native workloads had up to 7.4%
higher median latency and one microsecond-scale p95 increased 26%. Native benchmark
peak RSS increased up to 3.5%; wheel sizes increased 0.13–0.17%. These observations
passed the defined median/RSS thresholds but do not establish zero degradation.
Offline answer-review results matched 0.11.0; no reduction in real-model
hallucinations is claimed. Workerless source builds now require explicit opt-in.

See the [full comparison and qualification scope](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/docs/release/context-sdk-0.12.0-comparison.md)
and the [changelog](CHANGELOG.md) for compatibility and migration details.

## Local context graph (no server or model required)

```python
from cigar_sdk import LocalContextGraph

with LocalContextGraph("my-project") as graph:
    graph.replace_source("src/auth.py", [
        {"id": "authorize", "source": "src/auth.py", "text": "def authorize(user):\n    return user.active\n"}
    ])
    result = graph.compile({"query": "authorize", "max_tokens": 1024, "reserve_tokens": 128})
    context_text = result["rendered"]  # place in your prompt's DATA/context role
    assert result["snapshot"]["stats"]["rendered_tokens"] <= 896
```

The persistent worker retains incremental indexes and its bounded exact `o200k_base` cache.
`upsert`, `remove`, `link`/`unlink`, atomic `replace_source`, line-preserving `chunks`,
`compile`, `verify`, `delta`, `apply_delta`, `stats`, and `clear_cache` expose the Rust core.
Source replacement reuses unchanged indexed documents. The optional `prompt_view(snapshot,
max_tokens)` returns a `LocalContextPrompt` with all selected text and short citation handles.
Keep its citation map and full snapshot; use `verify_prompt(prompt, snapshot)` or
`resolve_citation("c1", prompt, snapshot)` against the expected authorized snapshot. Its
separate exact budget fails without truncation. Token savings depend on citation overhead.
Input/request/snapshot types are exported as `LocalDocument`, `LocalContextRequest`,
`LocalContextSnapshot`, etc. Local methods are synchronous and thread-serialized; the existing
`AsyncCigarClient` remains the asynchronous **remote** client.

`required` IDs include their complete hard dependency/contradiction closure. Pass `allowed`
on every call when source permissions differ (`[]` authorizes none; omission permits the
whole caller-owned graph). `excerpt_mode="query_windows"` is opt-in; full text is the default.
Source withdrawal preserves hard edges, so missing required evidence fails closed. Snapshot
digests are integrity commitments, not signatures or authority. Deltas reduce transport/storage
bytes, not stateless model prompt tokens. Token budgets include Rust-rendered citations but
exclude the provider envelope; reserve that separately. Retrieval optimizations preserve the
previous selected evidence. Answer review adds a host-enforced release contract;
it does not establish real-model quality without a separately evaluated reviewer.

Use `with` or `close()` to release the worker. Each graph owns one process and privacy-local
cache. Defaults: 30-second call timeout, 32 MiB request, 64 MiB response, 100k documents,
256 MiB indexed text, 2048 cache entries/8 MiB cached text. Customize `limits` and `timeout`.
Cache clearing drops strings but does not guarantee memory zeroization. A `LocalContextError`
has a content-free `code`; timeout/protocol/pipe failure closes the graph and never retries
mutations. Invalid wire fields also close it. A lock-wait `Busy` error leaves the active call alone.

Create graphs in the process that uses them. After `fork()`, inherited graph
operations and `close()` raise `ForkedProcess` before touching inherited locks or
the parent's worker. Create a new graph in the child; use a spawn-based process
pool where possible. `close()` is idempotent and preserves ordinary primary errors.
If OS cleanup fails, `cleanup_complete` remains false and another close retries.

The native inventory covers macOS ARM64/x64, Linux glibc/musl ARM64/x64 and
Windows x64. Candidate installed tests and independent archive comparison pass
for this inventory. Complete release qualification is still in progress;
use the receipt for your exact archive rather than inferring support from a name.

Building a wheel from the portable source distribution without native staging
requires explicit `CIGAR_ALLOW_PORTABLE_WHEEL=1`. This also applies to intentional
`pip install --no-binary hol-cigar` source installs. These builds retain all SDK APIs,
but local graphs require an **explicit trusted absolute** `worker_path`. Build it from the matching
0.14.0 Rust source using Rust 1.92+:

```sh
cargo build --locked --release -p cigar-context --features bpe,broker-persistence --bin cigar-context-worker
```

Pass the resulting executable to `LocalContextGraph("my-project", worker_path="/absolute/path/to/cigar-context-worker")`.
No PATH discovery, install-time downloads, shell invocation, or automatic filesystem ingestion
occurs. Bundled worker bytes are checked against their package manifest before launch; this is
not a substitute for trusting the package publisher. The subprocess runs with your OS privileges
and inherits its environment; it is not a security sandbox. It adds startup/IPC/memory overhead
compared with embedding Rust directly. Reuse graphs to amortize initialization.

## Complete workflow and diagnostics

The same complete example run by `cigar-context demo` is importable:

```python
from cigar_sdk.examples.local_workflow import run_local_workflow

result = run_local_workflow()
print(result["status"])  # passed
```

It covers ingestion, dependencies, authorized compilation, compact citations, cache
reuse, trusted fixture reviews, source updates, deltas and stale-review rejection.
Its reviewer uses separately authored fixture facts. Replace it with an authenticated
semantic reviewer for real answers. Reuse your application's graph across requests.

```python
from cigar_sdk import get_local_context_capabilities

capability = get_local_context_capabilities()
print(capability["platform"], capability["worker_available"], capability["guidance"])
```

The capability API inspects platform and bytes without starting a worker. `doctor`
also compiles synthetic context and verifies it. Missing/unexecutable workers report
`WorkerUnavailable`, absent platform support reports `UnsupportedPlatform`, and altered
worker bytes report `WorkerIntegrity`. These errors do not mean HOL services are missing.
An explicitly supplied matching worker can be checked with
`python -m cigar_sdk.local_cli doctor --worker /absolute/path`.

The installed `cigar_sdk` package includes `AGENT_GUIDE.md`, `BROKER_GUIDE.md`,
`SELECTION_EXPLANATIONS.md`, `SYNTAX_INGESTION.md` and `llms.txt`. The
[agent integration guide](AGENT_GUIDE.md)
explains explicit file ingestion, graph relationships, authorization and reviewed answers.

## Compatible remote client

Choose `AsyncCigarClient` or `CigarClient` when connecting to an existing CIGAR server.
Both expose all 45 frozen v1 operations, bounded deadlines, typed problems, resumable
streams, pagination, fixed idempotency keys, safe retry and local bundle/delta verification.
They accept your server's URL; HOL hosting is optional. `CONTEXT_ABI` remains `cigar.context.v1`.

```python
from cigar_sdk import AsyncCigarClient, TypedOperationRequest, create_idempotency_key, models

async with AsyncCigarClient("https://cigar.example", bearer_token=token_provider) as client:
    result = await client.compile_context_bundle(
        TypedOperationRequest(
            models.CompileContextBundleRequest(plan_id=plan_id),
            idempotency_key=create_idempotency_key("compile"),
        )
    )
```

Every nominal request and response is validated against the frozen payload schema.
Mutating retries reuse the exact caller-provided key and bytes. Effect dispatch is
always one attempt. Synchronous and asynchronous streams are explicit context
managers so callers can close the underlying response deterministically.

Token providers accept the remaining call timeout in seconds. Injecting a custom
`HttpTransport` requires `trust_custom_transport=True`; the default transport ignores
ambient proxies and refuses redirects. The wheel and source distribution both include
the shared fixture, so `cigar-qualify-bundle` works from a clean installation.

Honey distributions also install `cigar-agent-b-handoff`. It accepts an existing recipient-bound
handoff, then records one typed, evidence-backed result with independent idempotency keys. The
Agent B bearer token is read only from `CIGAR_AGENT_B_TOKEN`, never a command-line argument. Run
`cigar-agent-b-handoff --help` for the required handoff, plan, base-commit, revision, claim,
evidence, and caller-generated acceptance/result idempotency keys. The example requests no
follow-up capability and never dispatches an effect.

Remote HTTPS construction requires an explicit `bearer_token` value or provider. The SDK never
discovers credentials from the URL, environment, project configuration, proxy settings, or a
redirect target. Explicit cleartext loopback mode remains available only for local development.

## Answer review

Call `graph.review_keys(draft)` to bind an `AnswerDraft`'s claims to the snapshot
provided to the generator. Obtain `LocalClaimReview` verdicts through a separate,
trusted host review path, then call `graph.check_answer(request, draft, reviews)`.
Only display the assessed claims when `decision == "release"`. The check recompiles
current authorized context and rejects stale snapshots/reviews. Missing reviews,
unresolved support, invalid citations or unreviewed explicit conflicts block release.
`confidence_bps` is optional telemetry (0–10000), never permission. Keep reviews and
policy outside model control; CIGAR does not run a semantic judge. See the
[core contract](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/crates/cigar-context/README.md#check-answers-before-display).
