# `hol-cigar`

Local context graphs, exact token budgets, source citations and reviewed answers for
Python applications. **No HOL service, account, API key, daemon or database is required.**
CIGAR owns a Rust graph in a persistent local worker process.

## Install and check

Version 0.11.0 supports Python `>=3.14 <3.15`. The PyPI distribution is `hol-cigar`;
the Python import is `cigar_sdk`. The corresponding npm package is `@hol-org/cigar`.

```sh
python3.14 -m pip install 'hol-cigar==0.11.0'
python3.14 -m cigar_sdk.local_cli doctor
python3.14 -m cigar_sdk.local_cli demo
```

When evaluating an unpublished candidate, install the exact wheel for your platform
instead of the registry version. Release status is recorded in the repository's
[distribution plan](https://github.com/hashgraph-online/hol-cigar/blob/codex/cigar-0.11.0-distribution/docs/proposals/cigar-0.11.0-distribution.md).
The environment also gets a `cigar-context` command. `doctor` verifies a real local
compile; `demo` runs the complete workflow. Add `--json` for machine-readable results.

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

The 0.11.0 wheel matrix includes macOS 11+ ARM64/x64, Linux x64/ARM64 with glibc 2.28+
or musl 1.2+, and Windows x64. The release checks require every advertised wheel
before publication. Each platform wheel contains its worker and needs no Rust compiler.

The portable source distribution and wheels built without native staging retain all SDK APIs,
but local graphs require an **explicit trusted absolute** `worker_path`. Build it from the matching
0.11.0 Rust source using Rust 1.92+:

```sh
cargo build --locked --release -p cigar-context --features bpe --bin cigar-context-worker
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

The installed `cigar_sdk` package includes `AGENT_GUIDE.md` and `llms.txt`. The
[agent integration guide](https://github.com/hashgraph-online/hol-cigar/blob/v0.11.0/sdk/LOCAL_CONTEXT_GUIDE.md)
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
[core contract](https://github.com/hashgraph-online/hol-cigar/blob/v0.11.0/crates/cigar-context/README.md#check-answers-before-display).
