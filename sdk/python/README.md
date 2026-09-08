# `hol-cigar`

`hol-cigar` provides local Rust context graphs and the compatible remote CIGAR SDK from [HOL.org](https://hol.org).

> **Release candidate:** `0.10.0rc1`, Python 3.14. The platform wheel bundles the local context
> worker for macOS ARM64; it does **not** include the Honey daemon. Remote v1 APIs remain compatible
> with 0.9.4. Other native targets and production deployment are not qualified by this RC.

The Python 3.14 SDK exposes all 45 frozen CIGAR v1 operations through both
`AsyncCigarClient` and `CigarClient`. Both facades provide bounded deadlines,
typed problems, resumable streams, pagination, fixed idempotency keys, safe retry,
and local semantic bundle/delta verification.
The PyPI distribution is named `hol-cigar`; its stable Python import namespace remains `cigar_sdk`.
The exported `cigar_sdk.CONTEXT_ABI` constant is the exact string `cigar.context.v1`.

```sh
python3.14 -m pip install ./hol_cigar-0.10.0rc1-py3-none-macosx_11_0_arm64.whl
```

RC artifacts are prepared locally; this command does not imply registry publication.

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
Input/request/snapshot types are exported as `LocalDocument`, `LocalContextRequest`,
`LocalContextSnapshot`, etc. Local methods are synchronous and thread-serialized; the existing
`AsyncCigarClient` remains the asynchronous **remote** client.

`required` IDs include their complete hard dependency/contradiction closure. Pass `allowed`
on every call when source permissions differ (`[]` authorizes none; omission permits the
whole caller-owned graph). `excerpt_mode="query_windows"` is opt-in; full text is the default.
Source withdrawal preserves hard edges, so missing required evidence fails closed. Snapshot
digests are integrity commitments, not signatures or authority. Deltas reduce transport/storage
bytes, not stateless model prompt tokens. Token budgets include Rust-rendered citations but
exclude the provider envelope; reserve that separately. This RC does not claim new answer-quality
or token-reduction gains beyond the underlying Rust selector.

Use `with` or `close()` to release the worker. Each graph owns one process and privacy-local
cache. Defaults: 30-second call timeout, 32 MiB request, 64 MiB response, 100k documents,
256 MiB indexed text, 1024 cache entries/8 MiB cached text. Customize `limits` and `timeout`.
Cache clearing drops strings but does not guarantee memory zeroization. A `LocalContextError`
has a content-free `code`; timeout/protocol/pipe failure closes the graph and never retries
mutations. Invalid wire fields also close it. A lock-wait `Busy` error leaves the active call alone.

The portable source distribution and wheels built without native staging retain all SDK APIs,
but local graphs require an **explicit trusted absolute** `worker_path`. Build it from the matching
0.10.0 Rust source using Rust 1.92+:

```sh
cargo build --locked --release -p cigar-context --features bpe --bin cigar-context-worker
```

Pass the resulting executable to `LocalContextGraph("my-project", worker_path="/absolute/path/to/cigar-context-worker")`.
No PATH discovery, install-time downloads, shell invocation, or automatic filesystem ingestion
occurs. Bundled worker bytes are checked against their package manifest before launch; this is
not a substitute for trusting the package publisher. The subprocess runs with your OS privileges
and inherits its environment; it is not a security sandbox. It adds startup/IPC/memory overhead
compared with embedding Rust directly. Reuse graphs to amortize initialization.

## Compatible remote client

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
