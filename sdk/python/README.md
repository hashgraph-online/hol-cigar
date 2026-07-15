# `cigar-sdk`

The Python 3.14 SDK exposes all 45 frozen CIGAR v1 operations through both
`AsyncCigarClient` and `CigarClient`. Both facades provide bounded deadlines,
typed problems, resumable streams, pagination, fixed idempotency keys, safe retry,
and local semantic bundle/delta verification.
The exported `cigar_sdk.CONTEXT_ABI` constant is the exact string `cigar.context.v1`.

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

Remote HTTPS construction requires an explicit `bearer_token` value or provider. The SDK never
discovers credentials from the URL, environment, project configuration, proxy settings, or a
redirect target. Explicit cleartext loopback mode remains available only for local development.
