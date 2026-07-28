# `hol-cigar`

`hol-cigar` is the Python SDK for [CIGAR](https://hol.org/cigar), an open protocol
developed by [HOL](https://hol.org).

> **Developer preview:** version `0.9.1` is evaluation software. It is unsupported,
> is not production-qualified, and does not carry the full CIGAR release
> qualification.

The distribution name is `hol-cigar`; the Python import package remains
`cigar_sdk`.

## Install

Python 3.14 is required for this preview.

```sh
python -m pip install "hol-cigar==0.9.1"
```

## Use

The SDK exposes all 45 frozen CIGAR v1 operations through synchronous and
asynchronous clients. It provides typed problems, bounded deadlines, safe retry,
resumable streams, pagination, fixed idempotency keys, and local semantic
bundle/delta verification.

```python
from cigar_sdk import (
    AsyncCigarClient,
    TypedOperationRequest,
    create_idempotency_key,
    models,
)

async with AsyncCigarClient(
    "https://cigar.example",
    bearer_token=token_provider,
) as client:
    result = await client.compile_context_bundle(
        TypedOperationRequest(
            models.CompileContextBundleRequest(plan_id=plan_id),
            idempotency_key=create_idempotency_key("compile"),
        )
    )
```

The exported `cigar_sdk.CONTEXT_ABI` constant is `cigar.context.v1`.

Remote HTTPS construction requires an explicit bearer token or token provider.
The default transport ignores ambient proxies and refuses redirects. Explicit
cleartext transport is limited to loopback development.

## Qualification and limitations

This package uses the bounded Honey developer-preview standard for its selected
surface: authority and protocol drift checks, focused SDK tests, wheel and source
archive inspection, clean-install checks, license/notice verification, README
rendering checks, and artifact checksums.

Long-duration fuzzing, mutation qualification, soak, production chaos and scale
campaigns, two-builder reproducibility, production support, and GA claims remain
deferred. Passing the package gate is not evidence of production qualification.

The machine-readable profile is
[`packaging/pypi/release-profile.v1.json`](https://github.com/hashgraph-online/hol-cigar/blob/main/packaging/pypi/release-profile.v1.json).

## Source and license

- CIGAR website: [hol.org/cigar](https://hol.org/cigar)
- Protocol home: [hol.org](https://hol.org)
- Source: [hashgraph-online/hol-cigar](https://github.com/hashgraph-online/hol-cigar)
- Issues: [GitHub Issues](https://github.com/hashgraph-online/hol-cigar/issues)
- License: Apache-2.0
