# CIGAR SDKs

The Rust, TypeScript, Python, and Go SDKs expose the same 45 frozen operations and 70
nominal payload types. `capabilities-v1.json` is generated from the operation and payload
registries; `python3 generate_clients.py --check` rejects method, type, schema, capability,
or packaged-fixture drift.

Every package independently verifies `fixtures/semantic-bundle-v1.json` and prints:

```text
1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84
```

SDK-specific READMEs document clean install, transport, cancellation, streaming, and
safe-retry behavior. No client automatically retries `dispatchEffect`.

Each installed SDK exports its idiomatic `CONTEXT_ABI`/`ContextABI` constant with the exact value
`cigar.context.v1`; each packaged `release.json` binds it to that SDK's explicit release track.
Rust/Go remote SDKs retain `0.9.4`. Python `0.10.0rc1` and TypeScript `0.10.0-rc.1` add a local
Rust graph API without changing the frozen remote ABI. `local-context-release.v1.json` binds
these RCs to Rust core `0.10.0` and the separate `cigar.context-worker.v1` stdio protocol.
See [the SDK RC report](../reports/cigar-0.10.0-sdk-rc.md) for installable artifacts and qualification limits.
