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
`cigar.context.v1`; the packaged `release.json` binds that value to package version `1.0.0-dev.1`.
