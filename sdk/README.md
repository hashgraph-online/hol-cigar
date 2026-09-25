# CIGAR SDKs

For a **local context graph**, use TypeScript's `LocalContextGraph` from
`@hol-org/cigar/context`, Python's local graph API, or the Rust
[`cigar-context`](../crates/cigar-context/README.md) crate. These APIs require no HOL
account, hosted service, daemon, database, or model provider.

Start with the [published npm beta quickstart](../README.md#local-npm-quickstart).
The [TypeScript](typescript/README.md) and [Python](python/README.md) guides describe
the 0.11.0 distribution candidate, its native platform matrix, and the local
`cigar-context doctor` and `demo` commands. The TypeScript package
supports Node.js >=24.10.0 <25 and ESM. Reuse a graph across requests to retain its
indexes and exact-token cache.

## Remote protocol clients

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
Rust/Go remote SDKs retain `0.9.4`. Python and TypeScript `0.11.0` provide a local
Rust graph API without changing the frozen remote ABI. `local-context-release.v1.json` binds
these packages to Rust core `0.11.0` and the separate `cigar.context-worker.v1` stdio protocol.
See [the 0.11.0 release notes](../docs/release/context-sdk-0.11.0-notes.md) for changes and qualification limits.
