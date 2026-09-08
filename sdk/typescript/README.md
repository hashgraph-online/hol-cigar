# `@hol-org/cigar`

0.10.0 beta 1 for Node.js 24 ESM applications:

```text
npm install ./hol-org-cigar-0.10.0-beta.1.tgz
```

Verify the signed GitHub assets before installation. Registry publication requires a separate
maintainer approval; once listed, use `npm install '@hol-org/cigar@0.10.0-beta.1'`.
The prerelease channel is `beta`, never `latest`. The package intentionally does
not claim CommonJS or browser-runtime support, and consumers should pin an exact version for
reproducible workflow execution.

The CIGAR v1 ESM client supports all 45 frozen HTTP operations, resumable SSE streams,
bounded deadlines, abort signals, typed problems, pagination, idempotency-bound retries,
and local bundle/delta verification. It has no install script and downloads no binaries.
The exported `CONTEXT_ABI` constant is the exact string `cigar.context.v1`.

## Local Rust context graph

```ts
import { LocalContextGraph } from "@hol-org/cigar/context";

await using graph = await LocalContextGraph.create("my-project");
await graph.replaceSource("src/auth.ts", [
  {id: "authorize", source: "src/auth.ts", text: "function authorize(user) { return user.active; }"},
]);
const result = await graph.compile({query: "authorize", max_tokens: 1024, reserve_tokens: 128});
const contextText = result.rendered; // ordinary DATA/context, never an instruction/authority grant
console.assert(result.snapshot.stats.rendered_tokens <= 896);
```

The local-only `/context` entry point avoids loading remote/protobuf code. Root exports also
include the new API without removing existing exports. `upsert`, `remove`, `link`/`unlink`,
atomic `replaceSource`, line-preserving `chunks`, `compile`, `verify`, `delta`, `applyDelta`,
`stats`, and `clearCache` use the same Rust selector, citations, exact `o200k_base` accounting,
incremental indexes, and bounded token cache as the Rust library. No server or model is needed.

Beta 1 bundles a worker only for macOS ARM64. Other platforms retain the remote SDK; local graphs
require an explicitly supplied, trusted absolute `workerPath` built from the matching Rust
0.10.0-beta.1 source (`cargo build --locked --release -p cigar-context --features bpe --bin cigar-context-worker`).
They are not natively qualified by this beta. There is no install script, runtime download, PATH
lookup, shell, or implicit file ingestion. The worker is a persistent subprocess, not a native
Node addon or sandbox; it inherits your environment and OS privileges. Bundled bytes are checked
against their package manifest, not independently authenticated. Reuse a graph to amortize
startup; IPC and process memory cost more than embedding Rust directly.

Pass `allowed` IDs for each query when source permissions differ (`[]` authorizes none).
`required` evidence includes complete hard dependencies/counterclaims. Source withdrawal leaves
hard edges fail-closed until explicitly repaired. Full text is default; `excerpt_mode:
"query_windows"` opts into source-line excerpts. Digests detect changes; they are not signatures.
Delta reuse saves transport/storage bytes, not stateless prompt tokens. Budgets count complete
Rust-rendered context; reserve provider framing/history/output separately.

Use `await using` or `await graph.close()`. Calls are ordered, with at most 32 pending (configurable
`maxPending` 1..128), 64 MiB aggregate queued requests, 32 MiB per request, and 64 MiB per response.
`timeoutMs` defaults to 30 seconds **per active exchange**, including pipe writes; queued calls
wait their turn. `close()` aborts the active call and rejects the queue. Unsafe numeric integers
are rejected, not silently rounded. Customize graph/cache `limits`; default cache is 1024
strings/8 MiB. `clearCache` drops retained text but does not promise zeroization.
Errors expose a content-free `LocalContextError.code`. Timeout, malformed wire fields, and
protocol/pipe failures permanently close the graph; no mutations are automatically retried.

## Compatible remote client

```ts
import { CigarClient, createIdempotencyKey } from "@hol-org/cigar";

const client = new CigarClient({
  baseUrl: "https://cigar.example",
  bearerToken: process.env.CIGAR_TOKEN,
});

const result = await client.compileContextBundle({
  payload: { plan_id: planId },
  idempotencyKey: createIdempotencyKey("compile"),
}, { timeoutMs: 15_000 });
```

Every mutating method preserves the caller's idempotency key across retry attempts.
`dispatchEffect` is never retried automatically, even when a larger attempt count is configured.
Use `for await` or `await using` with `subscribeSpaceEvents`; reconnections send the last
verified event ID.

Bearer providers receive the call's abort signal. Supplying a custom `fetch` requires
`trustCustomFetch: true`; the SDK still requests `redirect: "error"`. Published source
maps contain their exact source text, including declaration maps, and the package has no
postinstall hook.

Remote HTTPS construction requires an explicit `bearerToken` value or provider. The SDK never
discovers credentials from the URL, environment, project configuration, proxy settings, or a
redirect target. Explicit cleartext loopback mode remains available only for local development.
Node proxy environment variables are rejected when using the default fetch implementation. A
caller that intentionally supplies a proxy-aware fetch must inject it and set `trustCustomFetch`;
that explicit transport becomes the caller's channel-identity and redirect-policy boundary.

Run `pnpm qualify:bundle` to verify the packaged cross-SDK fixture and print its semantic
bundle ID.

## Honey two-agent observer

The packaged `dist/examples/two-agent-observer.js` example uses a distinct observer credential and
only the disclosure-safe `previewHandoff` and `getSpaceLog` reads. It reports counts and authority
attenuation without printing task text, source material, result claims, credentials, or event
payload digests:

```text
CIGAR_URL=http://127.0.0.1:8080 \
CIGAR_OBSERVER_TOKEN=... \
CIGAR_HANDOFF_ID=... \
CIGAR_SPACE_ID=... \
node dist/examples/two-agent-observer.js
```

The observer principal must be provisioned independently. This example never accepts, records,
merges, or revokes a handoff and therefore does not receive Agent A or Agent B mutation authority.
