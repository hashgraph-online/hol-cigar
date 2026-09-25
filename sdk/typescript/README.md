# `@hol-org/cigar`

Local context graphs, exact token budgets, source citations and reviewed answers for
Node.js applications. **No HOL service, account, API key, daemon or database is required.**
CIGAR owns a Rust graph in a persistent local worker process.

## Install and check

Version 0.12.0 is an unpublished candidate for ESM on Node.js `>=24.10.0 <25`:

```text
npm install --save-exact /absolute/path/to/hol-org-cigar-0.12.0.tgz
npx --no-install cigar-context doctor
npx --no-install cigar-context demo
```

Install the exact archive from the candidate's qualification report. Public default
installs remain on 0.11.0 until a separate publication decision. This candidate
includes the canonical-CBOR union decoding repair and bounded worker hashing.

`doctor` verifies a real local compile. `demo` runs ingestion, dependency selection,
citations, cache reuse, trusted fixture reviews, source updates and stale-review
rejection. Add `--json` for machine-readable results. Both run without a model provider.
The package has no install script and downloads no worker at runtime.

## Local Rust context graph

```ts
import { LocalContextGraph } from "@hol-org/cigar/context";

const graph = await LocalContextGraph.create("my-project");
try {
  await graph.replaceSource("docs/retries.md", [
    {id: "retry-policy", source: "docs/retries.md", text: "Retry at most three times."},
  ]);
  const result = await graph.compile({query: "retry", max_tokens: 512, reserve_tokens: 64});
  console.log(result.rendered); // use as ordinary context data in your application's prompt
} finally {
  await graph.close();
}
```

The local-only `/context` entry point avoids loading remote/protobuf code. Root exports also
include the new API without removing existing exports. `upsert`, `remove`, `link`/`unlink`,
atomic `replaceSource`, line-preserving `chunks`, `compile`, `verify`, `delta`, `applyDelta`,
`stats`, and `clearCache` use the same Rust selector, citations, exact `o200k_base` accounting,
incremental indexes, and bounded token cache as the Rust library. No server or model is needed.

The optional `promptView(snapshot, maxTokens)` returns a `LocalContextPrompt` with every
selected text block and short citation handles. Retain its citation map and full snapshot;
`verifyPrompt(prompt, snapshot)` and `resolveCitation("c1", prompt, snapshot)` check against
the expected authorized snapshot. A separate exact budget fails without truncating evidence.
Token savings depend on citation overhead. Source replacement reuses unchanged indexed documents.

The 0.12.0 distribution matrix includes macOS 11+ ARM64/x64, Linux x64/ARM64 with
glibc 2.28+ or musl 1.2+, and Windows x64. The release checks require every advertised
worker before publication. Browser, edge runtimes that prohibit subprocesses, and
CommonJS are outside this package's runtime contract. On an unsupported platform,
an explicitly supplied, trusted absolute `workerPath` can select a worker built from
the matching Rust 0.12.0 source. There is no install script, runtime download, PATH
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
are rejected, not silently rounded. Customize graph/cache `limits`; default cache is 2048
strings/8 MiB. `clearCache` drops retained text but does not promise zeroization.
Errors expose a content-free `LocalContextError.code`. Timeout, malformed wire fields, and
protocol/pipe failures permanently close the graph; no mutations are automatically retried.

## Complete workflow and diagnostics

Import the same complete example run by `cigar-context demo`:

```ts
import { runLocalWorkflow } from "@hol-org/cigar/examples/local-workflow";

const result = await runLocalWorkflow();
console.log(result.status); // passed
```

Its reviewer uses separately authored fixture facts. Replace that reviewer with your
authenticated support-checking process for real answers; the library does not judge
arbitrary claims. Keep a graph alive across requests in your application, and use
`replaceSource` after edits so the cache and indexes retain their value.

```ts
import { getLocalContextCapabilities } from "@hol-org/cigar/context";

const capability = getLocalContextCapabilities();
console.log(capability.platform, capability.worker_available, capability.guidance);
```

The capability API inspects local worker bytes without spawning. `doctor` additionally
starts the worker, compiles synthetic context, verifies the snapshot and closes it.
`WorkerUnavailable` means a missing/unexecutable worker; `UnsupportedPlatform` means
there is no matching bundled target; `WorkerIntegrity` requires reinstalling verified
bytes. These errors do not indicate missing HOL services. For a deliberately supplied
matching worker, use `LocalContextGraph.create("project", {workerPath: "/absolute/path"})`
or `cigar-context doctor --worker /absolute/path`.

The installed package includes `AGENT_GUIDE.md` and `llms.txt`. The
[agent integration guide](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/sdk/LOCAL_CONTEXT_GUIDE.md)
covers explicit file ingestion, graph relationships, authorization and the answer-review flow.

## Compatible remote client

Choose `CigarClient` when connecting to an existing CIGAR server. It supports all 45
frozen HTTP operations, resumable SSE streams, bounded deadlines, abort signals,
typed problems, pagination, idempotency-bound retries and local bundle/delta verification.
It accepts your server's URL; HOL hosting is optional. The exported `CONTEXT_ABI`
constant remains `cigar.context.v1`.

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

## Answer review

Use `await graph.reviewKeys(draft)` to bind every atomic claim to the supplied
snapshot. Obtain `LocalClaimReview` verdicts from a separate trusted host reviewer,
then call `await graph.checkAnswer(request, draft, reviews)`. Display only assessed
claims when `decision === "release"`. The check recompiles current authorized
context and refuses stale snapshots/reviews, invalid citations, missing support
or unreviewed explicit conflicts. `confidence_bps` (0–10000 or null) is telemetry;
it never authorizes release. Keep policy and verdicts outside model control.
CIGAR does not run a semantic judge. See the
[core contract](https://github.com/hashgraph-online/hol-cigar/blob/v0.12.0/crates/cigar-context/README.md#check-answers-before-display).
