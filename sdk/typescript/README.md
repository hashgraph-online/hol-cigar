# `@cigar/sdk`

The CIGAR v1 ESM client supports all 45 frozen HTTP operations, resumable SSE streams,
bounded deadlines, abort signals, typed problems, pagination, idempotency-bound retries,
and local bundle/delta verification. It has no install script and downloads no binaries.
The exported `CONTEXT_ABI` constant is the exact string `cigar.context.v1`.

```ts
import { CigarClient, createIdempotencyKey } from "@cigar/sdk";

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
