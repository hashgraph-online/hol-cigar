# Honey TypeScript SDK

The historical Honey GitHub TypeScript asset identifies the unpublished `@cigar/sdk` package.
The separately qualified npm candidate is `@hol-org/cigar@0.9.4`. Until its staged publication is
approved, install only the exact reviewed local `hol-org-cigar-0.9.4.tgz` candidate.

## Offline clean-project install

Verify the tarball, create a new project, and install from the local filename with package-network
resolution disabled. Use the exact Node and package-manager cohort recorded by the release evidence.

<!-- docs-check: illustrative -->
```sh
mkdir honey-typescript-client
cd honey-typescript-client
pnpm init
pnpm add --offline ../hol-org-cigar-0.9.4.tgz
node -e 'import("@hol-org/cigar").then(m => console.log(m.PRODUCT_VERSION))'
```

## Typed client

The generated client binds operation identifiers, paths, canonical CBOR payloads, idempotency keys,
pagination, and structured errors. A custom `fetch` is trusted only when the caller explicitly opts
in; the built-in transport refuses insecure non-loopback endpoints.

```typescript
import { CigarClient, bundleId, verifyBundle } from "@hol-org/cigar";

const client = new CigarClient({
  baseUrl: "http://127.0.0.1:8765",
  allowInsecureLoopback: true,
  maxAttempts: 1,
});

const compiled = await client.compileContextBundle({
  payload: { plan_id: process.env.CIGAR_PLAN_ID! },
  idempotencyKey: "typescript-compile-1",
});
verifyBundle(compiled.payload);
console.log(bundleId(compiled.payload));
```

Do not retry an effect in `UNKNOWN` merely because a fetch failed. Query effect status and reconcile
with the same durable intent identity.

## Two-agent observer

A TypeScript observer can read the parent checkpoint, accepted handoff, typed result receipt, merge
outcome, and correlated evidence without receiving the parent transcript. It should verify:

1. the handoff recipient/audience and one-use policy;
2. accepted capabilities are a subset of requested and issuer capabilities;
3. result `base_commit_id` equals the intended parent base;
4. every claim points to immutable evidence; and
5. a merge either returns a content-addressed commit or stable typed conflict IDs.

The package includes `dist/examples/quickstart.js` and
`dist/examples/two-agent-observer.js`. Run them from the clean project after local installation; the
observer accepts an explicit distinct observer credential and does not inherit Agent A or Agent B
authority. See [two-agent coordination](honey-two-agent.md) for the authority model.
