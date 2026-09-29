# Context to execution integration evidence

Status: v0.14 development source; local validation only. This is not a published
package, a production authorization decision or a model-quality experiment.

The optional Python `dispatch_context_effect` and Node `dispatchContextEffect`
adapters connect a consumed local context binding to the existing CIGAR/Honey
effect client. They preserve the prepared effect ID, intent digest, observed
revision and caller's idempotency key. The host resolves current trusted reviews
after reading the remote effect and immediately before consuming the binding.
An agent cannot supply an execution command through its restricted broker port.

The adapter uses the two existing generated operations. It creates no service,
credential, intent, approval, reconciliation or retry policy. Local graphs and
broker clients continue to work without HOL services. This optional execution
path requires the application's explicitly configured effect client.

## Validated local paths

The integration test starts actual CIGAR HTTP routing and typed effect handlers
on literal loopback. Python and Node run in separate processes, each with a real
native context worker. Honey's real effect engine persists to SQLite and the real
worker processor performs the final authorization check. Its deterministic
connector records a synthetic send; it does not contact an external tool.

| Scenario, in each SDK | HTTP dispatch calls | Connector sends | Checked outcome |
| --- | ---: | ---: | --- |
| Current reviewed context and authorized effect | 1 | 1 | Succeeded; one durable attempt/receipt |
| Successful claim followed by an error acknowledgement | 1 | 1 | SDK reports uncertainty; same durable effect completes |
| Context changes after the effect read | 0 | 0 | Refused; effect remains authorized with no attempt |
| Bound intent differs from prepared intent | 0 | 0 | Refused; effect remains authorized with no attempt |
| Honey authority revoked before worker send | 1 | 0 | Failed without entering the connector |
| Ambiguous connector result then reconciliation | 1 | 1 | Unknown, then succeeded; one reconciliation and no second send |

All twelve scenarios passed on local macOS ARM64. The consumers read the same
status back through their generated clients. An independent SQLite connection
verifies the final retained version, intent and attempt count. Reprocessing the
existing outbox job does not enter the connector again. The successful raw log is
`CIGAR/releases/cigar-0.14.0-development/context-effect-honey-integration-02.log`.
The failed `-01.log` records an expired test-fixture clock; the corrected fixture
uses a current per-case clock and leaves production deadline checks intact.

The SDK suites additionally use deterministic wire fixtures for malformed or
substituted replies, u64 revisions above JavaScript's safe-number limit, stale
review/policy, exhausted revisions, lost replies, invalid inputs and callback-time
mutation. These tests verify refusal and uncertainty paths; a fixture's declared
outcome is not evidence that a real connector achieved it.

The full local regression run passed 452 Python tests plus 39 subtests, 146 Node
tests and 192 ordinary daemon library tests. Python statement/branch coverage is
93.42% / 86.57% overall and 100% / 100% for the new adapter. Strict Python typing,
daemon Clippy, changed-file lint/format, coverage-policy tests and generated local
asset checks pass. Complete regression logs, the Python XML result and coverage
JSON use `context-effect-adapter-` in the same development evidence directory.

## Reproduction

Build the matching native context worker with `bpe,broker-persistence`, compile
the TypeScript SDK, and install the locked Python development environment. Supply
explicit absolute paths for these test inputs:

```text
CIGAR_TEST_WORKER                 native context worker
CIGAR_TEST_PYTHON                 Python 3.14 executable with SDK dependencies
CIGAR_TEST_NODE                   supported Node executable
CIGAR_TEST_CONTEXT_EFFECT_NODE    sdk/typescript/dist/tests/context-effect-consumer.js
```

Then run:

```sh
cargo test --locked -p cigar-daemon --lib checked_context_sdk_honey_terminal_outcomes \
  -- --ignored --nocapture --test-threads=1
```

This test is explicitly selected because ordinary Rust-only environments do not
have the SDK consumers. Missing inputs fail it; it does not silently skip them.
The development workflow selects it on macOS after building both SDKs. The
platform-independent SDK refusal tests are selected on all three development
operating systems. Hosted execution remains pending.

## Boundaries still requiring application integration

- This is a check at queue admission, not a lock spanning Honey's later send.
  Execution-critical freshness belongs in the existing intent preconditions and
  must be rechecked by the execution authority.
- The host must validate that the reviewed claims justify the prepared action.
  The helper binds identities; it does not decide semantic truth. A local context
  snapshot is not a governed remote bundle and cannot substitute for its ID.
- A dispatch response may say `dispatching` or `unknown`; neither means success.
  Observe/reconcile the same effect. Never resolve uncertainty by creating a new
  intent or blindly rerunning the helper.
- The test's trusted authority, review labels and connector are authored fixtures.
  No model was called, and no independent efficacy or production policy claim is
  made. The SQLite readback is not a power-loss or cross-process key-rotation test.
- HUMIDOR's existing generated-client integration must opt in without changing
  its effect/replay authority or enabling an excluded deployment profile. That
  adoption, hosted qualification and exact distribution tests remain P2/Q work.
