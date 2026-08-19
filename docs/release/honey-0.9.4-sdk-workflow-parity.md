# Honey 0.9.4 four-SDK workflow parity

Status: closed for source-tree SDK behavior; installed-artifact qualification remains a separate
H094-800 gate.

Qualification date: 2026-08-18.

## Contract authority

Rust, Python, TypeScript, and Go consume the same
`sdk/workflow-context-session.v1.json` authority. Each SDK test pins the exact 20-phase state
inventory, 17-event inventory, 18 resume actions and operation mappings, five error-code spellings,
three quarantine reasons, retry fences, replay dimensions, identity formats, telemetry bounds, and
effect-state vocabulary. A missing, reordered, or renamed contract value fails independently in all
four suites.

The stable error-code order is:

1. `invalid_transition`
2. `invalid_event`
3. `identity_mismatch`
4. `invalidated`
5. `limit_exceeded`

The retained workflow scenarios behaviorally exercise the first three errors and assert that every
failed transition is atomic. `limit_exceeded` is retained for bounded delta, replay-cycle, and turn
counters. Failed bundle revalidation is represented durably by the `invalidated` quarantine reason,
not by a transient exception. Every SDK pins both the closed error inventory and the quarantine
mapping, so callers receive the same machine-readable result category in each language.

## Executed workflow matrix

Each SDK passed the same six focused tests:

| Scenario | Required semantic outcome |
| --- | --- |
| Shared contract inventory | Exact contract-to-SDK projection |
| No-effect cycle | Exact replay reaches `replay_verified` |
| Eight-delta bound | Next target is a full-bundle checkpoint |
| Ambiguous effect retry | Reconciliation advances and revalidation is required |
| Cancellation | Late provider result is rejected and state remains quarantined |
| Invalid transition | Failure is atomic and its diagnostic is content-free |

The executed results were:

| SDK | Command target | Result |
| --- | --- | --- |
| Rust | `cargo test -p cigar-sdk --test workflow_session` | 6 passed |
| Python | `python -m pytest -q sdk/python/tests/test_workflow_session.py` | 6 passed |
| TypeScript | `node --test sdk/typescript/dist/tests/workflow-session.test.js` | 6 passed |
| Go | `go -C sdk/go test ./...` | complete module passed |

All commands ran offline with the repository's locked/cached dependencies. No dependency was
installed or hydrated during qualification.

## Cross-language semantic identity oracle

The independent `wp13_cross_sdk` test computes the Rust reference result from the retained replay
vector, then invokes the Python, TypeScript, and Go verifiers over the same bytes. It requires every
implementation to emit the exact reference result rather than accepting a merely equivalent local
success. The result binds all five replay dimensions:

- bundle/delta selection;
- materialization;
- model-result identity;
- tool/effect decisions; and
- outcome.

`cargo test -p cigar-replay --test wp13_cross_sdk` passed both tests: exact four-language replay
reproduction and uniform rejection of duplicate JSON keys. Semantic identities use the shared
`sha2-256-multihash-lowercase-hex` format and record identities use lowercase UUIDv7.

## Decision

The source SDKs meet the H094-800 workflow parity requirement: the same state machine, identity
dimensions, durable outcomes, and stable machine-readable failure categories are enforced across
all four languages. This evidence does not substitute for the later clean-install gate. That gate
must rerun the workflows from the closed assembled artifacts without a repository-path dependency.
