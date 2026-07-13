# cigar-replay

Stability: application, pre-v1.

`cigar-replay` owns observable decision capture, immutable replay archives, exact dependency
reporting, recorded provider substitution, and the four replay contracts. It deliberately does not
capture hidden reasoning or expose a generic transcript field.

## Implemented foundations

- `DecisionCaptureBuilder` cross-checks the task, plan, manifest, bundle, materialization,
  invocation, recorded observations, verification receipts, output references, effects, and exact
  component fingerprints before sealing an archive.
- `DecisionArchive` binds a `DecisionRecord` to a sorted exact-dependency manifest. Its
  content-derived identity covers deterministic archive bytes with only the self-ID excluded.
- Capture requires exact policy and index evidence, binds the index to the plan watermark, and
  requires retained source identities to equal selected manifest and bundle provenance.
- `ReplayArchive` loads decisions only by exact `VersionId` and artifacts only by exact
  `ContentDigest`. `InMemoryReplayArchive` is the thread-safe hermetic reference implementation.
- `RecordedProviderTape` substitutes exact consumer, tool, connector, and effect responses in
  one-based order. It verifies response bytes and matches the request digest, provider fingerprint,
  observation kind, ordinal, and optional subject identity before consuming an entry.
- `ReplayCompleteness`, `MissingDependencyRow`, and `ReplayDiff` keep absence, tampering,
  component mismatch, semantic changes, and observation changes distinguishable.

The recorded tape has no callback, socket, connector, current-state lookup, or live fallback. Its
observable live-call counter is always zero. Empty responses are representable, while all entries
and byte totals remain bounded.

## Modes

- Evidence reproduction verifies retained source, blob, policy, index, manifest, bundle, and
  verification evidence without invoking a provider.
- Invocation reproduction reconstructs the exact final consumer input, declared parameters, tools,
  component artifacts and fingerprints, materialization, and environment without invoking them.
- Observational replay consumes the exact recorded transcript under denied egress. A mismatch or an
  unconsumed row fails; it never falls through to a live provider.
- Live comparison is a separate execution that requires fresh, request-bound authorization. Effects
  remain simulated unless the request names new, separately authorized effect intents.

Live verification supplies trusted current time; callers cannot backdate the authorization check.
Nonce and digest reuse are atomically reserved through `ReplayReservationLedger`. The in-memory
ledger is for embedded/test use; a daemon supplies durable reservations. All live output and the
terminal replay record are validated before fresh effects can reach the independent effect gate.

Non-live requests must set `simulate_effects = true`, omit live authorization, and name no
authorized effect intents. Their executions must report both egress and effect dispatch disabled.
See [Decision replay](../../docs/reference/decision-replay.md) for the operational and security
contract, [replay records v1](../../spec/context-abi/replay-records-v1.md) for record invariants, and
the [replay v1 vector](../../schemas/vectors/replay-v1.json) for cross-SDK digest reproduction.

## Exactness and failure behavior

Replay starts from a pinned decision ID. Missing dependencies produce an explicit incomplete result;
they are never replaced with a current source, policy, index, blob, schema, or implementation.
Digest and semantic-ID mismatches fail integrity validation before an observation is consumed or a
live dependency is called.

Foundation and recorded-provider errors expose stable categories and omit protected bytes. Debug
implementations report identities, counts, media types, and byte lengths rather than task,
invocation, response, or artifact contents.

## Limits

- At most 10,000 replay references, dependencies, observations, or provider-tape entries.
- At most 64 MiB in one retained artifact.
- At most 256 MiB of exact artifacts in one capture or recorded provider tape.
- At most 10,000 checks in one verification receipt; names are at most 512 UTF-8 bytes.

The in-process no-live surface is one layer of the non-live guarantee. Qualification also runs
observational replay inside an operating-system network-denial sandbox; a Boolean execution field
is not an egress control.
