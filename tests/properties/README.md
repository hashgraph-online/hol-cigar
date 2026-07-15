# WP19 property and concurrency qualification

This independent Cargo workspace executes semantic properties against production crates and uses
Loom to enumerate bounded schedules for cache publication, snapshot visibility, optimistic context
revisions, outbox fencing, subscription cursors, invalidation, and shutdown.

Run the native macOS gate with:

```sh
CARGO_NET_OFFLINE=true cargo nextest run --locked \
  --manifest-path tests/properties/Cargo.toml \
  --config-file tests/properties/.config/nextest.toml \
  --user-config-file none -P macos-qualification --no-tests fail --all-targets
```

The gate runs seven production-linked bounded Loom models, three model-governance tests, seven
semantic properties at 512 cases each, and one ordinary memory-model smoke test. The model
executions call the real compiler cache, MVCC store, context-space publication, durable worker
claim, event-page, dependency-invalidation, and daemon queue-admission state machines. The
compiler-cache and invalidation models use Loom-visible whole-state locks matching their production
critical sections; cursor and shutdown use Loom atomics around shared production decisions. The
already-`Send + Sync` store and space types run directly without a model-side serialization lock,
with an additional barrier-synchronized native race guard (64 snapshot/worker rounds and 16
context-publication rounds) so a weakened production lock is not hidden by the abstraction. The
checked [`model-refinement-v1.json`](model-refinement-v1.json) manifest is also the executable model
configuration: Loom 0.7.2, three threads, 1,000 maximum branches, preemption bounds two or four, no
duration or permutation truncation, and no explicit-exploration/checkpoint/location/log overrides,
132 exact schedules, and 14 required linearization branches. The source-binding test rejects
missing production anchors, model/config
drift, duplicate IDs/branches/mutants, and foreign platform execution; the divergence test proves
one deliberately invalid trace is rejected for every model.

The semantic families use the reviewed fixed seed `0x00c16a1900070512`, a 16,384-iteration shrink
bound, and direct failure persistence. Proptest persists every shrunk failure beneath
`tests/properties/regressions/`; a new file in that directory is a required checked-in regression,
never an ignored or quarantined case. Changing the seed, case count, shrink bound, persistence
path, model bounds, production bindings, branch inventory, or expected schedule counts is a
qualification-policy change.

This is native Apple-silicon macOS development diagnostic evidence. It is not a TSan, UBSan,
pinned-nightly, clean-candidate, installed-byte, or release receipt, and it must not be promoted as
one.
