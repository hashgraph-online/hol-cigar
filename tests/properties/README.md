# WP19 property and concurrency qualification

This independent Cargo workspace executes semantic properties against production crates and uses
Loom to enumerate bounded schedules for cache publication, snapshot visibility, optimistic context
revisions, outbox fencing, subscription cursors, invalidation, and shutdown.

Run `cargo test --locked --manifest-path tests/properties/Cargo.toml --all-targets`. The gate runs
seven exhaustive bounded Loom models, seven semantic properties at 512 cases each, and one memory
model smoke test. Proptest persists every shrunk failure beneath `tests/properties/regressions/`; a
new file in that directory is a required checked-in regression, never an ignored or quarantined
case.
