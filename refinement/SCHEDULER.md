# Opportunity miner and scheduler

The scheduler accepts only closed, content-addressed signal records. Public signals
may carry a bounded summary; hidden-partition signals must be aggregate-only and
must set `summary` and `owner_hint` to null. The source commitment remains available
for audit without exposing task text, oracle content, critical IDs, or per-task
diagnostics.

Each signal maps to one declared intervention family and owner-path set. Product
families forbid the harness, schemas, corpus, policy configuration, CI, release
scripts, lockfile, and unrelated SDK/product surfaces. The infrastructure family
forbids production crates and SDK paths. A task packet therefore cannot mix a
product hypothesis with evaluator changes.

Selection is deterministic and budgeted. Its score combines declared base priority,
normalized signal magnitude, reproducibility, an uncertainty/exploration bonus,
mean observed effect, estimated evaluation cost, and penalties for invalid or
rejected attempts. Exact signal, hypothesis, and patch commitments are
deduplicated. The score only chooses an experiment; R06 promotion remains the sole
acceptance authority.

Every decision includes the ranked candidate commitments, exclusions, and a
component-level explanation. Terminal iteration IDs replayed from the external
ledger and supplied trial-history fingerprints are excluded, allowing a restarted
run to select the next eligible experiment without repeating completed work.
