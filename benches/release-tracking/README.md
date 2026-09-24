# Release tracking: v0.10.0-beta.1 versus v0.11.0

This suite adds two measurements beyond snapshot/contract unit tests and Hiero's
fresh-process UTF-8 adapter. The [registered plan](plan.json) fixes workloads,
comparisons and success criteria before execution. Everything runs locally;
`run.py` requires an OS policy denying external network access.

## Answer adoption and useful completion

Twenty honest-review episodes and four reviewer/task diagnostic episodes use a
small **fictional, closed-world workflow ledger**, not claims about actual Hiero
configuration. Scripted drafts encode typed propositions and are rendered
deterministically into text. Gold support and citation labels are computed from
the declared ledger independently of supplied reviewer verdicts. This tests
application behavior under controlled inputs, not a semantic judge or real-model
hallucination frequency.

Three treatments run the actual workers: v0.10.0 with a reference citation host,
v0.11.0 with the identical host, and v0.11.0 with native trusted answer review.
The reference host recompiles current state, checks snapshot identity and requires
selected citations for every nonempty claim. It is a stated application control,
not a native v0.10.0 answer API or a measurement of Hiero's production answer flow.
The second treatment checks whether an upgrade alone changes the result. The third
measures adoption of the review contract, including its additional review input.

Each episode permits two predetermined attempts, stopping on release or explicit
abstention. Error controls include confident arithmetic/unit errors, promoting
negative or synthetic observations into validated results, false premises,
irrelevant and fabricated citations, source instructions, missing/partial reviews,
source change/withdrawal and authorization revocation. Valid answers, repaired
answers, unanswered questions and an incomplete true answer prevent abstention or
partial truth from earning a misleading perfect task score.

Primary KPIs are erroneous/confident-error releases, supported-and-cited complete
answer yield, useful fact recall, valid-control retention, unanswerable abstention,
attempt count and context tokens consumed across all attempts. Metrics retain all
four diagnostic episodes: a wrong trusted positive can leak a false claim, a wrong
negative can refuse a true answer, and supported claims do not ensure completeness.
Authored confidence is not model calibration. The shared metrics engine calculates
descriptive Brier/ECE from it, but those values must never be presented as measured
model calibration. No confidence interval extrapolates these authored episodes to
users. The claimed benefit is conditional on adopting the API and supplying good
reviews; a v0.10.0 application can implement its own independent review policy.

## Persistent-worker efficiency and continuation correctness

Eight paired new-process sessions per cache mode run 768 documents and 64 queries
with 12 required documents each. Two warmup rotations precede three measured
rotations. Complete-source unchanged/changed refreshes each have one excluded
warmup and eight measurements; measured time includes source replacement plus
compiling the affected query. A second mode gives both versions the same small
256-entry cache to distinguish default cache capacity from other changes.

RPC timing includes JSON encoding, IPC, native compile/verification and JSON
decoding; transcript writes, Python checks and worker startup are excluded.
Refresh timings sum the two RPCs. Startup and per-child peak RSS are reported
separately. Version order alternates; bootstrap units are eight paired process
session medians, never thousands of dependent requests. A 10% median reduction
with a wholly positive descriptive interval is the registered improvement target.
A 20% median RSS increase is flagged separately. Failed performance targets remain
reported and do not cause workloads to be retuned.

The [separate cache-pressure plan](cache-pressure-plan.json) was registered after
the initial workload showed zero warm misses even with a 256-entry cache. It uses
768 single-document required-only queries, avoiding lexical selection work. It
tests the larger default cache directly and retains the equal-small-cache control.
Run it separately with `--section performance --performance-plan
benches/release-tracking/cache-pressure-plan.json`. The initial cohort remains a
valid measurement of selection/source-refresh work; the addendum does not replace it.

That 768-query cohort also fit both default caches (771 retained entries), and
showed no default-cache warm speedup. The subsequently registered
[1,536-entry](cache-pressure-1536.json) and [3,072-entry](cache-pressure-3072.json)
plans bracket the 1,024/2,048 default capacities. Both sizes were fixed before
either ran, retain the 256-entry control, and assert that their measured miss
behavior actually exercises the intended capacity boundary.

Every complete compile/update/delta/error response used for comparison must match
between versions. Additional continuation checks cover atomic invalid updates,
exact budget failures, authorization changes, tampered snapshots, verified deltas,
withdrawal and cache bounds. Statistics/cache telemetry are compared as metrics,
not incorrectly required to match across cache implementations.

## Reproduce

Build both unchanged version-specific workers with identical release settings and
registry records, using cached Cargo dependencies. The isolated build package has
the exact core version so the worker's compile-time identity stays correct; build
receipts bind the path dependency and unchanged source files.

```bash
python3 benches/release-tracking/build.py \
  --baseline /absolute/path/to/hol-cigar-0.10.0 \
  --cargo /absolute/path/to/rust-1.92/bin/cargo \
  --output /absolute/path/to/new-build-directory
python3 -m unittest discover -s benches/release-tracking -p 'test_*.py' -v
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  python3 benches/release-tracking/run.py \
  --build /absolute/path/to/new-build-directory/build.json \
  --output /absolute/path/to/new-results-directory
```

The macOS sandbox command is local and uses no provider. On another OS, use an
equivalent external-network deny policy. `--section answers` or `--section
performance` runs a targeted part in a new results directory. All inputs are
frozen and hashed before evaluation; raw request/response transcripts, timings,
resources, per-episode gold annotations and failures are retained. Source and
binary hashes are checked before and after execution. Existing results are never
overwritten.

The resource field `startup_ms` times the init RPC after process creation; it does
not include Python's `Popen` call. Report it as worker initialization latency.

The evaluator itself has tests for reviewer/gold independence, citation support,
typed values, unknown labels, refusal/completeness penalties, malformed input and
process-level pairing. This suite complements the earlier contract and Hiero
reports; it does not resolve Hiero's EVM prompt overflow or activate review in its
production adapter.

After a run, `verify_results.py RESULTS_DIRECTORY` checks original file hashes,
exact required bodies, current scope and independently reconstructed answer labels
against saved worker replies. `export.py` produces a compact review bundle;
`verify_export.py BUNDLE --originals` checks archived transcript bytes and lossless
reconstruction of all per-session records against their retained originals.
