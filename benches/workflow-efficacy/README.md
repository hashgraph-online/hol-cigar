# Three-way workflow-efficacy evidence

This directory defines the content-free measurement and verification contract for the immutable
Honey `0.9.2/balanced_v1`, `0.9.3/balanced_v3`, and `0.9.4/balanced_v4` treatments. It does not
contain qualification observations.

`workflows.v1.json` is the governed actual-workflow fixture authority. It binds the exact Hiero
source snapshot for Solo, Consensus Node, Block Node/TSS, JSON-RPC, and EVM transaction-liveness;
blocking and effect-adjacent requirements; alternative evidence sets; typed tools/effects; terminal
oracles; denial cases; restart points; and single-axis mutations. `workflow_efficacy.py validate
--hiero-root ROOT` checks the exact source bytes, while `schedule --trials 20|50` emits the bounded
paired transport/restart/mutation schedule. The matching Draft 2020-12 schema is
`packaging/honey/schemas/honey-workflow-efficacy.v1.schema.json`.

`configuration.v1.json` pre-registers treatments, workflows, cohort sizes, ordering, metrics, and
the deterministic bootstrap. `verify.py` builds derived evidence from raw observations and then
independently recomputes it. Raw evidence must live in a new owner-only directory outside the
checkout; the checked-in release record may retain only its digest and byte length.

The historical cohort is five workflows by 20 measured trials and five warmups. The RC cohort is
five workflows by at least 50 measured trials and ten warmups. A pairing identity is the complete
tuple `(workflow, scenario, trial, turn)`. Treatment order is interleaved by the registered Latin
square, and RC blocks are deterministically shuffled from a recorded seed commitment. Even trials
exercise the embedded public crate boundary and odd trials exercise the local sidecar process
boundary. Every trial runs three materialized context cycles, two exact sealed deltas, revalidation,
an exactly-once effect fence, three durable checkpoints, restart, exact replay, and all nine closed
negative cases. Provider/model tokens and latency remain distinct from CIGAR-supplied tokens and
pipeline latency.

The independent Hiero checkout owns `scripts/compare_cigar_three_way.py`. Its qualifying interface
is `compare --candidate ROOT --baseline-092 ROOT --baseline-093 ROOT --cohort historical|rc
--evidence-dir NEW_ABSOLUTE_PATH`. It refuses an absent input, a dirty source, source reuse, the
wrong product authority, a runner profile mismatch, or an existing evidence directory.
It launches measured binaries under an operating-system network-denial sandbox and also removes
live-provider credentials. Absence of that sandbox is a qualification failure.

Build and verify an external evidence directory:

```text
python3 benches/workflow-efficacy/verify.py build --evidence-dir /absolute/new/evidence
python3 benches/workflow-efficacy/verify.py verify --evidence-dir /absolute/evidence
```

The build command expects exclusive `raw-observations.json`, `environment-receipt.json`, and
`configuration.json` inputs. It creates `aggregate-report.json`, `claim-ledger.json`, and
`evidence-manifest.json` without overwriting any existing file. The verify command checks every
attachment digest, treatment/order/pair invariant, metric value, aggregate, percentile, and
bootstrap interval.

Live-provider experiments are not deterministic evidence. A separate experiment must bind the
provider/model version and settings, randomize treatment order, use blind grading, enforce an
explicit spend cap, and retain provider receipts outside the checkout. The deterministic verifier
does not accept or sign live-provider output.
