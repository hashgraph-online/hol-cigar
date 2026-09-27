# Installed comparisons: 0.14 development

Latest status: compatibility passes and 112/115 performance guardrails pass in
the second study. Three startup guardrails remain failed; the user accepted these
specific startup costs as release exceptions on September 27, 2026. Neither study qualifies
the candidate for promotion. The first study and all its failures remain below.

The frozen study is `installed-regression-01` under the local development evidence
directory. Its plan SHA-256 is
`796ad29d29aba77899c571b8152da1dba32d6329f207335b65d6a0839340ebe3`.
The [registered plan](../proposals/context-release-comparison-0.14.0.md) fixes the
workloads, paired cohorts, failure handling and 10% latency/20% RSS guardrails.

## Exact treatments

All three environments use identical Python 3.14.7 executable bytes and protobuf
6.33.5. Every measurement child runs under macOS network denial. Measurements
were sequential with no concurrent local build, test, benchmark or soak.

| Treatment | SDK source | Native source |
| --- | --- | --- |
| Released 0.12 | `940fc65ee11ccda957649d7e5f1de5a4fa88e07a` | Same commit |
| Retained alpha | `7c3a348112b6d3538b323a09724fd2de92b89c74` | `65918385764f45c507d8e46a88215db1a73c90ce` |
| 0.14 development | `5aa65aa9a2bf5388591519717562a61590a8f225` | `bb1e41788802cd749fc6b62d50e454d2e10e3a26` |

The alpha's native source is unchanged between its two recorded commits; its SDK
source is also unchanged at the later examined alpha commit `c8117349`. The
development SDK's bound build inputs are unchanged from its native source commit.
The development wheel retains the `0.13.0a1` metadata version. Distinct archive,
installed-source and worker hashes establish its identity; it is not relabeled
as an already published 0.14 artifact. The worker comes from the matching hosted
two-builder native matrix. Exact hashes are in the frozen plan and raw identity
receipts.

## Compatibility and resources

All 172 complete compilation results agree across the three versions. The 160
answer-review cases cover five confidence settings and agree throughout. Valid
semantic identity, rejection of ambiguous mappings and all prior public exports
are preserved. Every RPC cohort also preserves complete result identities.

Of 115 same-workload latency and total-memory comparisons, 110 stay within their
registered median guardrails. Every shared-client call-latency and sampled total
RSS comparison passes. No stale context is accepted. No scope, budget, citation
or process-cleanup failure occurs.

| Metric | Change vs 0.12 | Change vs alpha |
| --- | ---: | ---: |
| RPC compile median | −0.35% | +0.64% |
| Update/compile/delta/apply median | −0.52% | +1.15% |
| First graph median | +7.49% | +3.86% |
| Graph construction median | +3.39% | +3.60% |
| Remote API loading median | −0.23% | −0.10% |
| Base import median | **+10.85%** | **+11.02%** |
| Local API loading median | **+41.32%** | +9.20% |
| Worker integrity hashing median | **+44.51%** | **+42.71%** |

Changes are medians of paired process-cohort percentage changes. Their raw pairs
and bootstrap intervals remain in `observations/summary.json`. The import
intervals span the 10% threshold; both hashing comparisons and local API loading
versus 0.12 clearly exceed it. Failures are retained regardless of interval width.

For context, median import time is 2.12/2.16/2.40 ms for 0.12/alpha/development;
local API loading is 7.88/10.38/11.35 ms; hashing is 3.19/3.22/4.59 ms. Worker bytes
are 7,282,304 / 7,412,496 / 10,647,952. First graph latency is 64.75/67.04/69.53 ms.
These absolute costs explain the practical impact without excusing failed gates.

## Twelve scoped clients

These clients share one Python host. Independent Python/Node agent processes
have their separate [broker qualification](context-sdk-0.14.0-broker-qualification.md).

| Treatment/mode | Compile median | Sampled total RSS | Unaffected reviews released | Unrelated stale rejections |
| --- | ---: | ---: | ---: | ---: |
| 0.12 shared root | 0.302 ms | 89.28 MiB | 0 | 4,400 |
| 0.12 private graphs | 0.357 ms | 684.81 MiB | 4,400 | 0 |
| Alpha views | 0.286 ms | 89.66 MiB | 4,400 | 0 |
| Development shared root | 0.299 ms | 90.52 MiB | 0 | 4,400 |
| Development private graphs | 0.352 ms | 693.34 MiB | 4,400 | 0 |
| Development views | 0.279 ms | 90.62 MiB | 4,400 | 0 |

Every row rejects all 400 affected stale contexts, abstains on all 96 missing
reviews and all 96 confidently wrong fixture claims, and accepts no stale answer.
Views preserve the alpha's scoped-sharing benefit: unrelated source changes no
longer invalidate every agent's work, with much less memory than private graphs.
The trusted fixture reviewer supplies the contradiction labels. These outcomes
are not a measured model hallucination rate or evidence of a new semantic judge.

## Follow-up

The first study found that native archive builds omitted the workspace release
profile. Commit `be0d3a8104f74e612f1d24bd4fa0f4f3637ae0da` retains the reviewed
symbol-stripping, thin LTO, single codegen unit and abort-on-panic settings in the
packaged build configuration. Full SHA-256 verification still runs on every
launch. Its compact lazy-export table preserves all 110 export targets.

The [hosted native matrix](https://github.com/hashgraph-online/hol-cigar/actions/runs/36338269053)
passed all fourteen jobs, with all 63 native/oracle/source payloads matching
between independent builders across seven targets. The separate source matrix
also passed on Linux, macOS and Windows. These are development checks, not the
final installed SDK or publication qualification.

## Second frozen study

`installed-regression-02` repeats the original plan without changing its harness,
baseline wheels, cohort counts, budgets or guardrails. It uses the same Python
and protobuf versions, OS network denial and sequential measurements with no
concurrent local build, test, benchmark or soak. The candidate SDK and native
source both bind commit `be0d3a8104f74e612f1d24bd4fa0f4f3637ae0da`.

| Identity | SHA-256 |
| --- | --- |
| Frozen plan | `7c9754f54dd2eeaa1c2b1e36cd686e3e59c9f2f21c15702274f46337b701556c` |
| Summary | `c67bfd21a99ca0ff45112fbdbc1113f8188639eb284e691745161f4ee131d048` |
| Candidate wheel | `5da019374dbb6b402fc5bb7e5e39853e937be94a3d1751b36e69efc9e2e48581` |
| Installed SDK source | `d9dcd9c48c56424dfaba37c86f9e5375e54545f815b903d30e65827490077c76` |
| Bundled worker | `75d67f6b95cc73c9feb39c48e3c9c2fb320b2a0dcad90703d637d5a9b603f935` |

All 172 complete compilation results, 160 answer-review outcomes, valid semantic
IDs, previous public exports and RPC identities still agree. All shared-client
latency and total RSS comparisons pass. The worker is 8,449,936 bytes, 20.64%
smaller than the first development build, but still 16.03% larger than 0.12.

| Metric | Paired median change vs 0.12 | Paired median change vs alpha |
| --- | ---: | ---: |
| RPC compile | −6.48% | −6.08% |
| Update/compile/delta/apply | −2.36% | −3.04% |
| First graph | +2.40% | −1.62% |
| Graph construction | −2.06% | −2.17% |
| Base import | −2.12% | −4.04% |
| Local API loading | **+35.18%** | +3.45% |
| Worker integrity hashing | **+16.19%** | **+13.48%** |

The compile change versus 0.12 has a descriptive paired 95% interval of
−6.87% to −4.73%. The three failed startup comparisons have intervals of
32.87–37.58%, 14.52–17.44%, and 11.23–15.73%, respectively. All outliers remain
in the raw record, including the unusually slow candidate import cohort.

Absolute medians for 0.12/alpha/development are 6.70/8.64/9.05 ms for local API
loading, 3.15/3.20/3.66 ms for integrity hashing and 64.78/67.09/66.28 ms for
first graph construction. The local API growth partly predates this release in
the alpha's view API. The larger worker contains the broker and persistence
implementation. These explain the remaining costs; they do not turn failed
guardrails into passes or establish a blanket no-regression claim.
