# Installed comparison: first 0.14 development study

Status: compatibility passes; five startup guardrails fail. This study does not
qualify the candidate for promotion. Its results remain retained while startup
changes are investigated.

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

Native archive builds omit the workspace release profile. The next experiment
will retain its symbol-stripping and link-time optimization settings in the
packaged build configuration, preserving full SHA-256 verification on every
launch. A compact lazy-export table will preserve all 110 export targets while
reducing Python source parsing. Neither change is considered successful until a
new frozen installed comparison passes; this study is never overwritten.
