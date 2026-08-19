# Honey 0.9.4 Hiero three-way RC comparison

Status: independently verified deterministic source-bound diagnostic. This is not final
installed-artifact, live-provider, signing, notarization, soak, or production qualification.

## Compared treatments

| Treatment | Source commit | Source tree | Profile | Runner SHA-256 |
| --- | --- | --- | --- | --- |
| Honey 0.9.2 | `35538959bce7497311906e4d370334a87abd362b` | `1157c5fb32b7faed65a8db5ae1e44505636b872f` | `balanced_v1` | `415a31d986ea07a67600974d271ef550563e9bbb60936cf08869926c9646a0fd` |
| Honey 0.9.3 | `a049fbc8ed81c9adc6b1a066ca053c5befc2578a` | `7179f2d0b78c8af314aebc8c86d62a0b6067e6ec` | `balanced_v3` | `fa0dd05315362010cadfb7c76f529edb670a94971addf8babf042c1f893891e9` |
| Honey 0.9.4 | `de8ec2214ac396b659512e112c1e2c0df25f865a` | `bb2f6f4d7bf80b63cdee459219b3ed3ac4917cc5` | `balanced_v4` | `48ab62f42519525836771983fccd2bede75f2204b3d6bfad37210aa3c474a259` |

The independent runner in the Hiero Pentest checkout verified the governed source bytes for Solo,
Consensus Node, Block Node/TSS, JSON-RPC, and EVM transaction liveness before execution. Each
treatment was built release-mode, locked, and offline. The runner used a recorded provider under
an operating-system network-denial sandbox, alternated embedded and local-sidecar boundaries, and
randomized treatment blocks from the retained seed commitment.

The RC cohort contained ten warmups and 50 measured trials per workflow and treatment: 150 warmup
executions, 750 measured observations, and 900 total executions. Deterministic trials varied
schedule, order, restart point, and registered source mutation rather than treating identical
repetitions as independent efficacy samples.

## Aggregate results

| Metric | 0.9.2 | 0.9.3 | 0.9.4 |
| --- | ---: | ---: | ---: |
| Valid completion | 100% | 100% | 100% |
| Blocking/gold/citation coverage | 100% | 100% | 100% |
| Useful-selection precision | 27.057% | 50.000% | **100.000%** |
| Semantic duplicate rate | 46.066% | 0% | **0%** |
| Mean exact selected tokens | 2,251.048 | 1,251.780 | **625.400** |
| Internal CIGAR pipeline mean | 3.114 ms | 2.037 ms | **0.823 ms** |
| Internal CIGAR pipeline p50 | 2.049 ms | 1.852 ms | **0.738 ms** |
| Internal CIGAR pipeline p95 | 7.658 ms | 3.268 ms | **1.216 ms** |
| Internal CIGAR pipeline p99 | 9.423 ms | 3.499 ms | **1.275 ms** |
| Process wall-time p50 | 25.715 ms | 24.852 ms | **23.552 ms** |
| Mean verified delta reuse | 93.199% | 87.506% | **75.134%** |

Against frozen 0.9.3, 0.9.4 used 50.039% fewer exact tokens and reduced mean internal CIGAR
pipeline latency by 59.627%. The paired 95% bootstrap intervals for candidate-minus-baseline means
were `[-662.933, -590.178]` tokens and `[-1.307, -1.123]` ms. Pipeline p50 and p95 improved
60.151% and 62.782%. Against frozen 0.9.2, exact tokens improved 72.217% and mean internal pipeline
latency improved 73.584%.

Process wall time improved less than internal pipeline time because each observation launches an
isolated sandboxed process. The p50 wall-time changes were 5.230% versus 0.9.3 and 8.410% versus
0.9.2; they must not be presented as equivalent to the internal library speedup.

## Workflow token and reducer-tail results

| Hiero workflow | 0.9.2 tokens | 0.9.3 tokens | 0.9.4 tokens | 0.9.4 reduction vs 0.9.3 | 0.9.3 reducer p95 | 0.9.4 reducer p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Block Node/TSS | 3,186.92 | 1,852.08 | **927.16** | 49.940% | 518.633 us | **147.181 us** |
| Consensus Node | 3,189.40 | 1,850.72 | **921.14** | 50.228% | 529.198 us | **153.719 us** |
| EVM transaction liveness | 846.16 | 467.84 | **234.20** | 49.940% | 107.671 us | **55.623 us** |
| JSON-RPC | 1,384.08 | 698.88 | **349.86** | 49.940% | 139.283 us | **77.248 us** |
| Solo | 2,648.68 | 1,389.38 | **694.64** | 50.004% | 345.898 us | **127.165 us** |

The 50-trial RC cohort closes the EVM tail uncertainty seen in an earlier 20-trial diagnostic:
0.9.4 improved EVM reducer p95 by 48.339%, exceeding the registered 30% small-workflow threshold.
No observation was excluded or replaced.

## Allocation and workflow assertions

In the workflow cohort, 0.9.4 reduced mean compiler allocation count by 77.126%, allocated bytes by
72.782%, and peak live bytes by 83.040% versus 0.9.3. These workflow measurements do not replace
the dedicated 128- and 512-candidate allocation gate; the claim ledger records that separate gate
as `not_evaluated`.

All 44 claims evaluated by this cohort passed. Every candidate observation completed three context
cycles and two sealed deltas, materialized three times, revalidated before use, fenced exactly one
effect, checkpointed each cycle, verified replay, passed all nine registered negative cases, and
failed closed where required. The ledger contains no failed evaluated claim.

## Evidence binding

| Attachment | Bytes | SHA-256 |
| --- | ---: | --- |
| Configuration | 5,122 | `975b756a5a26c98a012b9595591284aaa09412e28c4ef6617a8cddaeba38a3a7` |
| Raw observations | 1,531,792 | `b91500a89ecee0b4b745c4a04fe9d6a94d214729c2d7eda28c91b601b3bfe2fa` |
| Aggregate report | 220,243 | `7939bbd901b4ef16d57cdb887fa4ab6eaa62b8902e57acb27e590c4d15ee921d` |
| Claim ledger | 5,606 | `22d128f4fb720a03061dd302d35949d0271a59e45e08d9778db9a878bacd2545` |
| Environment receipt | 620 | `e5cc3b1cf137f6e494e2b6fcc32c1e8736425c5e6f7fedb69b32a06c0e2a168e` |

- Evidence ID: `ae0abda8daa92a00b1c5e1d75b947ee35d9abc75ef7364be0549558ad7b5c1e4`
- Seed commitment: `24deecaa337efc68c89172207a9e31f08c010851b32b7beec1f9c13e1128fdc7`
- Hiero orchestrator SHA-256: `3cc611a9bd0726bea29941826a16e24319e4a4759fcb7226a9c3480065e19421`
- Runner source SHA-256: `b7342f44ac22342294ebdbfc20494c76fee4c51d49d4641c85231fb46ceab2f2`
- Runner manifest template SHA-256: `53210135266f0860bcf787e90fd5e8e3db95496ef22c6a19b6b4be3b0d1755da`
- Host/toolchain: arm64 Darwin 25.6.0, Rust/Cargo 1.92.0, Python 3.14.6, protoc 33.2,
  AC power, no recorded thermal warning.

The independent verifier reconstructed every aggregate, percentile, paired interval, ordering
invariant, attachment digest, and claim from the retained raw observations and returned `verified`
for the evidence ID above.

## Limits and release interpretation

This cohort measures CIGAR-supplied context, deterministic terminal outcomes, and CIGAR pipeline
latency. Provider/model latency and tokens are separate and do not enter these claims. It does not
establish live-model completion quality, vulnerability discovery, universal performance,
cross-platform support, production safety, or final installed-artifact identity.

The measured 0.9.4 commit precedes this documentation-only packaging change. The release contract
therefore continues to require a final frozen-source and installed-artifact rerun. Raw observations
remain in owner-private evidence storage and are not added to the public 13-file release inventory.
