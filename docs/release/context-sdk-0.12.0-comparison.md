# CIGAR 0.11.0 to 0.12.0 comparison

Version 0.12.0 improves Python startup, semantic integrity validation, worker
lifecycle handling and package qualification. It preserves the context ABI,
worker protocol, valid canonical identifiers and all 69 Python public exports.
The npm 0.12.0 artifact also repairs union response decoding; its registry
publication is separate from the Python release.

## Baseline and method

The baseline is the published 0.11.0 npm/PyPI release at
`f00d5e932d4c1a0348d912ce883068f96d3ac6f9`. The primary installed comparison uses
the exact candidate archives from `ef0048c793be16dc256cc20a2998c3fefa81fd82`,
qualified by [this seven-platform run](https://github.com/hashgraph-online/hol-cigar/actions/runs/36171007366).
Release preparation updates documentation, the release title and the pinned PyPI
publisher for metadata 2.5 support; runtime code remains unchanged. The tagged release reruns qualification and identifies its
own final source and artifact hashes in `release-manifest.json`.

Measurements ran on one macOS ARM64 host with Python 3.14.7 and protobuf 6.33.5 in
both installed environments. Startup has 25 fresh-process samples per case,
alternating version order, two excluded warmups, warm filesystem/bytecode caches,
and five separate allocation samples. Persistent RPC has eight paired fresh-worker
sessions with 768 documents and 64 queries. Within-session calls are dependent.
Results are descriptive and do not guarantee performance on every machine.

The first final-artifact probe had unequal bytecode caches: the baseline had 29
cached SDK modules and the fresh uv install had none. It measured remote first
import at 55.25 versus 77.57 ms. After `compileall` prepared both environments
equally, the controlled run below measured 56.10 versus 50.15 ms. First-use source
compilation remains an installation-dependent cost; the unequal-cache probe is
not mixed into the controlled measurements.

## Measured changes

| Startup workload | 0.11.0 p50 / p95 | 0.12.0 p50 / p95 |
| --- | --- | --- |
| Package import | 60.01 / 71.48 ms | 1.54 / 1.74 ms |
| Local graph API import | 59.06 / 61.28 ms | 6.50 / 27.07 ms |
| Import plus first graph | 109.72 / 111.53 ms | 62.83 / 64.14 ms |
| Constructor after imports | 58.80 / 61.22 ms | 57.99 / 59.88 ms |
| Remote client first import | 56.10 / 73.42 ms | 50.15 / 64.54 ms |

Worker-hashing maximum traced Python allocation fell from 7,286,126 to 1,184,462
bytes. Every launch still verifies the entire executable. First-graph parent peak
RSS median fell from 46,284,800 to 31,064,064 bytes; these values exclude the worker.

The median of eight session compile medians was 0.3240 to 0.3233 ms;
update/compile/delta was 0.8078 to 0.8059 ms. These are essentially unchanged.
The latter's p95 across session medians increased 0.36%; it is not a request-level
p95 under production concurrency.

| Correctness contract | 0.11.0 | 0.12.0 |
| --- | --- | --- |
| Ambiguous non-string/NFC-colliding semantic map probes | Accepted | Rejected before entries can disappear |
| Valid npm union response fixtures decoded | 5/11 | 11/11 |
| Valid npm `publishSpace` variants decoded | 3/7 | 7/7 |
| Malformed union responses rejected | 7/7 | 7/7 |
| Requests sent per mutation fixture | 1 | 1; no decode-failure retry |
| Python public exports | 69 | All retained, including signatures and TypedDict shapes |
| Python protobuf dependency | Exactly 6.33.5 | `>=6.33.5,<8`, qualified with 6.33.5 and 7.36.2 |

The integrity issue is a canonicalization defect, not a SHA-256 collision. Valid
canonical bundle IDs and raw accepted CBOR spellings remain unchanged. Worker
cleanup preserves primary failures, handles partial initialization and concurrent
close, reports `cleanup_complete`, and rejects inherited graph use after fork.

## Observed increases and limits

Passing the defined 10% median-latency and 20% RSS investigation thresholds does
not establish zero degradation. In the separate native diagnostic corpus:

- Warm 50,000-document common-query median increased 3.484 to 3.743 ms (+7.4%).
- Warm 1,000-document selective-query p95 increased 5.292 to 6.666 microseconds
  (+26.0%, or 1.374 microseconds); the 50,000-document selective p95 rose 14.9%.
- The largest paired native-process peak RSS increase was 3.5%.

That corpus had only two paired process rounds. These increases are not established
as repeatable regressions and are not dismissed as noise. Cross-platform functional
qualification does not establish performance equivalence on every platform.
Extended soak behavior and performance under production contention are not
established by this comparison.

The measured candidate npm archive grew 0.017%, native wheels 0.129–0.174%, and
the sdist 20.6% (113,533 to 136,921 bytes), including more tests and documentation.
Release-document updates can change final archive sizes; exact release sizes and
hashes are in the signed manifest. No native binary size reduction is claimed.

Building a wheel without a staged worker now requires
`CIGAR_ALLOW_PORTABLE_WHEEL=1`; its local graph still requires an explicit trusted
matching worker. Ambiguous integrity mappings and inherited graphs are deliberately
rejected. Ordinary native wheel installation needs neither opt-in nor a compiler.

## Correctness and workflow qualification

- 1,434 distinct native requests produced 8,604 exact candidate comparisons,
  including expected failures, authorization, budgets, snapshots, deltas and updates.
- 172 installed context cases and 160 answer-contract scenarios matched exactly.
- 24 authored answer-review episodes per version matched. Honest-review fixtures
  produced supported cited answers for 16/16 answerable episodes; bad-reviewer,
  incomplete-answer and unresolved-claim controls retained their known limitations.
- Python passed 335 tests plus 39 subtests; TypeScript passed 81 tests. Python
  statement/branch coverage was 92.43%/85.60%, with separate stronger module gates.
- Two independent package builds matched; all seven native platforms passed at
  minimum/current runtimes, yielding 7,224 offline contract comparisons.
- Fifty offline Hiero campaigns exercised five workflows, five pairs each.
  Consensus, block-node TSS, Solo and JSON-RPC passed every pair. EVM transaction
  liveness failed in both versions because the full prompt exceeded its budget.
  There were 120 verified context packs and 100 verified negative-evidence artifacts,
  with no paired outcome differences. Block-node campaign median increased 2.7%.

All evaluation used zero model-provider calls. These fixtures test enforcement,
compatibility and authored scenarios; they do not measure real-model hallucination
rates or calibration. CIGAR still needs trustworthy independent semantic reviews.
Hiero used the native graph adapter and did not call the answer-review API; the
separate answer suites covered that contract.

## Reproduction and evidence

The [retained measurements](../../benches/context-012/qualified-2026-09-25.json)
contain controlled startup/RPC samples, the native diagnostic summary, artifact
size records and source/worker identities. Local Hiero archives are excluded.

Use `benches/context-012/compare_installed.py` against installed baseline and
candidate interpreters after matching their bytecode-cache preparation.
`benches/context-012/compare_union.mjs` uses installed npm packages and the shared
response fixtures. `benches/context-011/qualify.py` accepts the exact 0.11 checkout
as `--baseline`. Run these under an OS network-deny policy.

The signed release retains reproducibility, platform qualification, actual installed
dependency receipts, SBOMs and an advisory lookup. Advisory results are point-in-time
package/version checks, not a repository-wide security certification. The separate
Go gRPC xDS advisory is outside the shipped npm/Python dependency closure.
