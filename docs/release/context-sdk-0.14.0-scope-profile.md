# Development scoped-compilation profile

Status: local source optimization measured on September 27, 2026. This compares
two v0.14 development workers, not released v0.12 and v0.14 packages. No model or
external service was called. Installed-platform, agent-load and release gates
remain open.

An ordered intersection of authorized IDs and live documents removes repeated
tree lookups from broad view compilation. Sparse views still use direct lookups.
The change adds no authorization cache, synchronization, dependency or public
API. Scope contents, canonical order, document digests and checks are unchanged.

## Diagnosis and design

Three controls used the same synthetic graph and selected exactly one required
document: an unrestricted host graph, a view containing only the selected source,
and a view containing every source. At 5,000 cold documents, median warm compile
times in the initial diagnostic were 0.048, 0.056 and 1.444 ms respectively.
Authorization semantics differ, so the root control cannot replace an agent view.

Native samples in the broad view pointed to repeated ordered-tree searches in
scope commitment and authorized-document counting, plus serialization and hashing.
The Python profile spent most time waiting for the worker; JSON encoding and
decoding were small in this particular small-request workload. These samples
justify the lookup change, not a general decision about large-message IPC.
Inclusive stack sample counts are not independent phase durations.

The helper merges the two already ordered collections when authorized IDs exceed
one eighth of graph size; smaller sets retain direct lookups. Both paths produce
the exact live intersection in ID order and skip missing IDs. Tests compare them
against the previous lookup algorithm at density boundaries, with missing keys,
empty graphs, replacements and withdrawal. Snapshot and scope hashing still use
the same bytes and domain separators.

## Paired comparison

Both workers were built with Rust 1.92.0, `bpe,broker-persistence`, optimized
release settings, symbols enabled and stripping disabled. Python 3.14.7 on
macOS 26.6.1 ARM64 drove explicit workers through the same source SDK. These
diagnostic binaries are not distribution artifacts.

There are eight fresh-process pairs for each of three controls at each corpus
size: 144 processes total. Cold documents have 256 bytes of text; one hot document
contains the required evidence. Each process excludes ingestion and five warmups,
then measures 100 compile calls under a 512-token budget. Worker order alternates
and control order rotates. Latency includes SDK/IPC, validation and complete-result
JSON hashing. Simultaneous host-plus-worker RSS is sampled every 20 ms. Background
system activity was not controlled; sampled RSS is neither PSS nor an exact peak.

The complete result, including scope commitment and all snapshot fields, agrees
across workers in every matching treatment. Repeated calls within a process must
also agree. Process pairs, rather than the 14,400 individual calls, are the units
for descriptive bootstrap intervals. Profiling is excluded from the comparison.

Values below are medians of eight process medians, in milliseconds:

| Cold documents | Root before → after | One-source view before → after | Full view before → after | Full-view median change |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 0.04716 → 0.04715 | 0.05449 → 0.05301 | 0.07822 → 0.06830 | −12.7% |
| 1,000 | 0.04694 → 0.04873 | 0.05227 → 0.05601 | 0.26771 → 0.19100 | −28.7% |
| 5,000 | 0.04700 → 0.04999 | 0.05356 → 0.05335 | 1.27645 → 0.74341 | −41.8% |

For the 5,000-document full view, mean paired latency decreases 0.5320 ms, with
a process-bootstrap 95% interval of −0.5375 to −0.5259 ms. Descriptive call p95
falls from 1.364 to 0.816 ms. Mean paired combined RSS rises 565,248 bytes, about
0.50%; its difference interval is 126,976 to 1,073,152 bytes. The diagnostic
executable grows 240 bytes, from 9,329,480 to 9,329,720 bytes.

The smaller controls did not all improve. At 1,000 documents, the one-source
median increases 7.2% (0.00374 ms); its mean paired increase is 0.00421 ms, with
an interval of 0.00171 to 0.00709 ms. The 5,000-document root median increases
6.4% (0.00299 ms). No measured cell exceeds the existing 10% median-latency or
20% sampled-RSS regression guardrails. This narrow result does not establish
non-regression for other corpus densities, platforms, concurrent clients or
end-to-end tasks. Keep these increases in the release comparison.

## Evidence identities and reproduction

| Input | Identity |
| --- | --- |
| Source HEAD | `edc54bdb5d4f88df138526c88a0ed4ec8ac9b7e5` |
| Candidate native diff SHA-256 | `2d1284145a721bf720f913f91f2e2af3d1d02081464b18ee71939f3df7f870d0` |
| Baseline worker SHA-256 | `c285ec59c45e5bd7bc4627f848311e4ef8b4745acdad420f85606427df1e4f8a` |
| Candidate worker SHA-256 | `ef76363e613e35a31e07a9781a71544f8c713751b394d48021e569183372e952` |
| Result JSON SHA-256 | `ae20c2162332771f59d3ea61d4f487cdf86ce35c6863a2fc3227a99bb3e929e4` |
| Raw observations SHA-256 | `c99d417d10eefd742a512b17ae4d5b1457826467b25b7f9e901f1f621d1bfa90` |

The private evidence directory is
`CIGAR/releases/cigar-0.14.0-development/scope-intersection-comparison-01`.
It retains worker bytes, native patch, exact corpora, harnesses, plan, raw samples
and reductions. The earlier diagnostic, including native and Python profiles,
is retained in `scope-profile-baseline-01`. Its older harness hashed rendered
text only; those timings are not interchangeable with the paired comparison.
The preliminary one-cohort smoke test is retained separately and supplies no
performance interval.

See [the benchmark instructions](../../benchmarks/SCOPE_PROFILE.md) for build
and reproduction commands. Twelve benchmark-reducer tests reject missing,
duplicated or failed process pairs, changed inputs and complete-result drift.
The native gate passes 132 all-feature tests, one doctest and 57 core-only
test/doctest invocations, with strict Clippy and formatting. The crash helper
is invoked by its bounded parent test.
The complete SDK suites pass 470 Python tests plus 39 subtests and 156 Node tests.
Python statement/branch coverage remains 93.54%/86.74%, and all critical-module
coverage gates pass. SDK validation logs use the `scope-intersection-` prefix in
the development evidence directory.

Retain this optimization for the development candidate. Broad scope commitment
still scales with the number of authorized documents and relations. Transactional
ingestion, intermediate scope densities, host mutation/load interaction, agent
fairness, the 24-hour soak and final artifact comparisons remain required.
