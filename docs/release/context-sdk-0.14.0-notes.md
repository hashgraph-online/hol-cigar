# CIGAR 0.14.0

Version 0.14.0 is published on PyPI and npm; public readback matched the signed
archives on both registries. The 24-hour installed soak completed on
September 28, 2026 (PDT), and independent replay passed. The
[soak report](context-sdk-0.14.0-soak.md) records all checks and the continuing
Node client RSS growth within the configured cap. HUMIDOR adoption and broader
Hiero/task evidence remain pending. See the
[publication scope](context-sdk-0.14.0-pypi-publication.md) and the
[execution checklist](context-sdk-0.14.0-execution.md) for completed and open work.

## Shared context for independent agents

Python and Node applications can use one local broker and document index across
independent agent processes. The trusted host grants authenticated, expiring
source scopes and retains mutation, admission, reviewer and execution authority.
Per-agent queues, byte limits, quotas and source revision checks bound work and
reject conflicting writes. Agents propose evidence; host admission determines
which proposals become trusted graph content.

Optional SQLite persistence restores admitted documents, source versions and
provenance after worker restart. Recovery creates a fresh authority epoch: old
credentials, context tickets, reviews and abandoned staged writes are rejected.
Existing in-process graphs and scoped views remain available.

Source provenance records origin, upstream revision, observation time, trust and
derivation lineage. Expired or changed dependencies invalidate dependent evidence.
Reviewed execution handoffs bind context to the existing Honey effect client;
uncertain dispatch outcomes require reconciliation instead of an automatic retry.
HUMIDOR continues to own scheduling and orchestration.

## Context management and safety

- Transactional source batches stage bounded requests and commit an atomic source
  replacement, including logical sources larger than one worker frame.
- Selection explanations describe selected evidence and retrieval signals. Scoped
  ranking and syntax-aware ingestion recipes remain optional and host-controlled.
- Live capability reports distinguish available worker bytes from negotiated
  features and successful context compilation. Local use needs no HOL services.
- Filesystem admission checks both symlink aliases and resolved targets, rejects
  special files without retaining blocking capacity, and preserves policy spelling.
- TypeScript canonical maps retain special own keys; Python semantic verification
  enforces representation and transform-receipt consistency. Valid fixture IDs
  and the frozen context/remote ABIs remain unchanged.

The broker uses authenticated loopback connections. This is neither encrypted
multi-host transport nor an OS sandbox against code with the host's privileges.
Use separate privacy domains for unrelated hostile tenants. Reviewer labels must
come from a trusted independent authority; CIGAR does not determine semantic truth.

## Measured benefits and costs

The development comparison preserves 172 complete compile outputs and 160 answer
review outcomes across released 0.12, retained 0.13 alpha and the development SDK.
On the measured macOS ARM64 host, RPC compile latency is 6.48% lower than 0.12;
all 1/5/12-client latency and memory guardrails pass. Sharing benefits introduced
in the alpha are distinguished from new broker capabilities.

112 of 115 performance comparisons pass their original limits. On September 27,
2026 the user accepted the three measured startup exceptions: local API loading
versus 0.12 (+35.18%, about 2.36 ms), worker hashing versus 0.12 (+16.19%, about
0.51 ms) and hashing versus the alpha (+13.48%). Full SHA-256 verification on every
worker launch is retained. These are accepted trade-offs, not passing measurements.
See the [installed comparison](context-sdk-0.14.0-installed-comparison.md) for
exact artifacts, intervals, raw evidence and the retained initial failed study.

The independent SciFact study retains identical default retrieval results across
versions. The optional ranking hook improves recall at larger budgets but adds
cost and reduces precision; flat BM25 remains stronger on that corpus. No general
retrieval superiority or real-model hallucination reduction is claimed. See the
[retrieval report](context-sdk-0.14.0-retrieval-evidence.md).

The independent-process load matrix passes 2,379,985 cycles across 288 cells and
the fault matrix passes 3,879 checks. The a616c860 source, boundary and installed
distribution workflows pass. A host restart interrupted the first soak after
about 4 hours 50 minutes; its incomplete observations are retained separately.
The replacement 24-hour installed run completed 1,036,800 cycles, 104,561
additional checks and 23 forced worker recoveries with zero failed checks.
Independent replay and installed-package integrity checks passed. Sampled total
RSS peaked at 1.121 GiB, below the 2 GiB cap; the six Node clients grew from
367 to 864 MiB combined without demonstrating a plateau. Hourly worker restarts
limit conclusions about one worker remaining alive for a full day.
The published archives passed requalification and signing, and all eight PyPI
archives matched their signed hashes during public readback. No broader task or
model-quality gain is claimed.

## Compatibility and installation

The distributions remain `hol-cigar` / `cigar_sdk` for Python 3.14 and
`@hol-org/cigar` for Node.js 24 ESM. Seven native targets are retained. This
release is available as stable 0.14.0 on both registries.
Use `python3.14 -m pip install --upgrade 'hol-cigar==0.14.0'` or
`npm install --save-exact @hol-org/cigar@0.14.0`. Signed archive hashes
and installed qualification receipts accompany the GitHub release. A source-only
Python installation requires an explicit matching trusted worker. Existing graph
APIs do not require broker mode.

See the [broker guide](../../sdk/LOCAL_BROKER_GUIDE.md),
[local agent guide](../../sdk/LOCAL_CONTEXT_GUIDE.md), and
[Python changelog](../../sdk/python/CHANGELOG.md) for migration and API usage.

## Repository integration after publication

PR #38 also updates the repository's Rustls and Wasmtime dependencies, corrects
Windows SID pointer provenance, and repairs CI configuration and a
scheduler-sensitive cancellation test. These integration changes postdate the
immutable `v0.14.0` tag. Published archives retain their original signed bytes;
the soak evidence qualifies its named runtime source, not later runtime changes.
Shipping those later changes requires a subsequent version and qualification.
