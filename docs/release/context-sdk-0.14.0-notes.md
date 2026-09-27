# CIGAR 0.14.0 candidate

Status: release preparation; not published or fully qualified. The package version
is staged as 0.14.0 so qualification can test the intended distribution identity.
See the [execution checklist](context-sdk-0.14.0-execution.md) for open gates.

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
the fault matrix passes 3,879 checks. The continuous-run harness has passed only
its 60-second preflight so far. Final versioned installed qualification, the
24-hour soak, broader task evidence and publication/readback remain open.

## Compatibility and installation

The planned distributions remain `hol-cigar` / `cigar_sdk` for Python 3.14 and
`@hol-org/cigar` for Node.js 24 ESM. Seven native targets are retained. The intended
default channel is stable/latest; nothing in this preparation publishes a package.
Install only exact candidate archives with their corresponding qualification
receipts until final publication. A source-only Python installation requires an
explicit matching trusted worker. Existing graph APIs do not require broker mode.

See the [broker guide](../../sdk/LOCAL_BROKER_GUIDE.md),
[local agent guide](../../sdk/LOCAL_CONTEXT_GUIDE.md), and
[Python changelog](../../sdk/python/CHANGELOG.md) for migration and API usage.
