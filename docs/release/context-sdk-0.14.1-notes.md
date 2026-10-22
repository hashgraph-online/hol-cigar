# CIGAR 0.14.1 security release

Status: release candidate prepared for review. Publishing and seven-platform installed
qualification remain release gates; historical 0.14.0 receipts do not qualify these bytes.

This patch release updates the native context core, `hol-cigar`, and `@hol-org/cigar`
to 0.14.1. The local protocol remains `cigar.context-worker.v1`; the legacy remote
workspace remains 0.9.4. Python remains `>=3.14,<3.15`.

## Patched Node runtime required

Node support is now `>=24.22.1 <25`. The optional remote TypeScript client uses
Node's built-in fetch, which decodes Brotli before SDK size checks. On affected
Node versions, a malicious or compromised configured endpoint could reach
CVE-2026-111497. The upstream fix is in Node 24.22.1; see the
[Node security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

The SDK rejects built-in fetch on older or unsupported Node versions. Explicitly
trusted custom fetch implementations retain their existing trust contract. Package
engines, build checks, consumer qualification and digest-pinned CI images require
the patched runtime. Development `@types/node` versions are not runtime versions.

Operators must upgrade Node and restart or redeploy consumers. Installing a new
CIGAR npm package alone does not replace the runtime. Local graph/broker calls do
not use the vulnerable HTTP decoder.

## Bound compilation preparation before allocation

Previously, each candidate retained a full owned copy of its hard dependency
closure before output limits were applied. Overlapping `Requires` or `Contradicts`
closures could multiply memory and tokenization work even for a one-token output
request, affecting every client sharing the native worker.

Compilation and explanation now share a host-owned aggregate budget: one million
work units and 64 MiB of charged evidence/render work per call. Accounting happens
before closure expansion, evidence copies, JSON rendering, duplicate-text comparisons
and repeated scoring; it includes every excerpt citation/source copy and worst-case
JSON escaping. These accounting
limits are not an RSS guarantee. Exhaustion returns `LimitExceeded` for the whole
call, including optional roots; callers cannot raise the limits in a request.

Ordinary bounded calls retain exact token counting, complete hard dependencies,
source authorization, deterministic selection and alias coalescing. Extremely
complex requests that previously ran without an aggregate limit can now fail
explicitly. Narrow the candidate set or graph instead of automatically retrying
the same expensive request.

## Enforce Python HTTP response deadlines

The default urllib transport previously supplied an idle timeout. Periodic response
bytes or SSE keepalives could keep a call active beyond its total deadline.

The standard HTTP parser now reads through a deadline-aware socket reader. Each
underlying read uses the remaining monotonic deadline, including headers, chunked
bodies, error bodies and incomplete event lines. Client-level checks also enforce
the original deadline after token-provider/transport work and around every stream
item, including comments and duplicate events. Timeouts remain `CigarTimeoutError`.
Stream close shuts down active socket reads before closing buffered resources;
async cancellation closes directly without waiting for a free executor thread.

TLS verification, explicit endpoint credentials, no ambient proxy use, redirect
rejection, body/frame limits and retry/idempotency behavior remain enforced.
Trusted custom transports must still honor their timeout argument; arbitrary
application callbacks and system DNS resolution cannot be preempted by this API.

## Release gates

- Run native context/broker tests, Python deadline/client tests, Node SDK tests,
  generators, version checks and release-policy failure controls.
- Build both independent native/SDK candidates and compare the exact artifacts.
- Qualify installation on all seven native targets with patched Node and supported
  Python versions; retain new version-bound receipts.
- After merge and release approval, tag `v0.14.1`, create the signed GitHub release,
  publish the approved Python bytes, stage/approve npm, and verify registry readback.

No compromise or affected-user count is established by these source findings.
