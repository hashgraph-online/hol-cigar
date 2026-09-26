# CIGAR 0.13.0-alpha.1 local test candidate

Python identity: `hol-cigar==0.13.0a1`. npm/Rust identity: `0.13.0-alpha.1`.
This candidate is for local evaluation, not registry publication or production use.
The qualified platform is macOS ARM64; the seven-platform stable gates are retained.

## Scope

Five cooperating agents can use one worker/index through host-defined context views.
The host assigns readable/writable source sets and policy revisions. Writes are
atomic source replacements, including rejection of cross-source ID collisions.
Reads may narrow but cannot widen the host's source scope. Redefining/revoking a
view invalidates its previous handles.

View contexts commit to the complete current readable scope, policy, generation,
request and original snapshot. Scope identity is bound into the existing snapshot
and review-key chain. Answer checking verifies those commitments, recompiles current
evidence, and then applies the existing independent-review rules. An outside-scope
write does not invalidate the answer. Any inside-scope document/edge change does,
including unselected evidence. This conservative policy avoids treating unchanged
top-ranked evidence as proof that new counterevidence is irrelevant.

Existing context snapshots, canonical fixture IDs, root APIs, remote operations,
protocol framing, worker isolation, timeout/cleanup and fail-closed behavior are
preserved. The worker adds the negotiated `context_views.v1` capability. New calls
fail explicitly if it is missing; no automatic server or worker fallback is added.

## Evaluation

Run the Rust core tests, Python/Node full suites, published API snapshots, generators,
strict typing/linting and artifact inventory checks. The packaged shared-view demos
exercise five concurrent agents with fixture reviews. The comparison harness in
`benchmarks/shared_views.py` measures 0.12 shared-root and five-private-graph baselines
against the alpha, plus unchanged root API latency and output digests. Record paired
fresh-process cohorts, call medians/p95, startup, sampled aggregate worker RSS,
correct releases, stale rejections, scope/budget/citation failures and archive hashes.
Do not infer model hallucination improvement from scripted reviews.

## Limits and next gates

- One trusted host owns the root graph and routes agent calls. Views are logical
  scopes, not authenticated bearer credentials, an OS sandbox or a disclosure-safe
  multi-tenant service. A process boundary requires a host-owned broker.
- Worker calls remain serialized. There is no new scheduler, durable handoff log,
  crash recovery, persisted view protocol or multi-host service. Use fresh run
  domains and fresh reviews after restart. A worker failure closes every view.
- Assessment records its checked revision but grants no authority for a later
  external action. The host coordinates revalidation with effect execution.
- The entire readable scope is hashed for freshness. Large scopes add work; measure
  this overhead instead of assuming sharing improves every latency metric.
- HUMIDOR keeps scheduling/recovery and its separate Honey integration. Qualifying
  that integration, durable effects and a 12-agent soak are later milestones.
- Stable promotion still requires seven-platform installed/offline qualification,
  two-builder reproducibility, provenance, advisory checks and separate publication.

Install exact candidate archives, then run `python -m cigar_sdk.examples.shared_views`
or the npm `runSharedViews` example. No account, HOL service, provider or API key is needed.
