# Degraded compiler operation

## Identify degradation

A compile can be degraded only where the response schema explicitly reports it. Typical optional
causes are an unavailable non-authoritative index, stale optional retrieval channel, or bounded cache
miss. Policy, authority, mandatory source, provenance, canonicalization, token budgeting, materializer
semantics, and integrity checks never degrade to permissive behavior.

Compare the reported dependency reason, index watermark, catalog revision, policy digest, selected
provenance, omission dispositions, token counts, and bundle digest with the last healthy baseline.
Do not infer safety from a successful exit code alone.

## Contain and recover

Disable the failing optional channel if repeated calls remain bounded and the manifest explicitly
records its omission. Rebuild a disposable index from committed catalog state using the
[index-rebuild runbook](index-rebuild.md), or restore the authoritative dependency before retrying.
Invalidate cached degraded outputs when the dependency or policy revision changes.

Return a typed failure instead of a degraded bundle when mandatory context would be omitted, selected
provenance is incomplete, budget rules cannot be enforced, freshness/consistency is below the
contract, or an integrity/policy dependency is uncertain. Stop rollout if degraded rate, latency,
mandatory errors, or outcome comparisons exceed the approved threshold. Evidence contains dependency
reason codes, revisions/watermarks, manifest and bundle digests, counts, timings, and recovery result;
it excludes selected content.
