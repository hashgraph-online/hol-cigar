# CIGAR 0.14.0 PyPI publication scope

On September 27, 2026, the maintainer requested publication of `hol-cigar==0.14.0`
to PyPI while the installed 24-hour soak continues. The release uses the existing
signed GitHub release and protected PyPI Trusted Publishing workflows. npm
registry publication is outside this request.

The publication checkout starts at `a616c860013effe0a1eda6aa7105d0f37bec9946`.
Its changes update release documentation and Python package metadata text and add
hosted public readback/install verification after PyPI upload. Native worker code,
Python/Node runtime code, dependencies, pre-publication checks and soak inputs
remain unchanged. The active soak runs from its separately frozen installation.

## Completed evidence

- The [source workflow](https://github.com/hashgraph-online/hol-cigar/actions/runs/36352216714)
  and [project boundary workflow](https://github.com/hashgraph-online/hol-cigar/actions/runs/36352216827)
  pass for the runtime source.
- The [distribution workflow](https://github.com/hashgraph-online/hol-cigar/actions/runs/36352217153)
  passes fourteen native builds, two matching SDK archive builds, fourteen installed
  platform/runtime cells, legacy compatibility and archive assembly.
- The local complete distribution verifier passes for those exact candidate bytes.
- The repeated broker load study passes 2,379,985 cycles across 288 cells; the fault
  matrix passes 3,879 checks. The installed comparison preserves 172 compile results
  and 160 review outcomes and passes 112 of 115 performance guardrails. The three
  previously accepted startup exceptions remain failed measurements.

## Evidence that remains open

- The replacement continuous soak started at `2026-09-28T00:29:20Z`. Completion
  and independent replay remain pending. The interrupted first run cannot count
  toward the replacement's 24 hours.
- Full HUMIDOR adoption, actual Hiero terminal qualification and broader independent
  task/answer evidence remain pending. No reduction in model hallucinations is claimed.
- Sustained Windows load qualification remains pending.

Publication does not convert any of these incomplete requirements into passing
evidence. The historical execution checklist and original measurements are retained.
If subsequent qualification requires runtime changes, those changes need their own
version and qualification; the published 0.14.0 archives are retained unchanged.

## Publication verification

The tag workflow must requalify the documentation-adjusted archives, verify their
independent builds and installed consumers, and sign the exact release manifest.
The PyPI workflow checks that signed manifest, current dependency advisories and
package metadata before its protected upload. After publication, registry readback
must compare all seven wheels and the source archive to their signed hashes and
verify that PyPI resolves the intended version. Public install checks run on a
hosted runner while the local soak remains active.
