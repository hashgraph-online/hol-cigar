# CIGAR 0.14.0 PyPI publication scope

On September 27, 2026, the maintainer requested publication of `hol-cigar==0.14.0`
to PyPI while the installed 24-hour soak was running. The release used the existing
signed GitHub release and protected PyPI Trusted Publishing workflows. npm
registry publication is outside this request.

The publication checkout starts at `a616c860013effe0a1eda6aa7105d0f37bec9946`.
Its changes update release documentation and Python package metadata text and add
hosted public readback/install verification after PyPI upload. Native worker code,
Python/Node runtime code, dependencies, pre-publication checks and soak inputs
remained unchanged. The soak ran from its separately frozen installation and
completed on September 28 (PDT).

## Completed evidence

- The [source workflow](https://github.com/hashgraph-online/hol-cigar/actions/runs/36352216714)
  and [project boundary workflow](https://github.com/hashgraph-online/hol-cigar/actions/runs/36352216827)
  pass for the runtime source.
- The [distribution workflow](https://github.com/hashgraph-online/hol-cigar/actions/runs/36352217153)
  passes fourteen native builds, two matching SDK archive builds, fourteen installed
  platform/runtime cells, legacy compatibility and archive assembly.
- The local complete distribution verifier passes for those exact candidate bytes.
- The [tag qualification and signing run](https://github.com/hashgraph-online/hol-cigar/actions/runs/36377314040)
  passed all 35 jobs for release commit `830f936742088a7e39c5b5dd666e2f5b02415fde`.
- The [PyPI publication](https://github.com/hashgraph-online/hol-cigar/actions/runs/36378934783)
  and [public readback](https://github.com/hashgraph-online/hol-cigar/actions/runs/36379339557)
  passed: all seven wheels and the source archive matched their signed hashes;
  an unpinned clean installation resolved 0.14.0 and passed doctor and demo checks.
- The [completed soak and independent replay](context-sdk-0.14.0-soak.md) passed
  1,036,800 cycles, 104,561 additional checks and 23 forced worker recoveries.
  The interrupted first run is excluded from these results.
- The repeated broker load study passes 2,379,985 cycles across 288 cells; the fault
  matrix passes 3,879 checks. The installed comparison preserves 172 compile results
  and 160 review outcomes and passes 112 of 115 performance guardrails. The three
  previously accepted startup exceptions remain failed measurements.

## Evidence that remains open

- Node client RSS grew throughout the soak, within the aggregate 2 GiB cap.
  A stable plateau and the cause of growth remain unproven. Hourly worker
  restarts also limit claims about one uninterrupted worker process.
- Full HUMIDOR adoption, actual Hiero terminal qualification and broader independent
  task/answer evidence remain pending. No reduction in model hallucinations is claimed.
- Sustained Windows load qualification remains pending.

Publication does not convert any of these incomplete requirements into passing
evidence. The historical execution checklist and original measurements are retained.
If subsequent qualification requires runtime changes, those changes need their own
version and qualification; the published 0.14.0 archives are retained unchanged.

## Publication verification

The tag workflow requalified the documentation-adjusted archives, verified their
independent builds and installed consumers, and signed the exact release manifest.
Its SHA-256 is `b389836f861d9b1a6c956794ae075125cf7ace55fad3e568f2a149d000c20a89`.
The PyPI workflow checked the signed manifest, dependency advisories and package
metadata before its protected upload. Public readback then compared all eight
archives to their signed hashes and verified that PyPI resolved 0.14.0. These
hosted checks ran while the local soak continued.
