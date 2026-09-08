# CIGAR 0.10.0 Python and TypeScript RC1

Status: **created and locally qualified; not published**. All changes remain uncommitted.
The original 0.9.4 checkout is unchanged. This is an SDK/local-context release candidate,
not a promotion of the Honey daemon or a claim of production certification.

## Installable artifacts

The [local release directory](../artifacts/packages/context-sdk-0.10.0-rc.1/) contains:

| Artifact | Version | Size |
| --- | --- | ---: |
| [Python platform wheel](../artifacts/packages/context-sdk-0.10.0-rc.1/hol_cigar-0.10.0rc1-py3-none-macosx_11_0_arm64.whl) | `hol-cigar==0.10.0rc1` | 3,130,733 bytes |
| [Python source distribution](../artifacts/packages/context-sdk-0.10.0-rc.1/hol_cigar-0.10.0rc1.tar.gz) | `hol-cigar==0.10.0rc1` | 99,717 bytes |
| [TypeScript npm archive](../artifacts/packages/context-sdk-0.10.0-rc.1/hol-org-cigar-0.10.0-rc.1.tgz) | `@hol-org/cigar@0.10.0-rc.1` | 3,419,950 bytes |
| [Matching Rust source crate](../artifacts/packages/context-sdk-0.10.0-rc.1/cigar-context-0.10.0.crate) | `cigar-context 0.10.0` | 44,567 bytes |

The wheel and npm archive bundle the same persistent Rust worker for **macOS ARM64**.
Their normal local-graph use requires no Rust toolchain, daemon, database, network, or model.
Python requires 3.14; TypeScript requires Node `>=24.10.0 <25`, ESM. The Python source
distribution is portable SDK source: local graph use requires an explicit trusted
`worker_path` to a separately built worker. Other native targets are not bundled or qualified.

From the repository root, using Python 3.14 and the supported Node runtime:

```sh
python3.14 -m pip install ./artifacts/packages/context-sdk-0.10.0-rc.1/hol_cigar-0.10.0rc1-py3-none-macosx_11_0_arm64.whl
npm install ./artifacts/packages/context-sdk-0.10.0-rc.1/hol-org-cigar-0.10.0-rc.1.tgz
```

These are **local file installs**, not assertions that the RCs exist on PyPI/npm.
The intended npm prerelease tag is `rc`, not `latest`; no registry write or tag change occurred.
Package artifacts are deliberately under the repository's ignored `artifacts/packages/`
directory. Preserve that directory separately when distributing or committing the source.

## What changed from 0.9.4

| Area | 0.9.4 SDKs | RC1 |
| --- | --- | --- |
| Remote operations | 45 frozen operations; 70 payload models | Retained, with unchanged generated schemas and Context ABI |
| Workflow, retries, streams, bundle verification | Existing Python sync/async and TypeScript clients | Retained; original tests pass |
| Local graph | Not exposed by these SDKs | Python `LocalContextGraph`; async TypeScript `LocalContextGraph.create` |
| Incremental state | Remote-client functionality | Persistent local indexes, bounded exact token cache, atomic source replacement |
| Retrieval and context | Remote APIs | Also exposes the same Rust lexical/semantic-candidate selection, graph closure, authorization filtering, citations, and optional query windows |
| Integrity and transport | Frozen remote bundles/deltas | Adds distinct Rust snapshots, verification, and exact-base local deltas |
| Packaging | Portable SDK packages | Adds approximately 3 MB of compressed native payload to the host wheel/npm artifact |
| Local-only TypeScript entry point | None | `@hol-org/cigar/context`, avoiding remote/protobuf module loading |

The new methods are `upsert`, source replacement, removal, edge linking/unlinking, source
chunking, compilation, snapshot verification, delta generation/application, cache statistics,
and cache clearing. Python uses snake_case method names; TypeScript uses camelCase.
Public typed request/result/document/snapshot structures are supplied in both languages.
See the [Python guide](../sdk/python/README.md), [TypeScript guide](../sdk/typescript/README.md),
and [implementation plan](../docs/proposals/cigar-0.10.0-sdk-rc.md).

Each local graph owns one subprocess, graph, and privacy-local token cache. Python calls
are synchronous and thread-serialized; the existing asynchronous Python **remote** client
is unchanged. TypeScript local calls are asynchronous, serialized, and queue-bounded, with
`await using` support. Explicit close terminates the worker. There are no implicit downloads,
PATH-based executable discovery, shell execution, or file ingestion. Worker checksums and
protocol/core-version handshakes are checked before use. A timeout or broken protocol closes
the instance; no mutation is automatically retried or graph state silently restarted.

The frozen Honey publication profile remains 0.9.4. An explicit SDK RC track now permits
Python and TypeScript to advance independently while retaining `cigar.context.v1`. The local
worker uses the separate `cigar.context-worker.v1` protocol. CI routes RC checks to a new
non-publishing workflow; the old 0.9.4 publication validations are retained.

## Qualification results

Host: macOS 26.6.1 ARM64. Rust/Cargo 1.92.0; Python 3.14.7; TypeScript 7.0.2;
pnpm 10.34.5. Source SDK tests ran on Node 24.19.0; final installed-package and old-SDK
qualification ran on the declared minimum Node 24.10.0. Its downloaded official Node archive
was SHA-256 checked before execution. npm 12.0.2 packed the artifacts; the minimum-runtime
consumer used Node 24.10.0's npm.

| Gate | Result |
| --- | --- |
| Rust core/BPE/CLI/new worker | 35 tests plus 1 documentation example passed |
| Rust core-only configuration | 27 tests plus 1 documentation example passed |
| Python source, installed wheel, installed sdist | 36/36 tests in each treatment; no skips |
| TypeScript source and installed-package copy | 37/37 tests in each treatment; no skips |
| Independent old Python/TypeScript SDK copies | 28/28 Python and 29/29 TypeScript tests passed |
| Public API preservation | All 43 old Python exports and 104 old TypeScript runtime exports retained |
| Cross-language oracle | 172 cases × 3 consumers = 516 matching results |
| Exact successful snapshots | 155 cases × 3 = 465 full snapshot matches, including commitments/statistics |
| Expected refusals | 17 cases × 3 = 51 matching error categories |
| Rendered context | Identical across installed wheel, sdist, and npm consumers |
| Static checks | Rust fmt/Clippy, whole Python SDK Ruff/mypy, TypeScript strict typecheck, generated API/parity checks passed |
| Package checks | Wheel tags, clean installs, entry points, inline source maps, no npm install hooks, strict Twine checks passed |
| Repacking | Wheel, sdist, and npm archive each identical over two packs from the same staged inputs |
| Release/CI checks | 12 existing publication/verifier contract tests passed; updated workflows passed actionlint/static YAML validation |
| Known-advisory lookup | OSV returned no advisories for 34 locked Rust dependencies plus the 2 SDK production dependencies |

The 172 cases comprise 72 authored combinations (12 fixtures × 2 representation modes ×
3 budgets) and 100 seeded graphs/queries. They include Unicode, identifiers, hard dependency
and contradiction edges, authorization filtering, required evidence, and impossible budgets.
Independent SDK tests additionally exercise atomicity, retained hard edges after withdrawal,
chunk line offsets, cache hits/clearing/disabling, tamper and wrong-base rejection, concurrency,
queue limits, invalid frames, disposal, and deadlines against a deliberately stalled worker.
The stalled worker does not drain stdin, exercising blocked writes as well as response waits.

The older SDK baseline is commit `107880a53046b0abf0d5f5f6d9f63598722823e2`, copied into
isolated test directories. Generated operation/model files were not changed. Retaining exports
and passing tests is evidence of compatibility, not proof about every possible application.

Early qualification-harness runs needed pytest and the legacy suites' out-of-package fixtures
and pnpm dependency layout. Those were corrected without changing production package behavior
or relaxing the old runtime assertions. One actual worker defect—unknown fields ignored on
fieldless Serde commands—was fixed and regression-tested. An oversized Python timeout is also
rejected before process creation, preventing platform lock-timeout overflow.

## Evidence and boundaries

[Release manifest](evidence/context-sdk-010-rc1/release.json) retains hashes for 115 source
inputs, four artifacts, and 83 compressed evidence files. [SHA256SUMS](../artifacts/packages/context-sdk-0.10.0-rc.1/SHA256SUMS)
binds the distributable files and their release manifest. The worker was built from the
included standalone Rust source crate; both language packages include dependency/license notices.

The Python wheel SHA-256 is
`61e35dc9f9fe36c3ddf364a65a37267d2f5f2569fc1af9957b1deba42f06c8aa`;
the npm archive SHA-256 is
`2279b57f1b4773200fb9f570322c87f5c5676a7346814ec150633a1750069e6c`.
The platform wheel correctly uses a native platform tag rather than `any`; the hook and tag
design follow [Hatch build hooks](https://hatch.pypa.io/latest/plugins/build-hook/reference/)
and the [PyPA platform-tag specification](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/).

These SDKs expose the [previously measured Rust improvements](cigar-0.10.0-second-pass.md);
this packaging pass does **not** demonstrate new token savings, model-answer accuracy, or
end-to-end speedups over in-process Rust. IPC adds serialization/copying, startup, and process
memory overhead. Graph/cache reuse amortizes initialization; it does not remove that overhead.
Token budgets cover Rust-rendered context, not provider chat framing. Deltas save transport/storage
bytes, not stateless model prompt tokens. Applications still own authorization and must treat
source text as data. Hashes are not signatures, and the worker is not an OS sandbox.

Remaining gates before broader promotion: actual hosted CI and native Linux/Windows runs,
minimum supported Python/macOS runtime testing, release-owner review, and an explicit publication
decision. The binary's macOS 11 deployment floor was inspected, but execution here was on 26.6.1,
not macOS 11. OSV is a point-in-time public-version lookup, not a source security audit. The earlier
full Rust-workspace qualification is historical; this turn reran the affected standalone core,
worker, SDKs, packaging, and release checks rather than claiming a new whole-workspace run.

## Reproduction

Install the repository's pinned pnpm/uv dependencies and Rust 1.92. Then run
`scripts/release/prepare_context_sdk_rc.py --help`, followed by
`qualify_context_sdk_rc.py --help` and `finalize_context_sdk_rc.py --help` in the same directory.
Each script requires explicit paths and fresh output directories. The preparation script builds
the matching Rust crate and platform packages; qualification installs them separately and compares
against an explicit old checkout; finalization verifies results and writes local evidence/archives.
The [RC workflow](../.github/workflows/context-sdk-rc.yml) documents the complete invocation chain
for preparation/installed-consumer checks. It has no publishing command or write credential.
