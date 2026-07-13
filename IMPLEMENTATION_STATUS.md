# CIGAR v1 Implementation Status

Source specification: CIGAR v1 Production Implementation Execution Spec  
Repository baseline for this status update: active development workspace; the immutable beta candidate commit/tree must be recorded externally by the source descriptor after freeze
Updated: 2026-07-13T20:07:08Z
Executor: Codex `/root`

## Environment

- OS/architecture: macOS 15.6 (24G84), arm64
- Rust toolchain: rustc/cargo 1.92.0, stable-aarch64-apple-darwin
- Node/pnpm: Node 24.10.0; pnpm 10.34.5
- Python/build tool: CPython 3.14.6; uv 0.11.8
- Go: 1.26.3 darwin/arm64
- Native tools: protoc 33.2; protoc-gen-prost 0.5.0; protoc-gen-go 1.36.11; protoc-gen-go-grpc 1.6.2; protoc-gen-es 2.12.1; SQLite 3.43.2; Git 2.51.1
- Container runtime: Docker client/server 29.3.1; Podman unavailable
- Quality tools: cargo-nextest 0.9.140; cargo-deny 0.20.2; cargo-llvm-cov 0.8.7; just 1.56.0 (installed during WP00 after initial inventory)
- Network policy: network available; tests MUST remain hermetic and offline

## Work packets

| Packet | Status | Base | Owner | Evidence | Blocker |
|---|---|---|---|---|---|
| WP00 | complete | pre-commit workspace, first recorded by `0d8a8115` | Codex /root | `artifacts/work-packets/WP00.json` | none |
| WP01 | complete | WP00 | Codex /root | `artifacts/work-packets/WP01.json` | none |
| WP02 | complete | WP01 | Codex /root | `artifacts/work-packets/WP02.json` | none |
| WP03 | complete | WP02 | Codex /root | `artifacts/work-packets/WP03.json` | none |
| WP04 | complete | WP03 | Codex /root | `artifacts/work-packets/WP04.json` | none |
| WP05 | complete | WP04 | Codex /root | `artifacts/work-packets/WP05.json` | none |
| WP06 | complete | WP05 | Codex /root | `artifacts/work-packets/WP06.json` | none |
| WP07 | complete | WP02 | Codex /root | `artifacts/work-packets/WP07.json` | none |
| WP08 | complete | WP01, WP02, WP05-WP07 | Codex /root | `artifacts/work-packets/WP08.json` | none |
| WP09 | complete | WP08 | Codex /root | `artifacts/work-packets/WP09.json` | none |
| WP10 | complete | WP09 | Codex /root | `artifacts/work-packets/WP10.json` | none |
| WP11 | complete | WP10 | Codex /root | `artifacts/work-packets/WP11.json` | none |
| WP12 | complete | WP02-WP04, WP07 | Codex /root | `artifacts/work-packets/WP12.json` | none |
| WP13 | complete | WP08, WP09, WP12 | Codex /root | `artifacts/work-packets/WP13.json` | none |
| WP14 | complete | WP13 | Codex /root | `artifacts/work-packets/WP14.json` | none |
| WP15 | complete | WP14 | Codex /root | `artifacts/work-packets/WP15.json` | none |
| WP16 | complete | WP14 | Codex /root + SDK agents | `artifacts/work-packets/WP16.json` | none |
| WP17 | complete | WP14-WP16 | Codex /root + Claude-adapter agent | `artifacts/work-packets/WP17.json` | none |
| WP18 | complete | WP03, WP14 | Codex /root + shared-deployment agent | `artifacts/work-packets/WP18.json` | none |
| WP19 | in_progress | WP01-WP18 | Codex /root + quality agents | `reports/conformance-result.v1.json`, `reports/invariant-traceability.v1.json`, `${CIGAR_EVIDENCE_DIR}/wp19-quality-smoke.json` | closed representative-mutation evidence, seven-day fuzz, full RC mutation/chaos/platform campaigns, final integrated matrix evidence |
| WP20 | in_progress | WP19 | Codex /root + demo/benchmark agents | `${CIGAR_EVIDENCE_DIR}/wp20-local-readiness.json` | installed artifacts, independent task corpus/evaluator, qualified performance and outcome evidence |
| WP21 | in_progress | WP20 | Codex /root + SDK/release agents | `${CIGAR_EVIDENCE_DIR}/wp21-local-readiness.json`, `${CIGAR_EVIDENCE_DIR}/rust-publication-chain-local.json` | machine-recorded external, candidate-binding, installed-artifact, and live-operation gaps |
| WP22 | not_started | WP21 | unassigned | pending | WP19-WP21 exits, exact committed candidate, installed bytes, duration and external release gates |

WP19-WP22 remain unchanged by the initial beta lane. Beta completion cannot be used as their evidence or exit.

## Initial beta lane

| Release | Status | Exact scope | Workspace proof | Release blockers |
|---|---|---|---|---|
| `0.1.0-beta.1` | in_progress / STOP-SHIP | Workspace-state administration through `cigar`; target `x86_64-unknown-linux-gnu`; required qualification runtime Ubuntu 24.04 x86_64/glibc 2.39; six archives; no installer | Profile/schema checker and 8 tests; compile-time feature isolation; beta CLI suite with 22 tests | clean candidate, required builder and independent reproducibility, installed/offline/security qualification, legal approval, production beta signatures/trust roots, verified private reporting channel, offline verification, publisher approval/readback |

The beta profile is `cigar.beta.embedded-local.linux-x86_64.v1`, but the implemented CLI behavior is narrower than “embedded-local execution”: it only administers local workspace state. It does not ingest, index, retrieve, compile context, run services, execute effects, or expose daemon/API/MCP/SDK/plugin/shared/remote/vector/OTLP surfaces. The exact contract and open checklist are in `docs/release/INITIAL_BETA.md` and the separate BETA tasks in `todo-launch.md`.

The three listed proof groups passed in the development workspace only. They are not tied to a clean immutable candidate or built artifact and must be rerun after freeze. No beta candidate, archive, deterministic rebuild, installed-byte smoke, final-byte security scan, SBOM/provenance, production signature, offline verification, or publication task is complete.

## Current packet

- Objective: finish WP19 quality hardening and integrated matrices, then carry the exact stabilized source through the locally testable WP20/WP21 gates without misrepresenting external evidence.
- Completed transition: WP17 and WP18 are complete. All eight conformance profiles pass 24/24 cases; traceability is valid; 47 sealed security findings are reconciled; the 19-package Rust publication chain passes an offline local registry; seven demos, four SDK workflows, and the local CIGARBench protocol harness pass their honest local scopes.
- Active hardening: receipts preserved under the external `launch-000-*-4081a835` directories describe source `4081a8355b8e6bd5959dcc44c48b63b9d8dc55ca` (tree `844643f2d0daf36b4813c66fd62c3c65a2fdc952`). They record useful smoke observations, but their qualification/combined verification is failed or incomplete, they are not candidate-bound, and they do not satisfy the seven-day-per-target fuzz or four-hour release-candidate mutation gates. They are historical diagnostics only and cannot be copied, edited, or rebound as evidence for a later candidate or the beta.
- Active release blockers: the latest observed committed development baseline exists, but the worktree is dirty. Preserved WP20 and WP21 receipts describe earlier development states and remain historical, unbound evidence; they must be regenerated into `${CIGAR_EVIDENCE_DIR}` against the next exact clean candidate rather than edited by hand. A closed mutation-evidence format and verifier are still required before any representative mutation result can qualify. The full security-matrix receipt is not yet green, seven-day fuzz and full four-hour mutation are incomplete, CIGARBench lacks independent adjudicated tasks/evaluator evidence, no qualified final `dist/` or installed-byte matrix exists, and final platform/signing/SBOM/provenance/soak evidence is unavailable.
- Exact next action: the beta artifact/evidence assembly path is implemented and its development-workspace tests pass; commit one exact beta candidate, rerun the source gates while proving it stays clean, then build and qualify the six-artifact beta set on native Ubuntu 24.04 x86_64/glibc 2.39 with Rust 1.92.0 and Python 3.14.6. In parallel, continue the independent WP19-WP21 GA work without treating beta evidence as GA evidence.

## Workspace state

- Existing unrelated changes preserved: `prd.md` remains intact except evidence-backed completion marks requested by the user.
- Commit state: development history is not qualification evidence. The candidate commit/tree will be authoritative only when a clean detached source descriptor records it and every dependent gate is rerun.
- Uncommitted changes: WP00-WP18 remain complete; WP19-WP21 and the separate beta lane contain active work. Historical WP19-WP21 receipts were preserved outside the repository before their tracked copies were removed; the `4081a835` receipt set is explicitly nonqualifying.
- Generated and package artifacts require a final drift check after corpus reconciliation. No workspace result may be represented as release-candidate evidence while the worktree is dirty or while its source descriptor differs from the exact candidate commit/tree.
- Migration/schema owner: Codex `/root`; SQLite and PostgreSQL histories remain append-only and checksum-verified.
