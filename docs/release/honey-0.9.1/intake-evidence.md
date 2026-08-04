# Honey 0.9.1 intake evidence

Status: recorded 2026-07-20 before implementation changes.

This record authenticates the inputs used to plan the Honey 0.9.1 repair. It contains no protected
Hiero content. The untracked inputs listed here are retained as user-owned evidence and must not be
deleted, reset, rewritten, or hidden to make the working tree appear clean.

## Source baseline

| Field | Value |
|---|---|
| Git commit | `1ceea65e84fa59b3a4bff5027a0cced325cd2310` |
| Git tree | `769f2e6ea2f47673abba27e6dea0c017dadc430c` |
| Commit timestamp | `2026-07-17T08:02:25-06:00` |
| Planning checklist | `todo-0.9.1.md` |

Initial working-tree inventory:

| Status | Path | Disposition |
|---|---|---|
| external | `cigar-honey-0.9.0-honey.1-developer-handoff.zip` | immutable digest-bound historical handoff input; moved outside the source repository before freeze |
| untracked | `docs/cigar-honey-release-efficiency-handoff.md` | immutable findings input |
| untracked | `todo-0.9.1.md` | active implementation checklist |

## Authenticated handoff inputs

| Input | Bytes | SHA-256 |
|---|---:|---|
| `docs/cigar-honey-release-efficiency-handoff.md` | 22,903 | `cab11afc84b36cfe4929a3946cc25d5d14f77d413a687f675cc23d4a69dea813` |
| `cigar-honey-0.9.0-honey.1-developer-handoff.zip` | 116,927,188 | `53f484ae7e2be6a51a0dd613731986bfda926688b0dcff21462a2bdb8da7f421` |
| external paired raw benchmark | external/not copied | `776b84c8cce3b11915b53947f3bb21a86c8a9819fc43ef0d1c85362ca62a3455` |

The developer handoff ZIP contains exactly 13 top-level files according to a non-extracting central
directory inspection. It remains the historical 0.9.0 handoff and is not a mutable build input. Its
authority record is external and content-free: artifact name, byte length, and SHA-256 only. The
candidate source and qualification checks do not depend on its filesystem location or package its
bytes.

The frozen protocol check passed at intake with profile
`cigar.development.protocol-baseline.v1`. Its two source authorities were:

| Authority | Bytes | SHA-256 |
|---|---:|---|
| `spec/api/operations-v1.json` | 13,310 | `55c8dd34d7c6a62b0c68dce181c80ed8d4815810828476c188df190ef529d07b` |
| `spec/api/operation-payloads-v1.json` | 36,035 | `4ef0878a35952a98f0e4107e913f7ade8ffc028677974205436318b30b376817` |

These digests are comparison evidence, not permission to hand-edit generated projections.

## Evidence isolation and allowed mutable inputs

The retained approximately 50 GB Hiero state is classified `H91-EVIDENCE-RETAINED-HIERO-V4` and is
read-only external evidence. It is not present in this repository. It is excluded from the first
migration, compaction, fuzz, crash, performance, and recovery campaigns. No Honey command may open
it with write authority during 0.9.1 development.

The only initially authorized mutable workload classes are:

1. `H91-FIXTURE-SMALL-GENERATED`, created from a fixed public seed in a new owner-only workspace.
2. `H91-FIXTURE-BOUNDARY-GENERATED`, exercising every configured size/count boundary.
3. `H91-FIXTURE-HIERO-SHAPED-GENERATED`, matching content-free counts and sizes without Hiero data.
4. `H91-WORKLOAD-VERIFIED-COPY`, a disposable externally authorized copy selected only after all
   generated migration gates pass. Its path identity, byte length, digest, source freeze revision,
   and copy verification receipt are still required before it becomes executable.

The verified-copy descriptor is deliberately incomplete at intake. Until those fields are bound,
only the three generated fixture classes are executable.

## External reproduction references

The following inputs are held by the downstream Hiero project and were confirmed absent from this
repository at intake. They are identifiers only; protected contents must not be copied into Honey.

| External reference | Intake state |
|---|---|
| `docs/cigar-workflow-efficacy-report.md` | external, not present |
| `.hiero-audit/cigar/efficacy/workflow-context-paired-v1.json` | external, not present |
| `docs/cigar-final-verification.md` | external, not present |
| `hiero_audit_core/cigar_client.py` | external, not present |
| `hiero_audit_core/context_compilers.py` | external, not present |
| exact 0.9.0 source/schema/demo artifacts | represented only by authenticated historical handoff ZIP |
| 0.9.0 release manifest and checksums | contained in authenticated historical handoff ZIP; not extracted |

## Intake environment identity

These values describe the baseline host only. Candidate qualification must capture a fresh identity
and must not silently reuse this record as installed-byte evidence.

| Component | Identity |
|---|---|
| Rust compiler | `rustc 1.92.0 (ded5c06cf 2025-12-08)` |
| Cargo | `cargo 1.92.0 (344c4567c 2025-10-21)` |
| Python | `3.14.6` |
| Node.js | `v24.10.0` |
| pnpm | `10.34.5` |
| SQLite CLI/library | `3.43.2 2023-10-10`, 64-bit |
| macOS | `15.6 (24G84)` |
| kernel / architecture | `Darwin 24.6.0 / arm64` |
| CPU | `Apple M3 Ultra` |
| repository filesystem report | `/` from `stat -f %T`; data device `/dev/disk3s5` |
| filesystem capacity at intake | 3,902,665,360 KiB total; 641,586,476 KiB available; 84% used |

The filesystem type string returned by the baseline `stat` invocation is not sufficiently specific
to assert APFS. Candidate qualification must record a stronger filesystem identity before freezing
performance conditions.

## Enforcement

- Migration and compaction must require explicit source, verified backup, distinct empty target,
  free-space proof, and owner-controlled activation.
- Tests must create new owner-only workspaces under canonical `/private/tmp` on macOS.
- `VACUUM`, relaxed durability, a larger database ceiling, and manual row deletion are prohibited
  as the storage repair.
- No report may contain source text, prompts, raw tokens, credentials, private paths, or Hiero
  content.
- Candidate evidence must re-bind its exact source commit/tree, manifest, installed bytes,
  fixtures, raw observation attachments, environment, and thresholds.
