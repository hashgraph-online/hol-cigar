# Honey 0.9.1 findings and requirements traceability

Status: architecture baseline. `planned test/evidence` names are stable qualification obligations;
they do not assert that implementation or candidate evidence already exists.

Machine gate IDs and immutable input digests are authoritative in
`packaging/honey/efficiency-qualification-profile.v1.json`. No row may be marked passed until its
planned evidence is bound to the exact candidate source/tree, artifact manifest, installed runtime,
fixtures, environment and raw-observation digest.

## Findings

| Requirement | Handoff finding | Decision/workstream | Planned test/evidence | Machine gate |
|---|---|---|---|---|
| H91-R-F01 | Full residual snapshot per revision | ADR-0001; H91-110, 200-240 | `v5_no_ordinary_full_checkpoint`; 10k growth report | H91-G001, H91-G004, H91-G008 |
| H91-R-F02 | Excess commits per user compilation | vNext proposal; H91-110, 220, 510 | per-operation commit telemetry; atomic proposal conformance design | H91-G004; future/non-selected atomic gate |
| H91-R-F03 | Restart/readiness did not recover | ADR-0001/0002; H91-120, 300-340 | `v5_clean_start_bound`, `v5_crash_start_bound` | H91-G003, H91-G007 |
| H91-R-F04 | Duplicate selected content | ADR-0003; H91-410 | compiler equivalence properties; frozen quality cohort | H91-G010, G013-G015 |
| H91-R-F05 | Candidate displacement | ADR-0004; H91-420 | retrieval flooding/adversarial suite; frozen quality cohort | H91-G011-G015 |
| H91-R-F06 | Correlation prevents semantic reuse | vNext proposal; H91-430, 520 | stable-key SDK examples; mismatch/bypass vectors | H91-G020; context-quality evidence |
| H91-R-F07 | Quality advantage must remain | ADR-0003/0004; H91-640 | frozen five-workflow quality report | H91-G009-G015 |
| H91-R-F08 | Progressive serial latency | ADR-0001/0004; H91-110-140, 630 | 100-request OLS/bootstrap and stage profile | H91-G005-G007 |

## Track A requirements

| Requirement | Handoff obligation | Decision/workstream | Planned test/evidence | Machine gate |
|---|---|---|---|---|
| H91-R-A1-01 | Commit timings for load/decode/mutation/encode/root/transaction/fsync/anchor | H91-110 metrics contract | exact metric-catalog and stage-observer unit tests | H91-G004, G005 |
| H91-R-A1-02 | Logical/encoded bytes, DB/WAL growth, revision and retained-record counts | H91-110 | overflow/saturation tests; baseline raw observations | H91-G004, G008 |
| H91-R-A1-03 | Startup stage timings | H91-120 | unavailable/corrupt-stage readiness tests | H91-G007 |
| H91-R-A1-04 | Retrieval counts at every reduction stage and compiler output | ADR-0004; H91-130 | closed counter catalog; frozen quality report | H91-G010-G015 |
| H91-R-A1-05 | Content-free telemetry | threat model; H91-110-130 | nondisclosure canary and undeclared-label tests | H91-G015, G022 |
| H91-R-A2-01 | Select normalized records plus bounded deltas/checkpoints | ADR-0001; H91-210 | schema/record conformance and canonical vectors | H91-G001 |
| H91-R-A2-02 | Bind parent, delta, roots, result and chain | ADR-0001; H91-210/220 | corrupt/truncate/reorder/rollback properties | H91-G003, G018 |
| H91-R-A2-03 | Dual count/byte checkpoint triggers | ADR-0001; H91-220 | boundary/property tests and 10k report | H91-G004, G008 |
| H91-R-A2-04 | Exact retained revision replay | ADR-0001; H91-220/240 | memory/v4/v5 repository conformance | H91-G002, G018 |
| H91-R-A2-05 | Retention by count/age/bytes with pins and minimums | ADR-0001; H91-230 | policy validation, pin/hold and impossible-ceiling tests | H91-G017, G018 |
| H91-R-A2-06 | Signed guarded compaction | ADR-0001/0002; H91-330 | preview drift, interruption and reconstructability suite | H91-G017 |
| H91-R-A2-07 | Blob GC separate from revision compaction | ADR-0001/0002; failpoints K01-K12 | unchanged blob-GC plan/receipt assertions | H91-G017, G022 |
| H91-R-A3-01 | Never rewrite only v4 copy; verified backup/free space/distinct target | ADR-0002; H91-310 | migration preflight negatives and restore proof | H91-G016 |
| H91-R-A3-02 | Preserve every retained revision/root | ADR-0002; H91-310 | all-revision comparison root and sampled replay | H91-G002 |
| H91-R-A3-03 | Signed source/target-bound migration receipt | ADR-0002; H91-310 | strict receipt schema/signature/substitution negatives | H91-G002, G016 |
| H91-R-A3-04 | Atomic activation; retain v4; reject in-place downgrade | ADR-0002; H91-310 | activation A01-A08 and downgrade suite | H91-G016 |
| H91-R-A3-05 | Interruption at every durable boundary | failpoint matrix; H91-320 | C/M/K/A/R process-kill campaigns | H91-G003 |
| H91-R-A4-01 | Latest-only bounded startup and projection recovery | ADR-0001; H91-340 | retention-ceiling start profile | H91-G007, G008 |
| H91-R-A4-02 | Explicit incremental deep verification | ADR-0001; H91-340 | verified-prefix invalidation and full chain suite | H91-G018 |
| H91-R-A5-01 | Group after representation/governance eligibility | ADR-0003; H91-410 | incompatibility and disclosure tests | H91-G010, G015 |
| H91-R-A5-02 | Stable representative and complete provenance/dependencies | ADR-0003; H91-410 | permutation/tie/dependency properties | H91-G010-G014 |
| H91-R-A5-03 | Required-source and citations cover every member | ADR-0003; H91-410 | citation-alias/invalidation/required-source suite | H91-G013, G014 |
| H91-R-A5-04 | One manifest entry each using existing v1 vocabulary | ADR-0003; H91-410 | exact manifest/disposition and v1 schema tests | H91-G019, G020 |
| H91-R-A6-01 | Requirement/lane/token-aware bounds | ADR-0004; H91-420 | bound derivation and overflow properties | H91-G012, G015 |
| H91-R-A6-02 | Alias coalescing and deterministic source/lineage/content caps | ADR-0004; H91-420 | flooding and input-permutation suites | H91-G011, G012 |
| H91-R-A6-03 | Protected mandatory/policy/dependency/authority path | ADR-0004; H91-420 | protected flood/bound tests | H91-G014, G015 |
| H91-R-A6-04 | Deterministic diversity cannot displace protected evidence | ADR-0004; H91-420 | quantized-MMR properties and frozen cohort | H91-G011-G015 |

## Track B future/non-selected requirements

| Requirement | Handoff obligation | Design authority | Planned future evidence | 0.9.1 disposition |
|---|---|---|---|---|
| H91-R-B1-01 | One atomic plan/compile/seal/materialize/revalidate transaction | vNext proposal: Atomic operation | new-version canonical/conformance suite | non-selected; no v1 registry change |
| H91-R-B1-02 | Deterministic parent/child receipts and ambiguous reconciliation | vNext proposal: Response/idempotency | transport loss/status vectors | non-selected |
| H91-R-B1-03 | Preserve granular clients | vNext proposal: V1 compatibility | old-client/new-server matrix | H91-G020 for 0.9.1 |
| H91-R-B2-01 | Separate semantic identity from execution correlation | vNext proposal: Identities | identity positive/negative vectors | non-selected; examples only in 0.9.1 |
| H91-R-B2-02 | Reuse requires exact authority/policy/pins and closed reasons | vNext proposal: Cache rules; H91-430 | bypass/mismatch vectors and metrics tests | safe v1 reuse guidance only |
| H91-R-B3-01 | Revision preview/execute/status, diagnostics and stable errors | vNext proposal: Revision administration | new operation/schema/SDK compatibility suite | local offline admin only; no v1 RPC |

## Qualification matrix

| Requirement | Mandatory evidence | Implementation phase | Machine gate |
|---|---|---|---|
| H91-R-Q01 | Every migrated revision preserves revision/state/semantic/catalog roots | H91-620, 1030 | H91-G002 |
| H91-R-Q02 | Boundary/random v5 replay equality | H91-620 | H91-G002, G018 |
| H91-R-Q03 | All failpoints return prior or committed, never hybrid | H91-620 | H91-G003 |
| H91-R-Q04 | Backup/verify/distinct restore/downgrade pass | H91-620 | H91-G016 |
| H91-R-Q05 | Compaction preserves pins and rejects drift | H91-620 | H91-G017 |
| H91-R-Q06 | Deep verification authenticates all records | H91-620 | H91-G018 |
| H91-R-Q07 | 10k serial plus mixed concurrency campaign | H91-630 | H91-G004, G008 |
| H91-R-Q08 | Growth below 1 MiB per frozen Hiero-shaped compilation | H91-630 | H91-G004 |
| H91-R-Q09 | Serial slope point and bootstrap upper bound at most 10 ms/request | H91-630 | H91-G005 |
| H91-R-Q10 | Compile p95 meets frozen stricter objective | H91-630 | H91-G006 |
| H91-R-Q11 | Clean/crash readiness at most 30 seconds | H91-630 | H91-G007 |
| H91-R-Q12 | Completion exactly 100% | H91-640 | H91-G009 |
| H91-R-Q13 | Duplicate selected content at most 5% | H91-640 | H91-G010 |
| H91-R-Q14 | Aggregate and every workflow lineage diversity nonnegative | H91-640 | H91-G011 |
| H91-R-Q15 | Budget-displaced:selected below 10:1 | H91-640 | H91-G012 |
| H91-R-Q16 | Citations at least 99%; required source exactly 100% | H91-640 | H91-G013, G014 |
| H91-R-Q17 | All validation remains fail closed | H91-640 | H91-G015 |
| H91-R-Q18 | Exact artifacts, SBOM/licenses, schemas/vectors, install/SDK/demo/negative evidence | H91-700-1120 | H91-G022 |
| H91-R-Q19 | Versions agree and old v1 clients work; exactly 45/70 | H91-700-800 | H91-G019, G020 |
| H91-R-Q20 | Release notes cover format/migration/rollback/retention/limits | H91-740 | H91-G021-G023 |
| H91-R-Q21 | No mandatory non-pass state | H91-610, 650, 1120 | H91-G023 |

## Safety stop conditions

The handoff's prohibited performance fixes map to ADR-0001/0002, the repository threat model, and
H91-G015/G016/G021-G023. Qualification must stop on reduced SQLite durability; weakened checksums,
signatures, provenance, policy, authorization or revalidation; migration of the retained evidence as
the first test; mutation/deletion of the only v4 copy; unverified backup; unguarded history deletion;
`VACUUM` or a larger DB ceiling as the repair; early readiness; lost provenance during deduplication;
mandatory evidence removed by top-K/diversity; v1 contract-digest reinterpretation; new operations in
the frozen v1 registry; blind ambiguous mutation retry; or penetration-testing efficacy claims from
context/storage results.

## Coverage check

The rows above cover every checklist group in handoff sections 3, 4, 5 and 7. Section 6 downstream
Hiero coordination maps to H91-1050 and reuses Q08-Q17 on exact installed candidate bytes; it cannot
run before H91-900/1000 produce and qualify those bytes. Section 8 input identities are authenticated
in the intake evidence and efficiency qualification profile.
