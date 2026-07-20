# Honey 0.9.1 durable failpoint matrix

Status: frozen architecture input. Every row is mandatory for generated-fixture qualification unless
the row is explicitly a verified-copy-only repetition. Returned-error tests supplement but do not
replace process-kill tests.

## Universal assertions

After every injected failure:

- v4 source and verified backup device/inode/size/digest remain unchanged;
- a repository exposes the prior authenticated revision or the complete committed revision, never a
  hybrid, fork, gap, unverified root, or partial receipt;
- readiness remains closed until state, projections required for service, anchors, and recovery
  records authenticate;
- resume is idempotent or cleanup is restricted to the exact create-new target/work files named by a
  signed plan;
- no blind mutation retry occurs after an ambiguous outcome; reconciliation uses idempotency,
  revision, chain head, and receipt identity;
- content-free telemetry reports only the stable phase/reason; and
- the test reopens in a new process and runs repository conformance plus integrity checks.

Outcome codes used below:

- `P`: prior revision/state is authoritative.
- `C`: complete new revision/state is authoritative.
- `A`: ambiguous at transport level; authenticated reopen/reconciliation resolves to `P` or `C`.
- `R`: complete-prefix work is resumable without source mutation.
- `N`: non-active target/plan is rejected and may be safely cleaned by exact identity.

## Commit and checkpoint

| ID | Durable boundary | Injection point | Required outcome |
|---|---|---|---|
| H91-FP-C01 | writer serialization | immediately after writer lock, before state load | `P`; lock is recoverable after process exit |
| H91-FP-C02 | idempotency lookup | after matching/missing identity decision, before delta derivation | `P`; matching replay never writes |
| H91-FP-C03 | staged validation | after mutation validation, before canonical delta encode | `P`; no database/WAL publication |
| H91-FP-C04 | delta encode | after canonical bytes/digest, before `BEGIN IMMEDIATE` | `P`; temporary memory only |
| H91-FP-C05 | SQLite writer begin | immediately after `BEGIN IMMEDIATE` | `P`; rollback removes all writes |
| H91-FP-C06 | blob publication | after encrypted blob fsync/rename, before metadata | `P`; reopen quarantines exact orphan |
| H91-FP-C07 | normalized records | after each changed catalog/residual record batch, before delta row | `P`; transaction rollback |
| H91-FP-C08 | delta insert | immediately before delta insert | `P` |
| H91-FP-C09 | delta insert | after delta insert, before root/head update | `P`; transaction rollback |
| H91-FP-C10 | idempotency/outbox/effect | after each causal record insert, before head update | `P`; no partial causal state |
| H91-FP-C11 | checkpoint insert | before checkpoint insert when count trigger fires | `P` |
| H91-FP-C12 | checkpoint bytes | after checkpoint insert, before checkpoint digest/metadata check | `P`; rollback |
| H91-FP-C13 | checkpoint link | after checkpoint verification, before head/root update | `P`; rollback |
| H91-FP-C14 | authority/head update | after roots/head update, before SQLite commit call | `P`; rollback |
| H91-FP-C15 | SQLite commit | immediately before commit call | `P` |
| H91-FP-C16 | SQLite commit return | kill during/at commit system boundary | `A`; reopen resolves atomically to `P` or `C` |
| H91-FP-C17 | external anchor | after SQLite commit, before anchor temporary write | `A`; DB-ahead recovery verifies then advances anchor |
| H91-FP-C18 | external anchor | after anchor temp write/fsync, before rename | `A`; stale temp ignored by exact identity |
| H91-FP-C19 | external anchor | after rename, before parent-directory fsync | `A`; reopen authenticates DB/anchor pair |
| H91-FP-C20 | publication complete | after anchor publication, before response/receipt delivery | `C` via idempotency reconciliation; no duplicate delta |

Rows C05, C08, C09, C15, C17, and C20 extend the existing SQLite failpoint semantics; the
implementation keeps stable test mappings for the existing enum values.

## V4-to-v5 migration

| ID | Durable boundary | Injection point | Required outcome |
|---|---|---|---|
| H91-FP-M01 | backup proof | after backup verification/restore test, before preview signing | `N`; source/backup unchanged |
| H91-FP-M02 | preview | after signed preview write/fsync, before response | `N`; same preview may be read, not regenerated silently |
| H91-FP-M03 | target creation | after create-new work directory, before database create | `N`; exact target-only cleanup |
| H91-FP-M04 | schema create | after v5 schema transaction, before migration authority publication | `N` or authenticated `R` |
| H91-FP-M05 | migration authority | after `building` authority commit, before first source read | `R` |
| H91-FP-M06 | source revision read | after residual/checksum authentication, before delta derivation | `R` |
| H91-FP-M07 | batch delta | before each checkpoint/delta batch transaction | `R` at prior complete prefix |
| H91-FP-M08 | batch records | after v5 records, before progress row in same transaction | `R`; rollback batch |
| H91-FP-M09 | batch progress | after progress row, before batch transaction commit | `R`; rollback batch |
| H91-FP-M10 | batch commit | during/after each batch commit, before next source revision | `R`; reopen authenticates last full prefix |
| H91-FP-M11 | catalog copy/root | after normalized catalog batch, before ordered root verification | `R`; no target activation |
| H91-FP-M12 | final chain | after last revision, before complete-chain verification | `R`; verification repeats |
| H91-FP-M13 | revision comparison | during boundary/random/every-revision comparison | `R`; no activation |
| H91-FP-M14 | target deep verify | during deep-integrity verification | `R`; no verified status |
| H91-FP-M15 | target backup | during v5 backup/create/verify/restore | `R`; incomplete backup not accepted |
| H91-FP-M16 | readiness proof | during clean/crash startup qualification | `R`; target remains non-active |
| H91-FP-M17 | migration receipt | after receipt bytes write/fsync, before signature | `R`; unsigned receipt rejected |
| H91-FP-M18 | migration receipt | after signature, before verified authority update | `R`; receipt may be reverified and adopted exactly |
| H91-FP-M19 | verified authority | after target marked verified, before status response | verified non-active target; source still active |

Every M-row runs first on small generated state, then boundary state, then generated Hiero-shaped
state. The authorized verified copy repeats M01, M06, M10, M12-M19 only after all generated cases
pass, unless review expands that set.

## Compaction and retention

| ID | Durable boundary | Injection point | Required outcome |
|---|---|---|---|
| H91-FP-K01 | preview derivation | after head/policy/backup/pin snapshot, before signing | no mutation; preview absent |
| H91-FP-K02 | preview publication | after signed preview fsync, before response | preview readable/reusable only while all bindings match |
| H91-FP-K03 | execute lock | after exclusive writer lock, before drift recheck | store unchanged |
| H91-FP-K04 | execution marker | after recoverable marker insert, before first logical deletion | `P`; resume/abort from marker |
| H91-FP-K05 | compacted target | after create-new compacted database/schema, before record copy | active store unchanged; exact target `N`/`R` |
| H91-FP-K06 | retained copy | after each checkpoint/delta batch into compacted target | active unchanged; target `R` |
| H91-FP-K07 | pin/range verify | after copy, before reconstructability verification | active unchanged; target non-active |
| H91-FP-K08 | physical reclamation | during compact-target final checkpoint/reclamation | active unchanged; target `R`/`N` |
| H91-FP-K09 | post-root verify | after physical work, before semantic/catalog/chain equality | target non-active |
| H91-FP-K10 | compaction receipt | after receipt bytes, before/after signature and fsync | unsigned/partial receipt rejected; active unchanged |
| H91-FP-K11 | compaction switch | during active descriptor replacement | old or complete new descriptor; never hybrid |
| H91-FP-K12 | post-switch verify | after switch, before readiness/status | complete compacted state or authenticated recovery; pins intact |

Blob GC state, plans, candidate sets, and receipts are checked unchanged across all K rows. A
compaction retry accepts only the exact original signed preview and marker; drift forces a new preview.

## Activation and rollback descriptor

| ID | Durable boundary | Injection point | Required outcome |
|---|---|---|---|
| H91-FP-A01 | activation preflight | after locks and target/receipt revalidation | old descriptor |
| H91-FP-A02 | descriptor temp | after create-new temp write, before file fsync | old descriptor; incomplete temp rejected |
| H91-FP-A03 | descriptor file fsync | after fsync, before atomic rename | old descriptor |
| H91-FP-A04 | descriptor rename | during rename | old or complete new descriptor |
| H91-FP-A05 | directory fsync | after rename, before parent fsync | old or complete new descriptor authenticated on reopen |
| H91-FP-A06 | active open | after new descriptor, during target open/authentication | readiness closed; descriptor status reports recovery required |
| H91-FP-A07 | activation response | after successful active verification, before response | new descriptor complete; status reconciles |
| H91-FP-A08 | rollback descriptor | repeat A02-A07 while selecting unchanged v4 with no post-v5 writes | old or complete rollback descriptor |

## Startup, recovery, and deep verification

| ID | Durable boundary | Injection point | Required outcome |
|---|---|---|---|
| H91-FP-R01 | secure path/config | after path identity, before SQLite open | readiness closed; no mutation |
| H91-FP-R02 | migration ledger | after SQLite configure, during ledger/authority verification | readiness closed |
| H91-FP-R03 | checkpoint read | after latest checkpoint bytes, before digest validation | readiness closed |
| H91-FP-R04 | delta replay | after each replayed delta, before next chain link | readiness closed; next startup restarts authenticated replay |
| H91-FP-R05 | reconstructed state | after replay, before resulting state/root comparison | readiness closed |
| H91-FP-R06 | revision anchor | during DB/anchor reconciliation | readiness closed until exact pair published |
| H91-FP-R07 | catalog projection | during required projection recovery/verification | readiness closed; incomplete generation never active |
| H91-FP-R08 | blob reconciliation | during orphan/quarantine/integrity reconciliation | readiness closed when required by profile |
| H91-FP-R09 | readiness publication | immediately before readiness opens | liveness may be open; readiness remains closed |
| H91-FP-R10 | verified prefix | after deep-check prefix bytes, before signature/fsync | prefix rejected; next deep check starts from prior valid prefix |
| H91-FP-R11 | deep chain | after each retained checkpoint/delta verification | ordinary readiness unaffected; deep status incomplete |
| H91-FP-R12 | deep completion | after final chain verification, before signed completion receipt | unsigned completion rejected and rerunnable |

## Test execution rules

1. Use create-new owner-only workspaces under canonical `/private/tmp`.
2. Freeze fixture digest, tool/source identity, failpoint ID, expected outcome, timeout, and seed before
   launch.
3. Terminate only the child process created for the exact fixture; never use broad process patterns.
4. Reopen with a new process and capture database/WAL sizes, authenticated revision/root/chain,
   readiness timing, recovery reason, and receipt state.
5. Run each boundary enough times to cover before/after ambiguity and deterministic random I/O timing;
   report repetitions and every outcome.
6. A timeout, skipped injection, unobserved boundary, unexpected exit, or unverifiable result is a
   failed mandatory case.
7. Raw observations remain owner-private and content-free; summaries bind their SHA-256.
