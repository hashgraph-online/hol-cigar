# Hiero campaign evidence producer

`import_hiero.py` reads retained campaign data and writes the common evaluation
envelope. It never runs a campaign, worker, model, command, oracle or reader from
the evidence directory. The current producer supports deterministic mock/no-AI
campaigns. Recorded model answers belong in the separate
[answer adapter](ANSWERS.md).

```sh
python benches/context-evaluation/import_hiero.py /absolute/hiero-study-input \
  --output /absolute/new-hiero-evidence
python benches/context-evaluation/evaluation.py /absolute/new-hiero-evidence
```

Input files must be contained regular files, without symlink components. The
importer checks every artifact before and after use, copies original bytes under
`raw/`, retains itself and the evaluator, and refuses to overwrite output.
Re-importing `output/raw` with the same importer reproduces the result. The
hashes establish which bytes were supplied, not who produced them or whether
their account of execution is truthful.

## What the metrics mean

| Metric | Source and denominator |
| --- | --- |
| `process-exit-success` | Original execution has exit code zero / observed campaigns |
| `campaign-complete` | Exit zero and declared completed iterations equal the planned count / observed campaigns |
| `retained-iterations` | Retained contiguous iteration receipts / planned iterations |
| `declared-context-quality-pass` | Iteration receipts declaring `passed` / observed iterations with complete quality fields |
| `declared-target-executions` | Sum of Hiero's `target_executing_validation_count` declarations |
| `declared-synthetic-self-tests` | Sum of `synthetic_harness_self_test_count` declarations |
| `declared-context-tokens` | Sum of `token_budget_used`; this may be an estimate, not provider-exact token accounting |
| `campaign-wall-ms` | Original campaign seconds converted to milliseconds; descriptive, including failed processes |
| `terminal-contract-success` | All registered checks match a complete target readback / observed terminal contracts |
| `terminal-check-pass` | Matching terminal fields / registered checks |

The first eight metrics do not establish task correctness. In particular,
`oracle_validated_count`, context quality `passed`, a synthetic self-test and a
zero exit code cannot supply a terminal result. Missing fields are unavailable,
not zero. An interrupted process may have completed a target action, so a
separately bound terminal readback can establish the registered outcome despite
the process failure. This does not authorize a retry.

A nonzero exit from an observed campaign is a measured process failure. Use
record `status: "failed"` only when the campaign observation itself is missing;
its metrics remain unavailable and its pair incomplete. Use `unsupported` for
an explicitly unimplemented treatment, also retaining the pair. Neither status
may conceal supplied original execution/iteration/readback receipts.

## Input index

`study.json` has these required fields and rejects extras:

```text
schema = "cigar.hiero-study.v1"
id, evidence_class, oracle_kind, model_mode, cluster_unit, seed
baseline, candidate, cohorts, conditions, treatments, tasks, inputs, artifacts
```

Treatment identities and artifact descriptors use the
[common contract](README.md). Bind the actual `hiero-cigar-context` executable
as a `worker` artifact; original execution receipts must carry that exact hash.
Preserve original build/source identities too. A label such as `candidate` is
not a package identity. Artifacts are bounded to 240 entries, leaving room for
the generated envelope. Archives may retain larger corpus/harness inventories;
the importer hashes their bytes and does not extract or execute them.

Each task has `id`, `definition`, its canonical definition `sha256`, `cluster`
and `stratum`. Definitions must include:

```json
{
  "workflow": "consensus-node",
  "target_revision": "FULL_40_CHARACTER_TARGET_COMMIT",
  "requested_iterations": 3,
  "ai_mode": "mock"
}
```

The commit placeholder must be replaced with the real lowercase Git identity.
Extra definition fields can bind the precise task, corpus, budget and acceptance
conditions. `ai_mode` is `mock`, requiring the matching command option, or
`not-used`, requiring its absence. The latter covers the retained JSON-RPC
workflow, whose own result declares AI unused while the outer historical batch
receipt uses the generic `mock` label. The producer must substantiate this
disposition from its retained source; absence of an option alone is not proof.

Tasks sharing one target repository should share a cluster where their outcomes
are dependent. Repeated campaigns or iterations do not create new independent
task clusters. Use `process-cohort` only for a registered paired performance
study; a failed campaign finishing quickly is not an efficacy improvement.

`model_mode` is always `none` here. Evidence classes are `invariant`,
`performance` or `task-outcome`. The last requires executable/independently
adjudicated oracles and an identified terminal reader for every task. Review
must still establish that the reader observes the target independently of the
agent and producer assertions. These metadata checks cannot establish that fact.

Inputs are:

```text
corpus           corpus artifact, including exact inputs or frozen-index bytes
oracle           oracle artifact using the schema below
harness          original campaign producer artifact
records          observations artifact containing campaign JSONL records
terminal_reader  harness artifact ID, or null when no reader was retained
campaign_receipts exact list of source artifact IDs used for execution,
                  iteration and terminal readback documents
```

Every listed campaign receipt must be consumed once. Missing, reused, omitted or
duplicated receipts invalidate the import. Original legacy documents retain all
their fields; only the surrounding new contract is closed. Extra legacy fields
are preserved but cannot silently become success metrics.

## Original campaign records

Each JSONL row has exactly:

```text
schema = "cigar.hiero-campaign-observation.v1"
task, treatment, cohort, replicate, status, campaign_id
identity = {version, source_commit, artifacts, harness_sha256}
execution = source artifact ID, or null for failed/unsupported observations
iterations = source artifact IDs in contiguous order starting with iteration 1
terminal = terminal readback artifact ID, or null
```

The identity must match its treatment and original producer artifact. The
original `execution.json` binds workflow, required compiler, version, worker
hash, requested iteration count and recorded offline/mock mode. Its command
must identify the same campaign, target revision and iteration count, without
duplicate options. The importer does not run that command. Its retained
iteration-file count must agree with the supplied documents. Iteration fields
such as context-quality status, counts and token estimates remain declarations.

## Terminal oracles and readbacks

Choose terminal acceptance conditions before the study from target tests,
specifications or an independent reviewer. Do not derive success criteria from
which context the candidate selected. Retain the read-only target-state reader
and its dependencies as an immutable harness artifact. After each campaign,
read the authoritative state and retain the result with the execution digest.
An agent's own narrative or a harness self-test is not a target readback.

The oracle artifact has schema `hiero.context-task-oracles.v1` and `tasks`.
Each entry binds a task ID and definition digest:

```json
{
  "task": "ledger-operation",
  "task_sha256": "TASK_DEFINITION_SHA256",
  "mode": "terminal-readback",
  "checks": [
    {"id": "state", "path": ["effect_state"], "equals": "applied"},
    {"id": "send-count", "path": ["send_count"], "equals": 1}
  ]
}
```

This is an illustrative contract, not a claim that those field names describe
every target. Paths contain object keys or nonnegative array indices. Equality
uses exact canonical JSON types: `true`, `1` and `1.0` differ. A missing field
fails its check rather than comparing equal to null. There must be 1–128 distinct
checks. For a historical task lacking an oracle, record `mode: "unavailable"`
and `checks: []`; do not invent a passing oracle retrospectively.

A terminal artifact has exactly:

```text
schema = "hiero.context-terminal-readback.v1"
campaign_id, task, task_sha256, treatment, cohort, replicate, target_revision
execution_sha256, oracle_sha256, reader_sha256
mode = "target" | "synthetic"
complete = boolean
state = object read from the target
```

All identity/digest fields must match the registered task, campaign and supplied
artifacts. Every registered check is evaluated against `state`. The importer
does not trust a producer-supplied `passed` summary. A null, incomplete or synthetic
readback leaves both terminal metrics unavailable. Hashes cannot authenticate the
reader's state observation, prove its independence or prove that the target
revision actually executed; those require producer and provenance review.

The adapter does not measure hallucination prevalence, reverify historical
context packs, or establish best-in-class quality. It makes the boundary between
declared checks and bound terminal observations explicit and reproducible.
