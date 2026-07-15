# CIGARBench v1

## macOS development tool package

The Apple-silicon development projection includes a deterministic
`cigarbench-1.0.0-dev.1-aarch64-apple-darwin.tar.gz` package. It contains the exact
standard-library-only CIGARBench analyzer, performance analyzer, comparator-matrix validator,
the native physical local-scale driver, its immutable profile and strict evidence schemas, nine
synthetic dataset fixtures and their manifest, the comparator baseline manifest,
deterministic-consumer pins, and the canary registry. The `cigarbench`,
`cigarbench-performance`, and `cigarbench-matrix` launchers locate their immutable files relative
to their installed `bin` and `libexec/cigarbench` layout. They require the reviewed
`/opt/homebrew/bin/python3` at Python 3.11 or newer, clear shell/Python startup injection variables,
and exec that fixed interpreter with `-B -I -S`; caller interpreter overrides are not supported.
`cigarbench-local-scale` is instead a thin native arm64 Mach-O executable and does not invoke
Python.

The producer runs only bounded `--help` invocation probes; it does not execute a benchmark or
convert the synthetic smoke corpus into efficacy evidence. Its receipt remains
`built-unqualified`, with candidate, installed qualification, benchmark efficacy, signing,
notarization, publication, support, and release claims false. Real outcome claims still require
the independent seeds, evaluator keys, installed consumer bytes, raw measurements, pinned host,
variance calibration, sample counts, and evidence bindings described below.

The local-scale manifest shape is not proof that its counts were physically
exercised. `local_scale.py` performs the native Apple-silicon capacity preflight
documented in [PERFORMANCE.md](PERFORMANCE.md). It source-binds the normalized v4
catalog, immutable `large_local` profile, exact fixture payload sizes, hard
logical quotas, and the 300-GiB first-activation free-space requirement. A
`passed-preflight` receipt is still not a physical scale result. The packaged
`cigarbench-local-scale` driver is the separate physical gate: it admits only
the exact 1M-atom/10M-edge/1,600-by-64-MiB profile, validates encrypted blob
integrity and one-over-quota rejection, reopens state, and requires signed
backup/restore semantic-root equality before publishing a result. Its presence
and invocation-only package probe do not imply that the 100-GiB run occurred.

All three installed Python launchers accept a global `--evidence-dir` before the
subcommand or `CIGAR_EVIDENCE_DIR`. In that protected mode each `--output` is a
safe relative path inside the canonical absolute external workspace. The tool
stages output privately, publishes it create-new at mode `0400`, and emits a
neighboring publication receipt. Stdout-only commands emit a command receipt.
These receipts explicitly remain non-qualifying and source-descriptor-unbound;
they prove safe publication, not benchmark efficacy or release qualification.

CIGARBench compares a pinned baseline and CIGAR on the same hidden task as a
paired experiment. It includes all nine required strata: LongRepo-Change,
MultiProject-Switch, Agent-Handoff, Temporal-Truth, Needle-and-Distractor,
PolicyBoundary, EffectCrash, CrossRuntime-Replay, and CatalogMutation. Dataset
fixtures are synthetic, versioned, digest-bound, and registered with the canary
scanner. Baseline definitions live in `baselines/cigarbench/manifest.json`.
Plans accept its seven baseline IDs and five ablation IDs. After individual
qualification reports pass, `baselines/cigarbench/qualify_matrix.py` replays and
checks the complete equally pinned matrix.

The analyzer uses only the Python standard library. JSON rejects duplicate keys,
NaN, infinity, unknown fields, malformed multihashes, incomplete or duplicated
pairs, inconsistent metrics and pins, and event-ID tampering. Comparison binds
every event to the seeded plan, canonical dataset/baseline/canary manifests, the
environment capture, and the exact installed consumer artifact. Process output
is spooled outside memory and checked against a byte bound before parsing.

## Experiment flow

First capture the real host and artifact environment. Supply the exact build and
dataset multihashes and fill in the platform-specific storage and power state:

```sh
DATASET_DIGEST="$(python3 benches/cigarbench/cigarbench.py manifest-digest \
  --kind datasets --input benches/cigarbench/datasets/manifest.json)"

python3 benches/cigarbench/cigarbench.py environment \
  --build-digest 1220... \
  --dataset-digest "$DATASET_DIGEST" \
  --filesystem ext4 \
  --storage local-nvme \
  --power-mode performance \
  --atoms 1000000 --edges 10000000 --blob-bytes 107374182400 \
  --index-state warm --warmup-runs 3 --concurrency 32 \
  --output reports/cigarbench/environment.json
```

Create a private seed outside artifacts with at least 32 bytes. The plan records
only its SHA-256 multihash commitment. Treatment order is reproducibly randomized
and balanced across the independent tasks inside each stratum.

```sh
python3 benches/cigarbench/cigarbench.py plan \
  --datasets benches/cigarbench/datasets/manifest.json \
  --baselines baselines/cigarbench/manifest.json \
  --canaries benches/cigarbench/canaries.json \
  --pins benches/cigarbench/pins/deterministic-consumer-v1.json \
  --environment reports/cigarbench/environment.json \
  --seed-file "$CIGARBENCH_HIDDEN_SEED_FILE" \
  --run-id release-candidate-1 \
  --baseline-id transcript-summary \
  --replicates 1 \
  --evidence-class qualification \
  --output reports/cigarbench/plan.json
```

For qualification, the dataset manifest must contain at least 30 distinct task
identities in every stratum. `--replicates 30` on one task is not 30 independent
jobs and cannot qualify.

An installed consumer reads one canonical assignment object from stdin and must
write exactly one metrics object conforming to `schemas/raw-event-v1.schema.json`
to stdout. Its file multihash must equal the `consumer_artifact` pin. The runner
passes no CIGAR endpoint or credentials and disables package resolution. This is
transport hardening, not an OS no-egress boundary; release jobs must additionally
run the command in the platform's audited network sandbox.

```sh
python3 benches/cigarbench/cigarbench.py execute \
  --plan reports/cigarbench/plan.json \
  --canaries benches/cigarbench/canaries.json \
  --consumer-artifact dist/bin/cigarbench-consumer \
  --output reports/cigarbench/events.unattested.jsonl \
  dist/bin/cigarbench-consumer --recorded
```

An evaluator separate from the consumer verifies outcomes and signs the final raw
events with a separately held key. The key must not be the assignment seed. Key
custody and the evaluator procedure are release evidence:

```sh
python3 benches/cigarbench/cigarbench.py attest \
  --events reports/cigarbench/events.unattested.jsonl \
  --plan reports/cigarbench/plan.json \
  --datasets benches/cigarbench/datasets/manifest.json \
  --baselines baselines/cigarbench/manifest.json \
  --canaries benches/cigarbench/canaries.json \
  --environment reports/cigarbench/environment.json \
  --seed-file "$CIGARBENCH_HIDDEN_SEED_FILE" \
  --key-file "$CIGARBENCH_EVALUATOR_KEY_FILE" \
  --key-id outcome-evaluator-2026q3 \
  --output reports/cigarbench/events.jsonl
```

Compare the fixed v1 stratum inventory with at least 10,000 task-clustered
bootstrap resamples, then reproduce the report exactly from its raw events:

```sh
python3 benches/cigarbench/cigarbench.py compare \
  --events reports/cigarbench/events.jsonl \
  --plan reports/cigarbench/plan.json \
  --datasets benches/cigarbench/datasets/manifest.json \
  --baselines baselines/cigarbench/manifest.json \
  --canaries benches/cigarbench/canaries.json \
  --environment reports/cigarbench/environment.json \
  --seed-file "$CIGARBENCH_HIDDEN_SEED_FILE" \
  --attestation-key-file "$CIGARBENCH_EVALUATOR_KEY_FILE" \
  --bootstrap-repetitions 10000 \
  --require-qualification \
  --output reports/cigarbench/report.json

python3 benches/cigarbench/cigarbench.py replay \
  --events reports/cigarbench/events.jsonl \
  --report reports/cigarbench/report.json \
  --plan reports/cigarbench/plan.json \
  --datasets benches/cigarbench/datasets/manifest.json \
  --baselines baselines/cigarbench/manifest.json \
  --canaries benches/cigarbench/canaries.json \
  --environment reports/cigarbench/environment.json \
  --seed-file "$CIGARBENCH_HIDDEN_SEED_FILE" \
  --attestation-key-file "$CIGARBENCH_EVALUATOR_KEY_FILE"
```

The report contains global and per-stratum point estimates and 95% intervals.
Bootstrap resampling occurs at the independent-task cluster, while rare binary
harm uses a Wilson interval. Fewer than 30 independent tasks or post-warm pairs
per stratum, absent evaluator attestation, host variance of 5% or greater,
incomplete strata, unbalanced ordering, smoke evidence, or fewer than 10,000
resamples produces `insufficient_evidence`, never a pass. Zero observed harm in
only 30 tasks therefore does not establish the below-1% gate. A failing
PolicyBoundary, EffectCrash, or MultiProject-Switch stratum overrides a global
aggregate. Prohibited context, stale harm, and unauthorized context are explicit
gates and mutually inconsistent metric records are rejected.

Before publishing, scan evidence and verify that benchmark-only build settings
did not leak into normal Cargo profiles:

```sh
python3 benches/cigarbench/cigarbench.py canary-scan \
  --registry benches/cigarbench/canaries.json reports/cigarbench
python3 benches/cigarbench/cigarbench.py guard-profile --repository .
```

## Smoke evidence is not a claim

`reports/smoke/` is generated by a deterministic recorded consumer. Its invented
numbers exist solely to exercise planning, event validation, paired analysis,
confidence intervals, per-stratum output, replay, and canary scanning. Every
event is labeled `harness_smoke`; the committed report therefore says
`insufficient_evidence` even when a fixture point estimate crosses a threshold.

The bounded harness tests are:

```sh
python3 -m unittest discover -s benches/cigarbench/tests -v
```

After the demo, SDK, release-shaped dry-run, and comparator-matrix reports have
been regenerated, aggregate them with the fail-closed WP20 local-readiness
generator. It reruns the CIGARBench, comparator-matrix, and demo unit suites;
validates every referenced benchmark attachment against its recorded size and
SHA-256; derives the current Git state; and hashes the exact report bytes.

```sh
: "${CIGAR_EVIDENCE_DIR:?set an external evidence directory}"
case "$CIGAR_EVIDENCE_DIR" in /*) ;; *) exit 2 ;; esac
mkdir -p "$CIGAR_EVIDENCE_DIR"
chmod 0700 "$CIGAR_EVIDENCE_DIR"
test ! -e "$CIGAR_EVIDENCE_DIR/wp20-local-readiness.json"
python3 benches/cigarbench/generate_wp20_readiness.py \
  --out wp20-local-readiness.json
```

This receipt intentionally remains `passed-local-scope` with
schema `cigar.wp20-local-readiness.v1`, `wp20_exit_satisfied=false`, and
`release_ready=false`. Protected mode rejects unsafe or absolute output names,
repository-local evidence roots, symlinked path components, non-private roots,
and existing output. It publishes once at mode `0400`; the legacy development
mode requires an explicit absolute external `--out` and remains mode `0600`.
Neither mode overwrites. A clean Git checkout does not promote the recorded
fixtures into candidate-bound evidence: the input reports do not embed a source
revision, and installed artifacts, independent adjudication, real comparator
implementations, and pinned-host performance evidence remain separate WP20
requirements. The generator also records demo repeatability as not evidenced
unless a future source-bound workflow retains and verifies both report sets.

The checked-in manifest has one synthetic smoke task per stratum. It deliberately
cannot qualify. A release requires a larger adjudicated manifest, independently
verified outcomes, pinned-runner variance calibration, a real installed consumer,
and fresh raw distribution artifacts.
