# CIGARBench comparator matrix

`manifest.json` is the closed v1 inventory of seven baselines and five CIGAR
ablations. The selected ID is sent to the pinned installed benchmark consumer as
`baseline_id`; the consumer, not this manifest, must implement the actual
algorithm at the same model, runtime, tools, repository, output budget, sampling,
tokenizer, source, adapter, and compiler pins.

The canonical plan generator accepts both baseline and ablation IDs. A complete
qualification evidence root contains one directory per manifest ID:

```text
evidence/
  fixed-window/{plan.json,events.jsonl,report.json}
  ...
  cigar-without-temporal/{plan.json,events.jsonl,report.json}
```

After every individual report passes, replay and verify the complete matrix:

```sh
python3 baselines/cigarbench/qualify_matrix.py \
  --evidence-root reports/cigarbench/matrix \
  --datasets benches/cigarbench/datasets/manifest.json \
  --baselines baselines/cigarbench/manifest.json \
  --canaries benches/cigarbench/canaries.json \
  --environment reports/cigarbench/environment.json \
  --seed-file "$CIGARBENCH_HIDDEN_SEED_FILE" \
  --attestation-key-file "$CIGARBENCH_EVALUATOR_KEY_FILE" \
  --output reports/cigarbench/matrix-report.json
```

The verifier replays every report from raw events through the canonical analyzer,
requires the exact 12-comparator inventory, passing qualification and evaluator
attestation, distinct event/report evidence, one seed, one environment and
manifest set, and identical pins. A manifest entry alone is not a runnable
baseline and is never treated as evidence. The repository currently contains no
release matrix, so this gate remains unqualified.

## Honey 0.9.4 comparator freeze

`honey-0.9.4-three-way.v1.json` preserves the immutable 0.9.2 and 0.9.3 inputs
for the 0.9.4 three-way experiment. Each treatment binds a full relevant-source
inventory, exact Git commit/tree, Cargo.lock, selection and retrieval profile,
compiler/retrieval goldens, release-mode build artifacts, installed executable
identities, and the independently executed five-workflow Hiero cohort.

The structural check is repository-local:

```sh
python3 baselines/cigarbench/verify_honey_094_baselines.py check
```

Exact reproduction additionally supplies both detached source roots, both
installed roots, and the external Hiero raw/report evidence. The verifier
recomputes the complete manifest and rejects dirty or moving sources, incomplete
artifact identities, profile drift, duplicate treatments, or candidate reuse of
a comparator commit/tree. The JSON Schema fixes the closed record shapes and
profile/source constants; the reference verifier enforces cross-record digest
and source-distinctness relations that JSON Schema cannot express.
