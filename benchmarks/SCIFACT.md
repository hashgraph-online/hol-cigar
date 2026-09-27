# Offline evidence-selection study

This implements the [registered design](../docs/proposals/context-retrieval-evaluation-0.14.0.md).
The original SciFact development annotations are held out for this library study.
They are public development labels, not hidden test labels or a representative
sample of software-agent work. No provider, model or HOL service is called.

The five treatments are v0.12 default, candidate default, the same explicit BM25
adapter on each version, and a flat BM25 prefix packed with the v0.12 renderer.
All use the same abstracts and 512/2,048/4,096-token budgets. Gold documents and
rationales never enter retrieval or required-evidence requests. The flat control
uses predicted IDs only and stops at the first document that cannot fit.
Its empty prefix uses a fixed nonempty query and an explicitly empty allowed
set; this satisfies the API's query validation while selecting no evidence.

## Reproduction

Use Python 3.14 with the same protobuf runtime for both consumers, the exact
published v0.12 wheel for this machine, and an explicitly built candidate worker.
Freeze the source and candidate bytes before acquiring or inspecting the labels:

```sh
python benchmarks/run_scifact.py freeze \
  --output /absolute/path/to/new-study \
  --python /absolute/path/to/python \
  --baseline-wheel /absolute/path/to/published-v012-platform.whl \
  --baseline-commit 940fc65ee11ccda957649d7e5f1de5a4fa88e07a \
  --candidate-sdk /absolute/path/to/checkout/sdk/python/src/cigar_sdk \
  --candidate-worker /absolute/path/to/candidate-worker \
  --candidate-worker-commit FULL_WORKER_BUILD_COMMIT \
  --candidate-commit FULL_CANDIDATE_COMMIT
```

The freeze copies the SDK sources, workers, recipe, harness, scorer and design.
Its registration binds measured SDK inventories to the actual wheel/source
archive, not just a version string. Candidate source bytes are identified as
development bytes; this does not turn them into a qualified release artifact.
The SDK and native-worker build commits are recorded separately, so an unchanged
retained worker is not incorrectly attributed to a later documentation commit.

Acquire the archive through the owner’s
[documented URL](https://github.com/allenai/scifact/blob/master/script/download-data.sh)
in a separate action. Keep its original bytes, retrieval time, size, SHA-256 and
the upstream [license notice](https://github.com/allenai/scifact/blob/master/LICENSE.md)
outside the CIGAR package/repository. The source URL uses `latest`; archive hashes
are necessary for a reproducible comparison. Never execute the download script.

Use the frozen harness for the remaining steps:

```sh
python /absolute/path/to/new-study/benchmarks/scifact.py prepare \
  --archive /absolute/path/to/downloaded-data.tar.gz \
  --output /absolute/path/to/new-study/data
python /absolute/path/to/new-study/benchmarks/run_scifact.py run \
  --study /absolute/path/to/new-study
python /absolute/path/to/new-study/benchmarks/run_scifact.py score \
  --study /absolute/path/to/new-study
```

Preparation bounds archive expansion and rejects links, special files, traversal,
duplicate members/IDs and overlapping claim IDs. It preserves original annotations
separately from the two files the consumer can read: corpus and claim text.
Predictions retain full results and errors. Scoring refuses an incomplete or
changed 15-cell seal before reading annotations. An interrupted run remains
incomplete; do not silently pool it with a later run or remove failed queries.

The scorer exports the common evaluation contract for four comparisons at all
three budgets. Independent gold labels determine evidence recall, precision,
claim hits and complete rationale coverage. All claims sharing a gold paper form
one resampling cluster, including transitive connections. No-evidence cases stay
in the report; zero recall denominators are unavailable, not manufactured zeros.
Precision is agreement with the annotated evidence inventory, not a judgment
that every unannotated paper is false. Complete abstracts make rationale coverage
depend on paper retrieval; this is not a sentence-reasoning benchmark.

Check exact successful default/ranked result parity between versions, citation
text/line fidelity, budgets and every failed call. Report support, contradiction
and no-annotated-evidence strata; average gains cannot waive a contradiction
regression. Latency, process startup, index construction and summed RSS are
informational here. They come from sequential corpus runs, not independent
performance cohorts. RSS samples every 50 ms are neither PSS nor exact peaks.
Use the separate paired performance suite for release regression decisions.

## Harness verification

```sh
python -m unittest discover -s benchmarks -p test_scifact.py
python -m unittest discover -s benches/context-evaluation -p test_scifact.py
```

These authored cases test evidence handling, not product efficacy. The actual
study must report input/registration hashes and every comparison, including
neutral or adverse results. Do not tune the ranker on this held-out split.
