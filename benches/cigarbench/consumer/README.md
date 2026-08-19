# CIGARBench v2 production consumer

`cigarbench-consumer` is a non-published benchmark binary that converts one closed assignment
into one `cigar.benchmark-observation.v2`. It deliberately does not score success, recall,
precision, harm, leakage, or answer correctness. R04's independent evaluator owns those
derivations and receives the hidden oracle through a separate channel.

## Process contract

The process reads exactly one canonical `cigar.benchmark-assignment.v2` object from stdin. The
input has no trailing newline. On success it writes one canonical observation followed by one
newline to stdout and writes nothing to stderr. On failure it exits nonzero, emits no observation,
and reports only a fixed content-free category and, for typed API failures, the numeric public
error code.

Assignments and fixture archives must be strict UTF-8 JSON: duplicate keys, unknown fields,
non-finite numbers, non-canonical serialization, unsafe paths, unsorted exclusions/files, wrong
media types, digest mismatches, symlinks, and configured size overruns fail closed. Assignment and
archive schemas are:

- `schemas/refinement/assignment-v2.schema.json`
- `schemas/refinement/fixture-archive-v1.schema.json`
- `schemas/refinement/observation-v2.schema.json`

The assignment includes source, archive, treatment, task, run, pair, prompt, model, budget, and
flow pins. It intentionally has no oracle, expected-answer, critical-evidence, prohibited-evidence,
or canary-label field.

## Production path

The archive is digest-checked before parsing and extracted into a new temporary directory with
create-new files. A deterministic fixture connector reads those extracted files and derives
record identities only from canonical path/content facts, avoiding temporary inode and timestamp
variance. The connector is installed into the production `ConfiguredSourceRuntime`; the consumer
then executes the same typed application operations used by service transports:

1. `discoverSources`
2. `ingestCatalog`
3. production index build and activation
4. `createContextPlan`
5. `compileContextBundle`
6. `getContextBundleManifest`
7. `explainContextBundle`
8. `materializeContextBundle`

The installed compiled policy, authorized retrieval partition, catalog repository, retrieval
index, compiler, reference tokenizer, and materializer are real crate implementations. Optional
assignment flags additionally exercise handoff authority preview, deterministic effect recovery,
and structured replay comparison.

Excluded records are filtered in discovery before ingestion. Neither their bodies nor archive
paths are copied into observations. Failures never interpolate source or service text. The
controller must still scan stdout, stderr, and decoded retained artifacts for corpus canaries.

## Reproduction and identities

Every observation pins catalog, graph, index, policy, planner, compiler, tokenizer, materializer,
consumer executable, model, and prompt identities. It retains canonical, base64url-encoded plan,
bundle, manifest, explanation, materialization-reference, and optional-flow artifacts. Every
artifact has an exact byte count and SHA-256 multihash. Selected block rows reproduce bundle
order, lanes, representations, provenance, and token counts; disposition rows reproduce the
authorized manifest.

`observation_id` is the SHA-256 multihash of canonical observation bytes with only
`observation_id` omitted. It is not the hash of the final self-containing record. The Python
launcher re-derives this identity, every artifact digest, and the cross-artifact bundle/manifest
bindings.

`recorded` mode preserves all semantic facts and normalizes phase and end-to-end wall timing to
zero. Given the same assignment bytes and executable, its stdout is byte-identical. `production`
mode records integer wall timings and is not expected to reproduce byte-for-byte.

## Paired launcher

`tools.refinement.consumer` takes separate canonical champion and candidate assignments plus exact
absolute executable paths. It verifies that pair fields agree outside treatment/source, chooses a
deterministic balanced treatment order, sanitizes the environment, launches without a shell,
bounds time and both output streams, kills the process group on violations, and validates each
observation before returning it.

```sh
python3 -m tools.refinement.consumer \
  --champion-assignment /absolute/private/champion.json \
  --candidate-assignment /absolute/private/candidate.json \
  --champion-consumer /absolute/bin/champion-cigarbench-consumer \
  --candidate-consumer /absolute/bin/candidate-cigarbench-consumer \
  --cwd /absolute/benchmark/work \
  --state /absolute/private/consumer-state \
  --schemas /absolute/hol-cigar/schemas/refinement
```

The launcher rejects a successful process that writes stderr, more than one stdout record,
noncanonical or duplicate-key JSON, an incomplete observation, an invalid self-ID, an executable
pin mismatch, an assignment mismatch, an incomplete production trace, nondeterministic recorded
timing, malformed retained bytes, or inconsistent reproduction artifacts.

Build and test the consumer with:

```sh
cargo test --locked -p cigarbench-consumer --all-targets
cargo clippy --locked -p cigarbench-consumer --all-targets -- -D warnings
python3 -m unittest discover -s tools/refinement/tests -v
```
