# CIGAR corpus v1

This directory is the proposal-visible half of the qualified corpus. It contains 270 public
development tasks (30 independently pinned synthetic source archives in each of the nine
CIGARBench strata), their prompts, digest-bound oracles, source/setup fixtures, two-pass
annotations, resolver decisions, and replayable context-selection results.

The first task in every stratum is a lossless conversion of the corresponding CIGARBench v1
fixture. The remaining tasks have distinct task identities, lineages, normalized prompts, source
revisions, archive/setup digests, critical-evidence sets, postconditions, overlap fingerprints,
and canaries. Task 30 in each stratum is explicitly labeled for insufficient-evidence abstention;
an unanswerable task without that oracle label fails qualification.

## Privacy boundary

`shadow-manifest-v1.json` and `sealed-manifest-v1.json` contain opaque commitments, pack sizes,
aggregate annotation agreement, smoke counts, and selector aggregates only. Their task, prompt,
oracle, fixture, annotation, canary, and per-task selection packs are held under owner-only
permissions outside the Git repository. The private generation seed is also external and is
required to reproduce those packs. The qualifier scans all tracked and non-ignored repository
files for hidden task IDs, canaries, and prompt secrets.

The public manifests deliberately contain no private path. Evaluation infrastructure receives the
private root as an explicit credential-scoped input; proposal adapters do not.

## Qualification and execution

```sh
python3 -m tools.refinement.corpus qualify \
  --repository-root /absolute/hol-cigar \
  --private-root /absolute/private/cigar-corpus-v1 \
  --smoke
```

Qualification verifies canonical bytes, self-identities, every pack digest/size, task/oracle/
archive/setup bindings, license allowlisting, unique canaries, annotation agreement, explicit
abstention labels, selector replay, all cross-partition deduplication keys, and the proposal
privacy scan. `--smoke` additionally materializes and runs every deterministic verifier.

Three executable context selectors are retained:

- `baseline-all-authorized-v1` selects all permitted evidence and distractors;
- `cigar-lexical-v1` is the deterministic recorded retrieval proxy used for corpus construction
  smoke, not a claim about the production Rust retrieval stack; and
- `human-oracle-v1` selects the resolved relevant-evidence annotation.

The production Rust consumer is connected to these task contracts in later paired-run work. These
synthetic, machine-authored annotations are development qualification evidence. They do not
substitute for independent human review or give shadow/sealed results promotion authority.

One task can be selected or its verifier environment materialized without disclosing another task:

```sh
python3 -m tools.refinement.corpus select \
  --repository-root /absolute/hol-cigar \
  --private-root /absolute/private/cigar-corpus-v1 \
  --manifest /absolute/hol-cigar/refinement/corpus/development-manifest-v1.json \
  --task-id development-agent-handoff-001 \
  --selector human-oracle-v1
```

The corpus is generated from `tools/refinement/corpus.py`. Any generator change invalidates
`generated_by`, so regeneration and full qualification are required before commit.
