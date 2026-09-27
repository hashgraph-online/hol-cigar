# Bounded source ingestion measurement

`broker_ingestion.py` compares the ordinary complete-list source replacement
with the new batch API using the **same candidate worker and SDK**. This is an
offline source diagnostic, not a v0.12/v0.14 installed-version comparison or an
answer-quality study. Use an optimized worker built with `bpe,broker-persistence`.

```bash
python3.14 benchmarks/broker_ingestion.py \
  --worker /absolute/path/to/cigar-context-worker \
  --output /absolute/path/to/new-evidence-directory \
  --sizes 1 8 34 --cohorts 8
```

The harness generates retained JSONL corpora containing 256 KiB documents plus
one small independently checked context probe. Batches contain at most four
documents. Each fresh process starts with old evidence, then reads/decodes the
same corpus and either materializes one complete request or yields batches.
Timing includes input reading, JSON parsing/encoding, native validation/indexing,
IPC and every ingestion call. The final receipt must account for all documents
and withdrawal of the old source. A subsequent compile checks document count,
selected probe, rendering and exact budget; it is outside the ingestion timing.
SQLite runs reopen with a fresh epoch and check that context again.

The 34 MiB corpus exceeds the unchanged 32 MiB request ceiling. The complete-list
call must fail with `LimitExceeded`, `dispatched=False`, no queued frame and an
unchanged source revision. The batch call must commit successfully. **A rejected
operation is not a faster ingestion**: the reducer reports this boundary without
a latency/memory improvement ratio. Unexpected errors stay as failed observations
and prevent a complete result. Missing/duplicate pairs and identity drift fail.

Eight whole-process pairs per source size/storage mode alternate API order. The
report retains every timing and resamples process pairs for its intervals, not
dependent appends. Host and worker RSS are sampled simultaneously every 20 ms
during input-to-ack. These are sampled resident bytes, not PSS or exact allocation
peaks; short operations can end before a second sample. Do not present the 1 MiB
memory values as exact peaks. A working-machine run is not isolated hardware.

Explicit resource bounds are 64 MiB graph text, 256 KiB per document, 10,000
documents, 64 MiB shared retention, a 64 MiB checkpoint and a 256 MiB database.
Other broker limits keep their defaults. The graph count remains compatible with
default grant proposal limits. SQLite also requires database capacity of at least
twice the checkpoint limit plus 65,536 bytes. Sources can be larger than one frame
only within all these bounds; batching does not remove full-checkpoint cost.

The new output directory contains the copied executable, harness/helper sources,
corpora, source commit/patch identities (including untracked native source), raw
observations and computed result. Every process checks its worker/corpus/SDK
identity before and after use. The parent verifies the harnesses and recomputes
the summary. Do not replace the inputs while a study runs. The explicit worker
path excludes bundled-worker verification cost from graph construction timing.

For a separate Node contract check against a compiled candidate SDK:

```bash
node benchmarks/broker_ingestion_node.mjs \
  /absolute/path/to/sdk/typescript/dist/context-api.js \
  /absolute/path/to/evidence/worker \
  /absolute/path/to/evidence/corpus-34.jsonl
```

This confirms single-frame rejection, old-context validity between batches,
one successful commit, stale prior tickets, every document's complete text and
citations, and the same results after SQLite recovery. It records exact worker,
corpus, compiled-SDK and harness hashes. It makes no performance comparison.

Both probes use literal loopback and private temporary stores. Neither invokes a
provider or external service; neither claims OS-enforced network denial. The
complete native/SDK tests cover malformed input, graph/CAS/provenance conflicts,
expiry, private staging, agent/host separation and uncertain commit failure.
`test_broker_ingestion.py` separately checks the result reducer's pairing,
failure denominators, incompatible outputs and rejected-versus-committed boundary.

The initial results and limitations are recorded in the
[development report](../docs/release/context-sdk-0.14.0-batch-ingestion.md).
