# CIGAR 0.14.2 — exact query performance candidate

This is an unreleased development candidate on `codex/cigar-0.14.2-speed`, based
on main/release 0.14.1. It is not a signed or published 0.14.2 distribution.

The ordinary o200k token counter now constructs only the encoder and regex it
uses. It avoids unused decode/special-token/sorted-token tables and per-thread
regex replicas. The exact pinned vocabulary, regex, rank/start merge rules,
ordinary-token behavior and tokenizer identity remain unchanged. Long pieces
retain heap merging. Existing graph selection, budget checks, snapshot/delta
formats, privacy/cache boundaries, limits, deadlines and authorization are retained.

An initial ten-call profile reduced cold native SDK initialization/ingest/compile
from approximately 161 ms to 34 ms. This is preliminary profiling, not the final
paired benchmark or a general latency guarantee. The fixed benchmark protocol,
iterations and final verification are tracked under `docs/performance/`.

Python and TypeScript SDK metadata and native-worker compatibility advance together
to 0.14.2. The existing Node `>=24.22.1 <25`, Python `>=3.14 <3.15`, protobuf floor,
protocol and context ABI are unchanged. Publication gates continue requiring the
matching signed version/tag; no registry or remote publication is performed here.
