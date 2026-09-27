# Use CIGAR locally from an application or coding agent

CIGAR's local graph needs no HOL account, service, API key, daemon or database.
Use `LocalContextGraph`, not the remote `CigarClient`, when assembling context in
your own process. The npm package is `@hol-org/cigar`; the PyPI distribution is
`hol-cigar` and its import namespace is `cigar_sdk`.

## Start with the installed package

For Node.js 24 ESM, import `LocalContextGraph` from `@hol-org/cigar/context`.
For Python 3.14, import it from `cigar_sdk` or `cigar_sdk.context`.
Run `npx --no-install cigar-context doctor --json` in the npm consumer, or
`python -m cigar_sdk.local_cli doctor --json` in the Python environment. The diagnostic
compiles synthetic context locally and reports the selected platform and version.
Its `capabilities` field describes inspected worker-file availability;
`worker_capabilities` contains features negotiated with the running worker.
Applications can obtain the same handshake report from `graph.capabilities()`.
`compile_verified` means the diagnostic actually compiled and verified a snapshot.
Neither file inspection nor a platform inventory certifies a release's qualification.

If `/context` is not exported, inspect the installed npm version: the old 0.9.4
service SDK lacks that API. Use a local-context distribution. If a worker is unavailable,
inspect the diagnostic's platform and error code. Reinstall the matching distribution
or explicitly supply a trusted matching worker. Do not infer that HOL services or
credentials are required from either error. Never silently fall back to a server.

The 0.12.0 native matrix is macOS ARM64/x64, Linux x64/ARM64 on glibc or musl, and
Windows x64. The npm archive includes platform workers; each Python wheel includes
one platform worker. A source installation needs an explicit matching worker.
The 0.14.0 candidate retains these seven targets. Development native workers have
passed two independent builds on all seven; the final versioned installed matrix
and continuous soak remain release gates. The platform inventory alone does not
certify qualification. See the current release notes and execution checklist.
Node environments must permit local subprocesses; browser/edge execution is a
different runtime contract. These are local executables, not an OS security sandbox.

Run `cigar-context demo --json` through the same environment to exercise the entire
workflow. Its fixture reviewer is explicitly scripted; it is not a model or general
semantic judge. Node consumers can import `runLocalWorkflow` from
`@hol-org/cigar/examples/local-workflow`; Python consumers can import
`run_local_workflow` from `cigar_sdk.examples.local_workflow`.

## Ingest explicitly chosen source text

A document contains `id`, `source`, `text` and an optional `start_line`.
`source` is a provenance locator; assigning a filesystem path to it does not read
that file. Your application selects and authorizes the files it reads. Do not use
retrieved text as permission to read more files or call tools.

Given an already-open graph and a file the caller explicitly selected:

```ts
import { readFile } from "node:fs/promises";

const source = "src/auth.ts";
const text = await readFile(source, "utf8");
const chunks = await graph.chunks({id: source, source, text}, 80, 8);
await graph.replaceSource(source, chunks);
```

```python
from pathlib import Path

source = "src/auth.py"
text = Path(source).read_text(encoding="utf-8")
chunks = graph.chunks({"id": source, "source": source, "text": text}, 80, 8)
graph.replace_source(source, chunks)
```

Reuse stable IDs. Repeat atomic source replacement after edits so obsolete chunks
are withdrawn. Identical documents reuse their indexes. Line chunks preserve source
offsets but do not parse syntax; ingest complete symbols when code needs them.

Add `requires` edges for complete dependencies, `contradicts` for declared conflicts,
and `supports`/`related` for optional retrieval expansion. CIGAR does not automatically
discover factual contradictions or a repository's dependency graph. Attach edges
through trusted ingestion. Removing a node preserves hard edges, which fail closed
until the host repairs the dependency contract explicitly.

## Compile and retain evidence

Keep a graph alive across requests within one appropriate privacy domain. Starting
a new graph per request discards incremental indexes and the exact-token cache.
Always close the graph on shutdown (`try/finally` or `await using` in Node; `with`
or `close()` in Python).

Give `compile` a query and/or required IDs, current `allowed` IDs, `policy_revision`,
`max_tokens` and `reserve_tokens`. `allowed: []` authorizes no sources; omission permits
the caller-owned graph. Graph relationships and relevance do not grant access.
Reserve space for system instructions, history, provider framing and output.
The native worker counts the rendered context using `o200k_base`.

Full text is the default. Query-window excerpts are opt-in; required evidence retains
its full hard dependency closure. Optional `semantic_candidates` can supply ranked
IDs from your existing retrieval index without introducing a CIGAR model-service
dependency. Lexical coverage is not a probability that an answer is true.
The [retrieval adapter guide](RETRIEVAL_ADAPTERS.md) includes a bounded offline
Python reference ranker, an explicit callback contract and Node integration.
Scope text and corpus statistics before indexing or invoking a ranker, and rebuild
the index after source/policy changes. The current graph/view/grant remains the
final authorization boundary; optional ranks never grant access.

Keep the complete snapshot. `promptView` / `prompt_view` can produce a compact
rendering with short citation handles. Keep its citation map and verify it against
the authorized snapshot. `resolveCitation` / `resolve_citation` maps handles such as
`c1` back to source/node IDs and line ranges. The generator receives the rendered
context as data, not as higher-priority instructions or authority.

## Review before displaying an answer

1. Collect the generator's atomic claims and selected node citations in a draft bound
   to the exact snapshot ID. Resolve compact citation handles back to node IDs first.
2. Obtain claim bindings with `reviewKeys` / `review_keys`.
3. Obtain separate, authenticated reviewer verdicts about the entire claims, including
   quantities, negation, qualifiers, source independence and explicit counterevidence.
   Bind verdicts to those exact keys. A generator-supplied `supported` flag is not a
   trusted review. Keep review verdicts, policy and authorization outside its control.
4. Call `checkAnswer` / `check_answer` with the current authorized request, draft and
   reviews. Current compilation must match the draft snapshot. Every claim must pass.
5. Display only the assessed claims when the decision is `release`. Otherwise abstain,
   gather evidence or revise the draft and obtain fresh reviews. Do not append
   unreviewed factual prose after a reviewed answer.
6. Recheck after source or policy changes. Old snapshots and review keys are not
   permission to release an answer against newly changed evidence.

Confidence is optional telemetry in basis points (`confidence_bps`), never release
permission. CIGAR checks bindings, citations and supplied verdicts; it does not run
the semantic reviewer, certify truth, detect every undeclared conflict or guarantee
that a draft includes every assertion. Evaluate the reviewer and answer completeness
separately. The examples' known-fixture reviews cannot establish real-model quality.

## Refresh, synchronize and measure

### Sharing one worker in the 0.13 alpha

One trusted host can create five `createView` / `create_view` handles over one graph.
Host-owned `allowed_sources`, `writable_sources` and `policy_revision` define each
scope. View requests cannot widen it. Compile returns `{rendered, context}`; retain
the entire context and bind drafts to `context.snapshot.id`. Obtain independent
reviews and call the view's `checkAnswer(context, draft, reviews)` / `check_answer`.
An outside-scope update preserves reviews. Every inside-scope document/edge update,
including unselected evidence, requires new reviews. Revocation/redefinition rejects
old handles. Root methods keep their existing global-revision behavior.

Views share one index and serialized worker. They are not authentication, a sandbox,
a durable workflow or an effect permission. Keep root graph and review authority in
the host. Use fresh run domains and reviews after restart; remote agents need a
host-owned broker. HUMIDOR owns scheduling and recovery; this alpha does not replace
or qualify its separate Honey runtime integration. No HOL services are needed for
the local shared-view example in either SDK.

Use `replaceSource` / `replace_source` for edits and an empty document list for
withdrawal. Check cache hits/misses and graph revision with `stats`. Use `clearCache`
/ `clear_cache` when retention policy requires; deallocation is not zeroization.
Snapshots and deltas contain source text and need the same handling as that text.
Apply a delta only to its exact acknowledged base, then verify the reconstructed
snapshot. Deltas save transport/storage bytes; a stateless model still needs complete
reconstructed context.

Track supported-answer yield, erroneous confident releases, abstention, reviewer
errors, context tokens, warm compilation/refresh latency and memory. Keep diagnostic
output content-free. A digest detects changes; it is not a signature or an access grant.

The broader remote catalog, handoff and effect APIs remain available when your
application deliberately chooses a compatible server. They are optional deployments
and do not limit the standalone graph's capabilities.
