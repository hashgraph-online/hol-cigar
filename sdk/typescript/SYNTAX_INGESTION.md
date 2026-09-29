# Parser integration for exact source chunks (0.14 development)

`chunks_at_lines` in Python and `chunksAtLines` in Node partition explicit source
text at boundaries supplied by your parser. Both use the same native function.
They work on `LocalContextGraph` and the host's `LocalContextBroker`; an agent's
restricted broker client has no preprocessing/admission shortcut.

The worker must advertise `document_boundaries.v1`. The existing fixed-line
`chunks` operation is unchanged. The new operation introduces no parser
dependency, file discovery, model call, source admission or graph mutation.

```python
from cigar_sdk import LocalContextGraph
from cigar_sdk.examples.syntax_ingestion import python_boundaries

document = {
    "id": "module", "source": "project://module.py",
    "text": "def first():\n    return 1\n\ndef second():\n    return 2\n",
}
with LocalContextGraph("project") as graph:
    starts = python_boundaries(document)
    chunks = graph.chunks_at_lines(document, starts)
    graph.replace_source(document["source"], chunks)
```

The packaged Python example uses the host interpreter's `ast` parser. It preserves
top-level statements, decorated functions/classes, async functions, multiline
signatures and the initial preamble. Statements on the same physical line stay
together. It accepts at most 1 MiB of UTF-8, rejects malformed syntax and bare-CR
line endings, and emits no parser diagnostics containing source text. It never
executes the parsed code. It is an example adapter for the host's grammar, not a
sandbox or a promise about the resource use of arbitrary parsers.

Run the complete packaged example with:

```sh
python -m cigar_sdk.examples.syntax_ingestion
```

For another language, supply boundaries from an explicitly installed parser:

```typescript
import {LocalContextGraph} from "@hol-org/cigar/context";

await using graph = await LocalContextGraph.create("project");
const document = {
  id: "module", source: "project://module.ts",
  text: "function first() {\n  return 1;\n}\nfunction second() {\n  return 2;\n}\n",
};
// This fixture's second complete declaration starts at line 4.
// A real parser adapter computes these positions, including decorators/comments as appropriate.
const chunks = await graph.chunksAtLines(document, [4]);
await graph.replaceSource(document.source, chunks);
```

## Native contract

- `starts` contains strictly increasing one-based **absolute source lines**. The
  first chunk starts at `document.start_line` (default 1), so exclude that line
  from `starts`. An empty list returns one complete chunk.
- At most 4095 additional starts and 16 MiB of input are accepted. Each start
  must refer to an existing physical line; there is no extra line after a final LF.
- Each chunk must contain non-whitespace text. Bad, duplicate, reversed,
  out-of-range or empty partitions fail without returning partial results.
- UTF-8 bytes and LF/CRLF line endings are preserved. Joining the output text
  reproduces the entire input exactly, without overlap, omission or normalization.
- Output IDs are `original-id:L<start-line>`; original IDs are limited to 100
  printable ASCII characters. Source locators and absolute starting lines are
  preserved. Locators are metadata and are never opened.
- Additional memory for finding boundaries is proportional to the chunk count.
  The operation does not first build a list containing every input line. Returned
  documents still materialize the full input; this is not streaming ingestion.

Normal graph document, total-byte and IPC limits still apply. One large syntax
unit may exceed the graph's document limit. Select a reviewed subdivision or
explicitly configure an appropriate graph limit; this API does not silently split
the unit or increase resource limits.

## Source and evidence responsibilities

Boundary validation does not prove that boundaries are syntactically correct.
The parser is an application integration point. Keep its version and output in
your ingestion evidence, and test adapters on the languages you actually use.

Syntactic completeness also does not imply semantic completeness: a function can
depend on imports, configuration, types or other functions in different chunks.
Add explicit `requires`/`contradicts` edges where the host knows those dependencies.
The example links its known fixture dependencies; it does not infer general dataflow.

After a source edit, atomically replace the whole source so old chunk IDs are
withdrawn. Line-based IDs can change when earlier text moves. Existing hard edges
remain fail-closed until the host explicitly repairs them. Broker callers must
still supply source CAS and host-owned provenance to admit the resulting chunks;
preprocessing itself changes neither evidence nor source revisions.

These tests establish exact partitioning and boundary behavior. Independent
retrieval/task comparisons at matched token budgets remain a release requirement.
