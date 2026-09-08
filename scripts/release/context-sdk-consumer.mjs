import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as sdk from "@hol-org/cigar";
import { LocalContextGraph, LocalContextError } from "@hol-org/cigar/context";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
const results = [];
for (const item of cases) {
  try {
    await using graph = await LocalContextGraph.create(item.domain);
    for (const document of item.documents) await graph.upsert(document);
    for (const [from, to, kind] of item.edges) await graph.link(from, to, kind);
    const result = await graph.compile(item.request);
    assert.deepEqual(await graph.verify(result.snapshot), result);
    results.push(result);
  } catch (error) {
    if (!(error instanceof LocalContextError)) throw error;
    results.push({error: error.code});
  }
}
console.log(JSON.stringify({exports: Object.keys(sdk), results}));
