/** Independent consumer; credentials arrive through stdin, never argv/environment. */
import { LocalBrokerConnection, LocalContextClient } from "../context-api.js";
import assert from "node:assert/strict";
import type { LocalBrokerConnectionConfig, LocalContextRequest } from "../context-api.js";
const input: Buffer[] = [];
for await (const chunk of process.stdin) input.push(Buffer.from(chunk as Buffer));
const config = JSON.parse(Buffer.concat(input).toString("utf8")) as {connection: LocalBrokerConnectionConfig; request: LocalContextRequest};
const client = new LocalContextClient(LocalBrokerConnection.fromConfig(config.connection));
const context = await client.compile(config.request);
const trace = await client.explain(context.ticket);
assert.equal(trace.snapshot_id, context.context.snapshot.id);
const selected = new Set(context.context.snapshot.blocks.flatMap(block=>block.citations.map(citation=>citation.node_id)));
const traced = trace.steps.flatMap(step=>step.added_ids);
assert.equal(traced.length, selected.size);
assert.deepEqual(new Set(traced), selected);
process.stdout.write(JSON.stringify(context));
