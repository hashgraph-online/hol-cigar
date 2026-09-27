/** Independent consumer; credentials arrive through stdin, never argv/environment. */
import { LocalBrokerConnection, LocalContextClient } from "../context-api.js";
import type { LocalBrokerConnectionConfig, LocalContextRequest } from "../context-api.js";
const input: Buffer[] = [];
for await (const chunk of process.stdin) input.push(Buffer.from(chunk as Buffer));
const config = JSON.parse(Buffer.concat(input).toString("utf8")) as {connection: LocalBrokerConnectionConfig; request: LocalContextRequest};
const client = new LocalContextClient(LocalBrokerConnection.fromConfig(config.connection));
process.stdout.write(JSON.stringify(await client.compile(config.request)));
