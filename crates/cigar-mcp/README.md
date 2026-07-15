# cigar-mcp

Stability: product surface, pre-v1.

`cigar-mcp` is CIGAR's bounded MCP 2025-06-18 stdio facade. It exposes ten exact tools and eight
stable `cigar://` resource families while keeping authority in the daemon. The server rejects
duplicate JSON keys, malformed envelopes, unknown input fields, requests above 256 KiB, and output
budgets outside 500–4000 approximate tokens. The complete serialized result envelope is charged to
that budget, including escaping and metadata. Larger authoritative JSON responses are retained in a
bounded in-memory store and returned through 128-bit OS-random, process-local handles that expire
after five minutes.

Tools accept the exact typed CIGAR protocol object under `request`; the smaller context and effect
forms are explicit, mutually exclusive schema alternatives. Every daemon-backed operation marked as
a mutation by the generated interface authority requires a caller-supplied `idempotency_key`, so an
MCP retry preserves the original logical operation. Paging an existing local output handle is a read
and does not require an idempotency key.

Modes:

- `cigar-mcp serve` (also the default) runs newline-delimited MCP on stdin/stdout.
- `cigar-mcp doctor` emits only content-free daemon availability.
- `cigar-mcp schema-noop` emits stable build and MCP protocol metadata without contacting a daemon.

The packaged server delegates through the installed `cigar` CLI, optionally selected with
`CIGAR_MCP_CLI_BINARY`. That reuses the CLI's production Unix-socket, named-pipe, loopback-token,
remote TLS/authentication, compatibility, and canonical-envelope behavior without exposing request
content in argv. An injectable loopback-only `HttpBackend` remains available to applications that
provide a dedicated frozen MCP facade. Backend transport details, environment values, and
filesystem paths are never included in MCP errors.

Valid JSON-RPC notifications are always silent. `notifications/cancelled` is correlated using the
same bounded string or JavaScript-safe integer ID rules as requests and interrupts the packaged CLI
process. A cancelled mutating call is reported as potentially ambiguous and must be inspected before
retrying with the same idempotency key.

When the daemon is unavailable, tool failures carry `degraded: true` without a synthetic `data`
field; resource reads return a content-free JSON-RPC error instead of a fabricated resource.
`effect_prepare` and `effect_commit` explicitly fail closed.
