# Honey MCP and Claude Code

Honey's `cigar-mcp` is a bounded MCP 2025-06-18 stdio facade over CIGAR authority. The Claude Code
plugin packages the exact `cigar-mcp` and `cigar-claude-hook` bytes from the matching runtime archive;
plugin commands are rooted at `${CLAUDE_PLUGIN_ROOT}` and never resolved through ambient `PATH`.

## MCP surface

The fixed Honey tool inventory is:

- `context_compile`, `context_expand`, `context_explain`, and `catalog_query`;
- `checkpoint_create`;
- `handoff_create` and `handoff_accept`; and
- `effect_prepare`, `effect_commit`, and `effect_status`.

Resources use `cigar://project`, `cigar://workspace`, `cigar://task`, `cigar://decision`,
`cigar://bundle`, `cigar://handoff`, `cigar://effect`, and `cigar://artifact`. Large results return a
bounded summary and handle rather than injecting unbounded content.

Configure the client to start the installed binary directly:

```json
{
  "mcpServers": {
    "cigar": {
      "command": "/absolute/path/to/cigar-honey-0.9.3/bin/cigar-mcp",
      "args": ["serve"]
    }
  }
}
```

Every mutation requires an idempotency key. MCP cancellation propagates to bounded backend work;
deadlines and response limits remain enforced even if the client does not cancel. If authority or
state is unavailable, reads return an explicit degraded marker and mediated effect commits fail
closed.

## Claude lifecycle

Honey's compatibility cohort is the exact Claude Code version named in the release record. The
default qualification makes no model call and denies network access.

<!-- docs-check: illustrative -->
```sh
cigar plugin install claude-code --dry-run
cigar plugin install claude-code --yes
cigar plugin doctor claude-code --output json
cigar plugin uninstall claude-code --yes
```

Installation is receipt-owned and preserves unrelated provider settings byte-for-byte. `doctor`
checks the plugin manifest, exact hook/MCP bytes, compatibility, schemas, command paths, and local
backend readiness. Uninstall removes only manifest-owned files.

## Session behavior

Startup bootstrap is capped at 500 tokens. Prompt compilation uses deterministic task boundaries and
does not inject an identical semantic block twice. Compaction checkpoints structured CIGAR state and
recompiles from the checkpoint; resume does not copy a provider transcript into CIGAR. Subagent start
creates a recipient-specific, one-use, attenuated handoff.

Claude includes a `transcript_path` field in hook input. CIGAR validates it as inert JSON and does not
open, parse, copy, or modify that path. CIGAR stores typed context, handoff, decision, effect, and
evidence records—not hidden chain-of-thought.

The hook's context path fails open with a visible bounded degraded marker so Claude remains usable.
The recognized mediated effect precheck fails closed so backend failure cannot silently authorize an
external action. Use `/cigar:why` to inspect source, snapshot, authority lane, expiry, degradation,
and token accounting for the latest injection.

See [Honey troubleshooting](honey-troubleshooting.md) for plugin mismatch and degraded mode.
