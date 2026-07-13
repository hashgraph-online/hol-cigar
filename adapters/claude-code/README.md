# CIGAR for Claude Code

CIGAR supplies deterministic, inspectable context to Claude Code through its documented plugin, command-hook, and MCP surfaces. The plugin is user-scoped, runs signed CIGAR executables already installed on the host, and never downloads executable code after installation.

## Qualified host

This package is qualified for Claude Code `2.1.207` on Apple silicon macOS and deliberately rejects every version or host outside that recorded compatibility claim. Portable Linux and Windows runtime/test assets are included but remain non-installable until their distributed artifacts pass native platform qualification. The matching `cigar`, `cigar-mcp`, and `cigar-claude-hook` executables must be on `PATH`.

Install and inspect it through CIGAR rather than by editing Claude settings:

```text
cigar plugin install claude-code --dry-run
cigar plugin install claude-code --yes
cigar plugin doctor claude-code --output json
cigar plugin uninstall claude-code --yes
```

Installation uses Claude Code's public marketplace and user-scope plugin commands. Uninstall removes only adapter files managed by the installation receipt; it preserves the portable CIGAR catalog, journal, and other user data.

## What is registered

The root `.mcp.json` starts the installed `cigar-mcp serve` binary directly so Claude owns the lifetime of the stdio server. It exposes ten bounded tools:

- `context_compile`, `context_expand`, and `context_explain`
- `catalog_query`
- `checkpoint_create`
- `handoff_create` and `handoff_accept`
- `effect_prepare`, `effect_commit`, and `effect_status`

Resources use stable `cigar://project`, `cigar://workspace`, `cigar://task`, `cigar://decision`, `cigar://bundle`, `cigar://handoff`, `cigar://effect`, and `cigar://artifact` URI families. Results identify their source or snapshot, expiry, degraded state, and authority lane. Large results are summarized and returned by handle instead of being injected wholesale.

The command hook is registered for session, prompt, instruction, tool, batch, subagent, task, compaction, directory, worktree removal, stop, failure, and end events. Every registration uses `type: command`; this package contains no `prompt` or `agent` hooks and therefore makes no hook-triggered model call.

`WorktreeCreate` is supported by the hook parser and has a recorded fixture, but it is intentionally not registered. Claude Code documents that registering that event replaces its default Git worktree creation behavior. CIGAR observes `WorktreeRemove` without taking ownership of worktree creation.

Newer low-risk events that are not required for CIGAR state transitions have recorded fixtures but are not registered. In particular, `MessageDisplay`, `FileChanged`, notifications, permission UI events, elicitation, and configuration changes would add unnecessary process starts or could alter host behavior. The fixture set keeps schema compatibility visible without claiming a runtime effect.

## Bounded and inspectable behavior

- Startup bootstrap is capped at 500 tokens.
- Prompt compilation uses deterministic task-boundary rules and never injects an identical semantic block twice.
- The hook's daemon call has a 100 ms deadline; command-hook execution is capped by Claude Code at one second.
- Context failure fails open with a visible bounded degraded marker. A governed mediated effect precheck fails closed before dispatch.
- Compaction writes a structured CIGAR checkpoint and recompiles current state afterward.
- Subagents receive recipient-specific handoffs, never the parent transcript.
- `/cigar:why` explains the source, snapshot, bundle, authority lane, expiry, degradation state, and token accounting for the most recent injection.

Claude Code includes `transcript_path` in documented hook input. CIGAR validates it only as inert JSON input and deliberately ignores its value. The adapter never opens, parses, copies, modifies, or relies on provider session files. Durable hook state lives only in the directory supplied by `${CLAUDE_PLUGIN_DATA}`.

Before starting Claude, configure subagent attenuation with `CIGAR_CLAUDE_PLAN_ID`, `CIGAR_CLAUDE_HANDOFF_PROJECT_ID`, and `CIGAR_CLAUDE_HANDOFF_AUDIENCE`, plus exactly one of `CIGAR_CLAUDE_HANDOFF_RECIPIENT_ID` or `CIGAR_CLAUDE_HANDOFF_RECIPIENT_ROLE`. The selected principal or role must resolve to the authenticated CLI recipient and the issuer must be allowed to create handoffs. Each `SubagentStart` creates and accepts a signed, one-use, read-context-only capsule; the hook exposes only its distinct accepted bundle. Missing or rejected authority produces the visible degraded marker instead of substituting the parent bundle.

## Limitations

CIGAR cannot guarantee effects hidden inside arbitrary shell commands, remove provider tool output that is already in context, make provider output deterministic, or replace Claude Code's filesystem and tool permission system. Only recognized mediated effect tools receive the fail-closed pre-dispatch authorization check. Other host tools retain their native permission flow.

Compatibility is based solely on documented hooks and MCP. Private provider files and undocumented configuration stores are not dependencies. If the daemon is unavailable, Claude remains usable and the hook emits a visible degraded marker where context would otherwise have been added.

## Qualification

Run from this directory:

```text
./tests/validate-package.sh
./tests/static-private-path-scan.sh
./tests/run-fixture-demo.sh
./tests/public-surface-smoke.sh
```

PowerShell equivalents are provided for future Windows qualification but are not a Windows support claim. The fixture demo needs the installed `cigar-claude-hook` binary; it substitutes a deterministic CIGAR CLI fixture and makes no network or model call. The public-surface smoke runs strict Claude plugin validation plus hook and MCP schema handshakes. An authenticated model smoke is deliberately separate and must be opted into with `CIGAR_CLAUDE_LIVE_SMOKE=1`.

`package-manifest.json` lists every packaged file except itself in strict path order, with its byte count and SHA-256 digest. The signed `cigar` installer embeds the exact release manifest, so a mutable external package cannot authorize changed bytes by rewriting its own manifest. Installation reads each authenticated payload once, stages only those frozen bytes in a private directory, and rehashes the staged tree before any Claude command runs. Any release byte change requires regenerating the manifest before building and signing the matching installer.
