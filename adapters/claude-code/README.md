# CIGAR for Claude Code

CIGAR's development adapter supplies deterministic, inspectable context to Claude Code through its documented plugin, command-hook, and MCP surfaces. Its design is user-scoped, invokes separately built CIGAR executables on the host, and does not download executable code during the plugin lifecycle.

## Development compatibility target

This is the unpublished, unsupported development package for CIGAR Honey `0.9.0-honey.1`, targeting Claude Code `2.1.207` on Apple silicon macOS. The declared version range and platforms define a future qualification scope only; they are not evidence of installed compatibility, signing, release qualification, publication, or support. The Honey installer rejects every version or host outside that narrow target. Portable Linux and Windows runtime/test assets remain non-installable until their distributed artifacts pass separate native-platform qualification. Any Honey exercise also requires matching `cigar`, `cigar-mcp`, and `cigar-claude-hook` executables from one verified native archive. The installer captures the exact hook and MCP bytes and stages them under `${CLAUDE_PLUGIN_ROOT}/bin`; neither runtime command is resolved through ambient `PATH`.

The release-mode `cigar` executable embeds the reviewed adapter manifest and every manifest-bound source byte at compile time. Plugin installation therefore does not read this checkout or accept a mutable package as its authority. An explicit `CIGAR_CLAUDE_PLUGIN_SOURCE` remains a development-test injection point; production and installed qualification omit it and exercise only the embedded payload.

Exercise the planned lifecycle through a matching CIGAR development build rather than by editing Claude settings:

```text
cigar plugin install claude-code --dry-run
cigar plugin install claude-code --yes
cigar plugin doctor claude-code --output json
cigar plugin uninstall claude-code --yes
```

The development implementation uses Claude Code's public marketplace and user-scope plugin commands. Its uninstall path removes only adapter files managed by the installation receipt; it preserves the portable CIGAR catalog, journal, and other user data. These commands are qualification inputs, not release installation instructions.

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

## Development qualification procedure

Run from this directory:

```text
./tests/validate-package.sh
./tests/static-private-path-scan.sh
./tests/run-fixture-demo.sh
./tests/public-surface-smoke.sh
```

PowerShell equivalents are provided for future Windows qualification but are not a Windows support claim. The fixture demo needs the installed `cigar-claude-hook` binary; it substitutes a deterministic CIGAR CLI fixture and makes no network or model call. The public-surface smoke runs strict Claude plugin validation plus hook and MCP schema handshakes. An authenticated model smoke is deliberately separate and must be opted into with `CIGAR_CLAUDE_LIVE_SMOKE=1`.

The development archive producer must receive the exact previously built native runtime archive. It copies both `bin/cigar-claude-hook` and `bin/cigar-mcp` from that contract-verified archive instead of compiling second copies:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-claude-plugin-build \
  python3 scripts/release/build_claude_code_plugin.py \
    --runtime-archive /private/tmp/cigar-native-build/cigar-0.9.0-honey.1-aarch64-apple-darwin.tar.gz
```

Installed development qualification uses the exact runtime and plugin archives under an isolated owner-private home. A real local Claude Code executable can exercise its documented public lifecycle commands without making a model request:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-claude-installed-qualification \
  python3 scripts/release/qualify_claude_code_plugin.py \
    --runtime-archive /private/tmp/cigar-native-build/cigar-0.9.0-honey.1-aarch64-apple-darwin.tar.gz \
    --runtime-archive-sha256 <independently-recorded-runtime-sha256> \
    --plugin-archive /private/tmp/cigar-claude-plugin-build/cigar-claude-code-0.9.0-honey.1.tar.gz \
    --plugin-archive-sha256 <independently-recorded-plugin-sha256> \
    --claude /absolute/path/to/claude \
    --claude-sha256 <independently-recorded-claude-sha256>
```

When a real Claude executable is unavailable, the explicit fixed-host lane exercises the same closed public command protocol without claiming Claude compatibility:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-claude-installed-qualification \
  python3 scripts/release/qualify_claude_code_plugin.py \
    --runtime-archive /private/tmp/cigar-native-build/cigar-0.9.0-honey.1-aarch64-apple-darwin.tar.gz \
    --runtime-archive-sha256 <independently-recorded-runtime-sha256> \
    --plugin-archive /private/tmp/cigar-claude-plugin-build/cigar-claude-code-0.9.0-honey.1.tar.gz \
    --plugin-archive-sha256 <independently-recorded-plugin-sha256> \
    --fixed-host
```

The qualifier requires independently supplied SHA-256 values before parsing either archive or exercising a supplied Claude executable. It reads each input once, extracts only from captured bytes, and executes only protected copies. It requires the exact packaged thin-arm64 `cigar`, `cigard`, `cigar-mcp`, and `cigar-claude-hook` identities; the plugin archive must reuse both the identical hook and MCP server. The installed plugin manifest closes over every staged adapter and runtime byte.

Lifecycle execution is shell-free and runs under a deny-default macOS `sandbox-exec` profile. Only isolated managed roots are writable, process execution is restricted to frozen binaries and exact staged runtime locations, and network operations remain denied by default. The qualifier snapshots the complete isolated HOME, CIGAR home, project, and provider roots and requires their paths, modes, byte counts, and SHA-256 identities to be identical after uninstall. The provider root is outside candidate read/write authority, and exact canary copies are rejected across every candidate-writable root.

The fixed host, daemon, and hook-backend helpers implement the versioned `cigar.claude-installed-fixture-protocol.v1` command set. They are staged as three independent owner-only files with one recorded digest and invoke only the root-owned Command Line Tools Python executable. Candidate processes receive no transcript-writing authority; consequently the receipt does not claim authenticated fixture invocation counts. Passing `--fixed-host` proves CIGAR's package/lifecycle semantics against exact responses only. It is not evidence that a real Claude build accepted the plugin, that a provider session ran, or that a model response was safe or correct.

Every development receipt remains explicitly unqualified. Real interactive Claude compatibility, a live daemon, approved Developer ID signatures, notarization, a clean frozen candidate, a non-admin clean VM, marketplace publication/readback, and support ownership require independent evidence before the compatibility record or release claims can advance.

`package-manifest.json` lists every packaged file except itself in strict path order, with its byte count and SHA-256 digest. The CLI embeds both that manifest and its complete byte inventory; a mutable external package therefore cannot authorize changed bytes by rewriting its own manifest. Installation reads each selected payload once, stages only those frozen bytes in a private directory, and rehashes the staged tree before any Claude command runs. Any candidate byte change requires regenerating the manifest and repeating the applicable build, signing, and qualification gates.
