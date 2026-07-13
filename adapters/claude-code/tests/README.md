# Claude adapter fixtures

`fixtures/events` contains one recorded JSON input for each event accepted by `cigar-claude-hook`. Every fixture includes Claude Code's documented `transcript_path` common field with an intentionally opaque value. Tests prove that CIGAR accepts the field without opening or depending on it.

`fixtures/scenarios` contains semantic cases that reuse an event type, such as an authorized mediated-effect precheck. `fixtures/invalid` contains inputs that must be rejected. `generate-oversized.sh` and `generate-oversized.ps1` produce an event larger than the hook's 64 KiB input limit without storing a large package file.

The Bash and PowerShell demo scripts exercise the installed hook executable against a deterministic local CLI fixture. They cover every event, exact duplicate replay, bounded bootstrap, daemon degradation, effect fail-closed behavior, malformed input, oversized input, invalid state boundaries, and warm prompt latency. No script reads a provider transcript, calls a model, or uses the network.

The public-surface smoke scripts separately run strict Claude plugin validation and the hook/MCP schema handshakes. Setting `CIGAR_CLAUDE_LIVE_SMOKE=1` explicitly opts into one authenticated Claude request; it is never enabled by default.
