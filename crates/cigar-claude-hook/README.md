# cigar-claude-hook

Stability: product surface, pre-v1. This executable consumes only documented Claude Code hook JSON
from standard input. It never opens provider transcripts, session caches, or private provider state.

The runtime stores bounded idempotency, provider-present observations, checkpoints, and token
accounting in the CIGAR-owned plugin data directory. Context failures are visible and fail open;
recognized mediated effect commits fail closed before dispatch.

Subagent handoffs require `CIGAR_CLAUDE_PLAN_ID`, `CIGAR_CLAUDE_HANDOFF_PROJECT_ID`, and
`CIGAR_CLAUDE_HANDOFF_AUDIENCE`, plus exactly one of `CIGAR_CLAUDE_HANDOFF_RECIPIENT_ID` or
`CIGAR_CLAUDE_HANDOFF_RECIPIENT_ROLE`. The hook creates a signed, one-use, read-context-only
handoff and accepts it through the authenticated CLI identity. Only the resulting
recipient-specific bundle is injected; a missing or rejected configuration produces the normal
visible degraded marker.
