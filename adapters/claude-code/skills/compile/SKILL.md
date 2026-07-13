---
name: compile
description: Compile a deterministic CIGAR context bundle for the current task with an explicit token budget and inspectable manifest.
argument-hint: "[task and optional token budget]"
---

Turn the user's task into the smallest explicit CIGAR compile request that preserves mandatory policy and authoritative project context. Use `context_compile` with a default output budget between 500 and 4,000 tokens; never request an unbounded result.

Return the semantic bundle identifier, snapshot or source, expiry, degraded status, authority lane, and a short manifest summary. Leave large material behind a stable handle. Use `context_expand` only for references needed by the immediate task and use `context_explain` when provenance is ambiguous.

Do not copy a project knowledge base into this skill and do not make a model call to decide hook behavior.
