---
name: why
description: Explain the provenance, authority, expiry, degradation state, and token accounting of CIGAR context already presented in this session.
argument-hint: "[bundle, source, or current]"
---

Use CIGAR's `context_explain` MCP tool for the requested bundle, source, or current session context. If the user gives no identifier, explain the most recent injection recorded by the hook.

Report the source or snapshot, semantic bundle, authority lane, expiry, degradation state, evidence references, and separate physical, cache-write, and cache-read token counts. Distinguish facts present in the bundle from your own inference. Keep the answer bounded and paginate through handles only when the user asks for more detail.

Do not inspect provider transcripts or private Claude files. If the MCP server is unavailable, say that provenance is temporarily unavailable; do not invent it.
