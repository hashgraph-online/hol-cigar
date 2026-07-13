---
name: handoff
description: Create or accept a recipient-specific CIGAR handoff without forwarding the parent conversation transcript.
argument-hint: "<recipient or handoff id>"
---

For a new handoff, identify the recipient and use `handoff_create` with the active semantic bundle, explicit claims, unresolved work, and least-authority disclosure. For an existing handoff, use `handoff_accept`, verify its audience and expiry, and report the accepted source bundle.

Do not copy the parent transcript. Expand only authorized referenced material and keep the receiving context bounded and inspectable.
