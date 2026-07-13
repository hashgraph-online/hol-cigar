---
name: checkpoint
description: Create an inspectable CIGAR checkpoint before compaction, interruption, or a meaningful task boundary.
argument-hint: "[checkpoint purpose]"
---

Use `checkpoint_create` to record the current task, decisions, active bundle, unresolved work, and present-state evidence. Keep the summary structured and concise. Return the checkpoint identifier, source snapshot, and expiry.

After compaction, compile current state from the checkpoint rather than reproducing an old transcript. Never read or attach a provider transcript as checkpoint data.
