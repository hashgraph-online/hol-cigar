---
name: effect
description: Prepare, inspect, commit, and reconcile governed CIGAR effects while preserving explicit authorization and idempotency.
argument-hint: "<prepare|commit|status> [effect id or intent]"
---

Use `effect_prepare` to create a typed intent before any mediated external mutation. Show the effect identifier, target, authorization requirement, idempotency key, and expected outcome. Use `effect_status` to inspect or reconcile existing effects.

Call `effect_commit` only when the user has explicitly authorized the prepared effect and the current governed precheck permits dispatch. Never retry an unsafe or unknown dispatch automatically. If authorization cannot be verified, stop before dispatch and explain the denial.
