# Concepts

An **atom** is the smallest provenance-bearing indexed unit. A **contract** states the task,
budgets, classification ceiling, freshness, source policy, and allowed operation classes. A
**selection manifest** explains every selected and rejected candidate. A **bundle** contains the
canonical context blocks produced from that manifest; a **delta** describes an exact-base change.

A **context space** is a versioned branch for focused work. A **handoff** is a signed, attenuated
capsule that transfers selected state and no broader capability. An **effect** is a governed external
mutation with durable intent, authorization, attempt, and receipt records. **Replay** reconstructs a
recorded decision; observational replay forbids network and mutation, while live comparison is a
separate explicitly authorized operation.

Canonical bytes and digests are deterministic. Retrieval ranking, source freshness, connector
responses, and model output are not automatically deterministic; CIGAR records the inputs and
decisions needed to explain and compare them.

See the detailed references for [catalog ingestion](../reference/catalog-ingestion.md),
[deterministic compilation](../reference/deterministic-compiler.md),
[context spaces](../reference/context-spaces.md), [handoffs](../reference/handoffs.md),
[effect journals](../reference/effect-journal.md), and [decision replay](../reference/decision-replay.md).
