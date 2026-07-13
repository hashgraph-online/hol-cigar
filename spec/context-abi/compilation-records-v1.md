# Compilation records v1

The compilation ABI consists of `ContextPlan`, `PlanLane`, `CandidateDisposition`, `ContextBlock`, `ContextBundle`, `SelectionManifest`, `MaterializedContext`, and `ContextDelta`.

Plans require sorted unique lanes, exact lane-budget sums, one lane per selected version, and agreement between assignments and dispositions. Blocks require non-zero exact token counts and non-empty sorted provenance. Extracted and summarized representations require a transform receipt. Bundle token totals equal the checked sum of their ordered blocks.

Selection manifests contain one sorted unique entry per considered candidate with bounded sorted reason codes and provenance. Materialized bytes use unpadded base64url in JSON and never appear in `Debug`. Deltas require distinct base and target identities with disjoint sorted add/remove sets.

All generated JSON Schemas are listed in `schemas/generated-manifest.json`; Protobuf wire messages are defined in `schemas/proto/context_abi.proto`. Semantic validation remains in `cigar-protocol`.

