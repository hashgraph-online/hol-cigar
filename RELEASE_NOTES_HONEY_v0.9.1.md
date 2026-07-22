# CIGAR Honey v0.9.1 release notes

CIGAR is an alpha project from [HOL.org](https://hol.org).

Version: `0.9.1-honey.1`
Channel: `honey`
State: alpha developer preview
Context ABI: `cigar.context.v1`

Honey 0.9.1 is a bounded proof-of-concept repair release for the persistence, restart, retrieval,
duplicate-content, and correlation-related efficiency issues observed during the 100-with/100-without
CIGAR security-platform evaluation. The candidate remains unpublished until explicit release-owner
approval. Publication keeps it an unsupported developer preview that is not production-qualified.

## Attachments

The public candidate contains exactly these 13 files:

| Attachment | Purpose |
|---|---|
| `cigar-0.9.1-honey.1-source.tar.gz` | Exact release source |
| `cigar-0.9.1-honey.1-docs.tar.gz` | Version-bound documentation |
| `cigar-0.9.1-honey.1-schemas-conformance.tar.gz` | Protocol schemas, vectors, and conformance inputs |
| `cigar-0.9.1-honey.1-aarch64-apple-darwin.tar.gz` | CLI, daemon, MCP, hook, man page, and completions |
| `cigar-sdk-0.9.1-honey.1.tgz` | TypeScript ESM SDK |
| `hol_cigar-0.9.1.dev1-py3-none-any.whl` | `hol-cigar` Python wheel |
| `hol_cigar-0.9.1.dev1.tar.gz` | `hol-cigar` Python source distribution |
| `cigar-rust-sdk-0.9.1-honey.1-local-registry.tar.gz` | Offline Rust registry kit |
| `cigar-claude-code-0.9.1-honey.1.tar.gz` | Claude Code plugin using matching runtime bytes |
| `cigar-honey-demos-0.9.1-honey.1.tar.gz` | Deterministic installed-artifact demonstrations |
| `RELEASE_NOTES_HONEY_v0.9.1.md` | This document |
| `honey-release-manifest.json` | Exact artifact, source, profile, and evidence inventory |
| `SHA256SUMS` | SHA-256 for every other public attachment |

## What changed

- SQLite storage format v5 keeps normalized catalog rows authoritative while representing retained
  revisions as typed incremental deltas plus bounded checkpoints. Ordinary mutations no longer
  persist a complete catalog-free residual state.
- Startup authenticates the latest checkpoint and bounded delta suffix needed for readiness.
  Full retained-history authentication is an explicit deep-integrity operation.
- Local daemon startup selects an activated v5 target only through the explicit owner-private
  `production.active_store_descriptor`; v4 remains the default when that field is absent, and
  shared deployments reject the setting.
- Generated migration, crash-boundary recovery, backup/restore, compaction, pin, and downgrade
  tests fail closed on revision, checksum, semantic-root, catalog-root, or policy drift.
- The signed v4-to-v5 migration-receipt schema now declares explicit maximum lengths for every
  string field, and its reviewed schema digest/test vector are updated together.
- Compiler selection groups content-equivalent candidates, preserves every governed provenance and
  citation alias, and deterministically chooses one emitted representation.
- Retrieval applies requirement/lane budgets, protected mandatory evidence, alias coalescing,
  source/lineage/content caps, and deterministic diversity before compiler budget displacement.
- Downstream shadow testing exposed and repaired seven additional integration defects: restart now
  reconstructs a pruned mandatory index from authenticated repository state; sparse graph hashing
  walks authorized edges instead of every document pair; per-requirement allowance is distributed
  once across retrieval channels; semantic kind filtering occurs before ranking; combined blocking
  requirements retain their protected allowance; equivalent displaced provenance remains valid; and
  projection integrity is bound to the catalog root so non-catalog revisions do not invalidate an
  otherwise exact projection.
- The SDK documents a stable semantic request key that excludes run/job/trace correlation while
  retaining authorization, disclosure, policy, catalog, tokenizer, materializer, target, and
  compiler pins. Correlation remains in a separate execution receipt.
- New content-free telemetry records commit phases/bytes, retained chain counts, startup stages,
  candidate reduction, result quality, and closed cache reasons.

## Upgrade and rollback

Stop the daemon and create and verify a backup before migration. Migration reads v4 as immutable
source evidence and builds v5 in a distinct, empty, owner-controlled target. Preflight checks exact
source/backup identity, exclusive access, available space, capacity profile, retention policy, and
every retained v4 revision. Duration and free-space requirements are workload-dependent and are
reported by preflight; do not proceed when the bound estimate or reserve is unavailable.

Activation occurs only after the target, signed migration receipt, latest projection, and revision
anchor authenticate. An interrupted migration resumes its signed operation or leaves the prior
source active. Rollback restores the verified backup into another distinct empty target and then
activates that target; v5 is never opened by an older v4 runtime and in-place downgrade is rejected.
The original v4 source remains untouched until an owner separately authorizes removal.

After activation, keep `production.metadata_database` pointed at the retained v4 source and set
`production.active_store_descriptor` to the descriptor under `state_directory`. On restart the
local daemon opens only the descriptor-selected v5 target, verifies bounded readiness, reconciles
the revision anchor and encrypted blob roots, and fails closed on descriptor, path, capacity, lock,
chain, or projection mismatch. See `docs/guides/honey-storage-v5.md` for the exact configuration.

Retention is governed by authenticated count, age, byte, checkpoint, replay-window, pin, legal-hold,
and backup constraints. Compaction is explicit preview/execute/status administration. It rejects an
active writer, missing backup, legal hold, insufficient space, revision/policy/pin drift, or failed
post-verification. `VACUUM`, manual row deletion, and a larger capacity ceiling are not repairs.

## Qualification and compatibility

The public 0.9.1 alpha gate binds one clean source commit/tree, the exact release manifest, package
contracts, strict metadata checks, and installed Python SDK smoke tests. It establishes artifact
integrity and SDK installability, not full-product efficiency or production qualification. The
separate internal efficiency/reliability program remains fail-closed and may not be reported as
passed without its authenticated raw cohort and complete evidence ledger.

The public v1 API remains exactly 45 operations and 70 nominal payload types. Existing granular
clients remain the compatibility surface. Atomic context compilation, signed semantic/execution
identity protocol objects, and retention RPCs are future proposals, not 0.9.1 v1 operations. The
release records commit counts for the existing granular workflow and does not claim a one-commit
atomic RPC.

## Known limits

Only Apple-silicon macOS, embedded mode, and local-sidecar mode are selected. Archives are unsigned
and unnotarized. Honey does not claim production support, remote multi-tenancy, shared deployment,
cross-platform qualification, public registries, live-provider replay, remote OTLP, HTTPS effects,
or vulnerability-finding efficacy. Longevity, full production chaos, notarization, two-builder
reproducibility, and non-macOS qualification remain deferred.

Use the repository discussion/issue channel for content-free product feedback and the private
process in `SECURITY.md` for vulnerabilities. Never post protected source, prompts, credentials,
handoff capsules, stores, or raw qualification attachments.
