# Honey security and limitations

Honey is a developer preview for one local operating-system user on Apple-silicon macOS. It provides
meaningful authority, integrity, and traceability controls inside that boundary, but it is not a
security boundary between mutually hostile processes running as the same user.

## Trust model

- Project sources are untrusted data and cannot promote themselves to system/project instruction
  authority.
- Agent A and Agent B are distinct authenticated CIGAR principals, but their local host process
  isolation is supplied by the operator and operating system.
- The local user controls configuration, binaries, keys, daemon state, and evidence storage.
- Embedded and local-sidecar modes are supported. Remote multi-tenant operation is not.
- Filesystem and Git ingestion and the local filesystem reference effect are in scope. HTTPS effects
  and arbitrary extensions are not.

## Controls included in Honey

Honey retains strict schemas and bounded inputs/outputs, policy-before-disclosure, capability
attenuation, recipient/audience/nonce/expiry handoff binding, one-use replay protection, durable
revocation, exact-base merge, typed conflicts, idempotency, intent-before-dispatch, `UNKNOWN`
reconciliation, content-addressed evidence, secret/prompt-injection canaries, and no-egress recorded
demos.

Content-safe telemetry exports operation names, status classes, bounded counts, durations, queue
state, and correlation identifiers—not prompts, source bodies, credentials, encrypted arguments, or
handoff capsules. Telemetry is not durable application truth. Durable evidence and provenance remain
in the CIGAR store.

CIGAR records typed claims, decisions, references, manifests, receipts, and uncertainty. It does not
ask for or store hidden model chain-of-thought. Traceability means attributable inputs, authority,
actions, and outcomes; it does not mean exposing private reasoning.

## Artifact limitations

The Honey archives are unsigned and unnotarized. SHA-256 detects changed bytes relative to the
release checksum, but a checksum downloaded from the same compromised channel is not an independent
signature. Review the GitHub release source and manifest and use a disposable environment for initial
evaluation. Do not disable Gatekeeper globally.

Honey has bounded functional and safety qualification, not the production release program. Deferred
work includes:

- seven-day fuzz accumulation, four-hour mutation testing, and 24-hour soak;
- complete chaos, cross-platform, failover, and SLO matrices;
- million-atom, ten-million-edge, and 100-GiB scale qualification;
- efficacy baselines, ablations, and CIGARBench claims;
- Apple Developer ID signing/notarization and two-builder reproducibility;
- public package registries, Homebrew, OCI, Kubernetes, shared PostgreSQL/S3, OIDC, and remote
  multi-tenancy; and
- production support, independent audit, and GA compatibility guarantees.

## Proof boundaries

Domain-separated SHA-256 identities and Merkle-style content roots prove exact canonical records,
ordering, and inclusion when their inputs are available. They do not prove source truth, model
correctness, human intent, or that an omitted external event never happened. Poseidon is not required
for Honey; a future zero-knowledge proof profile may add a field-friendly hash without changing the
current evidence semantics.

## Vulnerability reporting

Follow the private reporting process in the repository `SECURITY.md`. Include version, artifact
SHA-256, platform, minimal content-free reproduction, affected operation, expected/actual structured
error, and whether an effect may be `UNKNOWN`. Do not publish credentials, private source, prompts,
agent transcripts, handoff capsules, or diagnostic archives.
