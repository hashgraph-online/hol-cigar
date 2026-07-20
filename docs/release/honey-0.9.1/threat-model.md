# CIGAR repository threat model

## Overview

CIGAR is a model-agnostic runtime for governed context compilation, bounded agent coordination,
recoverable effects, and replayable evidence. Its primary runtime surfaces are the embedded and
daemon APIs, CLI, MCP server, Claude Code adapter, language SDKs, source connectors, deterministic
compiler, context spaces and handoffs, effect engine, replay engine, cryptographic providers, and
durable repository. Release and qualification tooling produces the artifacts through which those
surfaces are installed.

The selected Honey profile is an unsupported Apple-silicon developer preview for one local operating-
system user. It supports embedded and local-sidecar operation, filesystem/Git ingestion, a local
filesystem reference effect, offline demos, and local SDK/MCP/Claude integrations. It is not a
security boundary between mutually hostile processes running as the same user. Repository code also
contains shared TLS/OIDC, PostgreSQL/S3, remote effects, extension-host, and vector-provider work that
is outside the current Honey artifact profile; those paths matter when selected by another profile
but their presence does not expand Honey's claims.

The highest-value properties are confidentiality of protected sources, prompts, credentials, keys,
handoffs and effect arguments; integrity and authenticity of policy, provenance, revisions, receipts,
artifacts and release evidence; tenant/project/principal isolation; prevention of unauthorized or
ambiguous external effects; deterministic context identity and replay; availability under bounded
adversarial input; and preservation of exact historical evidence through migration, recovery,
retention and compaction.

Concrete security-critical components include:

- strict protocol and generated operation authority in `crates/cigar-protocol`, `crates/cigar-api`,
  `spec/`, `schemas/`, and `proto/`;
- policy-before-disclosure and deterministic selection in `crates/cigar-policy`,
  `crates/cigar-retrieval`, and `crates/cigar-compiler`;
- local bearer and shared TLS/OIDC boundaries in `crates/cigar-daemon/src/auth.rs`, `endpoint.rs`,
  `jwks.rs`, and `authority.rs`;
- durable state, backups, anchors, blobs, idempotency and migration in `crates/cigar-store`;
- signing/encryption/key custody in `crates/cigar-crypto`;
- attenuated handoffs and merge semantics in `crates/cigar-space` and the daemon adapters;
- intent-before-dispatch and `UNKNOWN` reconciliation in `crates/cigar-effects`;
- replay/archive verification in `crates/cigar-replay`;
- extension/provider isolation in `crates/cigar-extension-host` and internal daemon adapters; and
- artifact authority and evidence verification in `packaging/` and `scripts/release/`.

## Threat Model, Trust Boundaries, and Assumptions

### Actors and control classes

Attacker-controlled inputs include untrusted repository/filesystem content, Git metadata and remote
identifiers, source paths within configured roots, context contract fields, API/MCP/SDK request bytes,
pagination/resume cursors, idempotency keys, imported replay archives, handoff/result capsules,
extension/provider outputs, remote HTTP responses, effect observations, vector candidates, and any
package/archive offered for install or restore. Prompt-like source text is always data and cannot
promote its own instruction authority.

Operator-controlled inputs include deployment mode, local paths, capacity/retention policy, trust
roots, OIDC issuer/audience, key provider references, connector/effect capabilities, source scopes,
backup/restore/migration/compaction authorization, release candidate selection, and network policy.
Operator control is not proof of safe configuration: security-sensitive configuration is strict,
bounded, path-verified, and fails closed when ambiguous.

Developer/release-controller inputs include source code, migrations, generators, locked dependencies,
schemas, canonical vectors, package manifests, qualification thresholds, signing identities, release
notes and publication approval. Compromise here can subvert every runtime control and is therefore a
separate high-trust supply-chain boundary.

### Trust boundaries

1. **Untrusted source to governed catalog.** Connectors and parsers cross from attacker-controlled
   bytes/names/history into versioned atoms, edges and source snapshots. Path escape, symlink races,
   parser resource exhaustion, credential-bearing remotes, and content/instruction confusion are
   principal risks.
2. **Client/agent to API authority.** Embedded calls, HTTP/gRPC, local loopback bearer, MCP stdio and
   SDKs cross into generated operations. Authentication must map to an exact principal/tenant;
   operation policy, idempotency, revision requirements, quotas, deadlines and schemas then constrain
   behavior. A generated route or handler is not authorization by itself.
3. **Catalog to protected disclosure.** Retrieval sees candidate references; policy and disclosure
   must run before protected content or denied identity is exposed. Compiler output crosses into an
   agent/model consumer and must preserve provenance, budgets and instruction authority.
4. **Agent principal to agent principal.** Spaces and handoffs cross principal/audience boundaries.
   Capsules require signer, recipient, audience, purpose, nonce, expiry, attenuation, one-use replay
   protection, exact base and typed conflict handling.
5. **Decision to external effect.** The effect engine crosses from proposed intent to a filesystem,
   HTTP, GitHub or other connector. Durable intent and current authorization must precede dispatch;
   timeouts/network loss preserve `UNKNOWN` until authenticated reconciliation.
6. **Runtime to durable evidence.** SQLite/PostgreSQL, encrypted blobs, revision anchors, effect
   checkpoints, backups and receipts cross process/crash boundaries. Atomicity, canonical encoding,
   roots, signatures, secure path identity and `synchronous=FULL` protect this boundary.
7. **Live store to maintenance target.** Backup, restore, v4-to-v5 migration, revision compaction,
   blob GC and activation are distinct privileged boundaries. Source, verified backup, create-new
   target, pins/holds, free space, preview, execution and receipt must remain separately authenticated.
8. **Runtime to provider/extension/vector service.** Subprocess, WASI, remote provider and vector
   adapters receive attenuated requests. Their results are untrusted observations/candidates, not
   policy, provenance, repository or effect authority.
9. **Runtime to observability/dashboard.** Metrics and diagnostic views leave the authority plane.
   They may carry closed counts, timings and statuses but not protected content or durable truth.
10. **Source tree to release consumer.** Generators, builds, archives, manifests, checksums, evidence,
    installation and publication cross the software supply-chain boundary. Exact source/tree and
    installed bytes must be bound; unsigned Honey artifacts do not provide publisher authentication.

### Security invariants

- Tenant, project, purpose, principal, disclosure and policy authority are explicit and cannot be
  supplied ambiently by content, transport headers, extensions or providers.
- Denied content and identity do not cross the disclosure boundary through results, errors, counts,
  timings, explanations, metrics, caches or vector indexes.
- Canonical records have strict versions, bounds, domain-separated digests and no accepted unknown
  fields where semantics affect authority or evidence.
- Repository publication is atomic. After any crash, only the prior or complete committed revision
  can authenticate; idempotency reconciles ambiguity without duplicate effects or deltas.
- Revision order, parent links, state/catalog/semantic roots, anchors, signatures and receipts detect
  deletion, substitution, reordering, rollback and fork attempts.
- Readiness stays closed until mandatory configuration, authority, current state, required
  projections, anchors and recovery checks authenticate. Liveness does not imply safe service.
- Mandatory/required/higher-authority evidence cannot be removed by optional top-K, diversity,
  deduplication, cache or token optimization.
- Content equivalence charges duplicate bytes once but retains every compatible source/version,
  dependency, citation and invalidation identity.
- Every external effect has durable intent, scoped authorization, fencing/idempotency and an explicit
  observation; ambiguous execution remains `UNKNOWN`.
- Private keys and bearer/effect credentials do not enter repositories, packages, environment dumps,
  command arguments, logs, telemetry, diagnostic archives or unprotected backups.
- Maintenance never modifies/deletes the only source, treats an un-restored backup as verified,
  drops protected revisions, combines revision compaction with blob GC, or activates an unverified
  target.
- Derived indexes—including HNSW/vector and semantic graph projections—are generation/revision bound,
  reauthorized on read and rebuildable from authoritative state.
- Release checks do not treat missing, skipped, waived, unknown or source-only evidence as passed
  installed-byte qualification.

### Assumptions and limits

The selected Honey profile assumes the local OS, kernel, filesystem primitives, process owner and OS
credential store behave correctly. The operator protects the account, state paths and backup media
and supplies process isolation between local agents where needed. A malicious process with the same
user's full file/keychain/debug authority can impersonate or tamper with Honey and is outside the
claimed isolation boundary, although secure modes, path checks and cryptographic integrity can still
detect some accidental or offline corruption.

Cryptographic roots prove canonical bytes, ordering and inclusion given trusted keys and inputs. They
do not prove that source claims are true, that a model is correct, that human intent was accurately
captured, or that an omitted external event never occurred. Honey is unsigned, unnotarized,
unsupported and not production-qualified. Remote multi-tenancy, production key custody, hostile
same-user isolation, generalized arbitrary effects/extensions, and publisher authentication require
separately selected and qualified profiles.

## Attack Surface, Mitigations, and Attacker Stories

### Source ingestion, parsing, and code intelligence

An attacker controlling a repository can supply huge/deep files, pathological syntax, Unicode/path
confusion, symlink/hard-link swaps, Git URL credentials, malicious instructions in content, forged
timestamps or dependency cycles. Relevant vulnerability classes are path traversal/TOCTOU, parser
crashes and resource exhaustion, credential disclosure, canonicalization collisions, lifecycle/lineage
confusion, and instruction-authority escalation.

Existing controls include explicit source identities and scopes, capability-based filesystem access,
credential-free remote fingerprinting, strict size/count/depth limits, versioned records, checked
derivation acyclicity, immutable publication revisions, and policy/instruction authority separate
from source text. Tests must exercise link swaps, normalization collisions, adversarial syntax,
cycles, large/deep inputs and source mutation between observation and publication.

### API, daemon, MCP, SDK, and dashboard

Attackers can send malformed/oversized JSON, Protobuf or MCP frames; wrong methods/routes/content
types; forged bearer/JWT claims; replayed idempotency keys/cursors; slow streams; cancellation races;
or browser-originated loopback requests. Shared deployments add TLS name/root, OIDC discovery/JWKS,
algorithm, issuer/audience, cache-staleness and tenant-mapping threats. A dashboard adds XSS/CSRF and
secret exposure if it renders protected fields or stores credentials in browser state.

Controls include exact generated route/handler registries, strict schemas, bounded body/stream/queue
sizes, quotas, deadlines and cancellation, operation-specific auth classes, HMAC-bound cursors,
request-bound idempotency, random owner-only local token files, loopback-only MCP HTTP backends, and
pinned TLS/OIDC policy. Deployment must reject non-loopback local endpoints, URL credentials,
redirect/proxy/root fallback and stale authority. The Honey dashboard should consume only content-free
telemetry/evidence summaries and use a non-browser or explicit same-origin authenticated boundary for
any mutation.

### Retrieval, policy, compiler, cache, and vector/graph projections

An attacker can flood one source/lineage, create aliases or byte-identical copies, manipulate
approximate vector neighbors, exploit score/token overflow, race a policy/catalog/index generation,
or try to infer denied candidates from timing/count/disposition. Malicious content can attempt prompt
injection or masquerade as system/project instruction. Cache-key omission can reuse an artifact across
policy, tenant, authorization, watermark, tokenizer, materializer or disclosure domains.

Controls include governance before disclosure/diversity, snapshot/generation pins, checked integer
scoring, bounded retrieval stages, mandatory closure, strict token/item/lane budgets, deterministic
ordering, provenance-complete blocks, current authorization at explanation/materialization, and cache
keys/invalidation roots covering semantic authorities. Content grouping must not merge incompatible
policy/authority/loss/receipt domains. Qdrant or another vector engine returns candidate pointers only;
SQLite remains the source of truth, and every vector result is filtered, reauthorized and fetched by
exact version. The HNSW neighbor graph is not provenance or knowledge-graph authority.

### Spaces, handoffs, and collaboration

Attackers may replay or redirect a capsule, weaken capabilities, extend expiry, accept twice, forge a
sender/recipient, merge against a stale base, smuggle denied content in results, or exploit conflict
resolution. Controls are signed audience/recipient/purpose/nonce/expiry bindings, monotonic
revocation, one-use acceptance, explicit attenuation, exact base commitments, fencing leases, typed
results/conflicts and policy revalidation. Critical tests cover replay, recipient substitution,
revocation races, expired/overbroad capability and concurrent/stale-base merge.

### Effects and remote dependencies

An effect caller or compromised connector can widen credential scope, change target/body after
approval, dispatch twice, forge success, exploit redirects/DNS/proxies, access metadata services, or
turn timeout into an unsafe retry. Filesystem effects add path/link/race/destructive-operation risks.

The effect engine separates proposal, authorization, durable intent, dispatch and observation;
requests bind exact arguments/connector/capability/fencing token and persist uncertainty. Credential
reach must be no broader than authorized resource scope. Connectors require strict endpoint/TLS/path
policy, response bounds, idempotency and reconciliation. `UNKNOWN` is a safety state, not failure;
blind retry is prohibited.

### Durable state, cryptography, backup, migration, and maintenance

Important attacker stories include corrupt or oversized v5 deltas/checkpoints, truncated/reordered
chains, stale/forked anchors, rollback to an older database, forged/expired retention pins, disk
exhaustion at commit, path substitution, same-user writer races, receipt tampering, malicious SQLite
files, blob swap/corruption, backup substitution, interrupted migration/activation, and compaction
that removes held history.

Controls include strict canonical CBOR, domain-separated state/delta/checkpoint/chain digests,
consecutive parent revisions, semantic/catalog roots, external fsynced anchors, SQLite defensive mode,
WAL and `synchronous=FULL`, secure owner-only regular paths, a single writer, bounded replay,
encrypted content-addressed blobs, reconciliation/quarantine, and authenticated backups/restores.
V4-to-v5 migration uses a verified restored backup, unchanged v4 source, create-new v5 target,
free-space proof, resumable complete-prefix journal, root equality, deep verification, signed receipt
and atomic active descriptor. Compaction requires a signed preview bound to head/policy/backup/pins and
remains separate from blob GC. Every durable boundary has a process-kill failpoint; recovery may
expose only the prior or complete committed state.

### Keys, secrets, telemetry, and privacy

Threats include key/credential bytes in logs/debug formatting, environment/arguments, metrics labels,
crash reports, packages, backups, dashboards or error messages; weak key derivation; wrong-purpose or
cross-tenant key use; lost historical verification keys; and unbounded high-cardinality telemetry.

Controls include Argon2id plus AEAD-protected file keystores, OS keychain provider references,
zeroizing/redacted secret wrappers, key purpose/tenant/status, retained historical decrypt/verify
material, closed content-free metric catalogs and nondisclosure tests. Operational evidence records
digests, counts, duration and closed statuses—not protected bodies. Key compromise remains severe:
hashes cannot authenticate against a compromised trust root.

### Extensions, providers, replay, archives, and supply chain

Extension/provider outputs may be malicious, stale, oversized or cross-tenant; subprocess/WASI/remote
hosts may seek ambient filesystem/network/environment/credential access. Replay archives and package
archives may attempt traversal, duplicate paths, symlinks, decompression bombs, schema confusion or
live-provider egress. Build dependencies, generators, scripts, artifacts, manifests or publication
channels may be compromised.

Mitigations include capability brokers, bounded framed protocols, provider identity/config digests,
no healthy implicit provider, generation binding, network-free observational replay, strict archive
inventories/extraction paths, exact dependency locks, generated-authority drift checks, clean source
requirements, SBOM/license/secret scans, artifact contracts, SHA-256 manifests and installed-byte
qualification. Honey checksums detect drift relative to a trusted checksum but do not authenticate
the publisher; initial use belongs in a disposable environment.

### Realistic and out-of-scope stories

Realistic Honey attackers include malicious project content, a compromised agent/MCP client with only
its issued principal/capabilities, malformed local requests, corrupted/copied state or archives,
ambiguous effects, and dependency/release tampering. A different unprivileged OS user attacking
improper file/socket modes is also realistic.

A process already running with the Honey user's full file, keychain, debug and code-execution
authority is outside the claimed hostile-isolation model. A root/kernel/hypervisor compromise,
cryptographic primitive break, malicious Apple platform, or human-authorized destructive command
with all checks deliberately bypassed is outside repository enforcement. These limits do not excuse
unexpected privilege widening, cross-tenant disclosure, silent corruption, unsafe defaults, or
misleading production claims.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

A realistic path that crosses the core authority/effect/release boundary with broad irreversible
impact: unauthenticated remote or cross-tenant arbitrary effect execution with protected credentials;
release-signing/build compromise producing accepted malicious artifacts; private key extraction that
enables repository-wide receipt/handoff forgery; or migration/compaction that predictably destroys the
only evidence and verified backups across tenants. Honey's local-only unsupported status can reduce
deployment breadth, but not the impact where the path is actually selected and reachable.

### High

Cross-tenant/project protected-content disclosure; policy-before-disclosure bypass; forged/replayed
handoff accepted with unauthorized capability; blind retry causing a destructive duplicate effect;
path escape writing outside an authorized root; accepted state/anchor/backup substitution; corrupt
delta chain authenticating a hybrid revision; or local bearer/TLS/OIDC bypass granting operator
authority. A same-user attack requiring already-equivalent full account access is normally lower or
out of scope, but an ordinary untrusted source or limited agent principal reaching these outcomes is
high.

### Medium

Bounded denial of service from pathological parsing/retrieval, readiness lockout recoverable from an
intact verified backup, candidate/timing leakage revealing limited metadata without content, cache
poisoning contained to one tenant and detected before effects, telemetry cardinality/resource abuse,
or deterministic/compiler drift that invalidates reproducibility without bypassing policy. Severity
rises if it is remote, persistent, cross-tenant or able to suppress required security evidence.

### Low

Content-free diagnostic inaccuracies, low-rate local resource inefficiency, non-sensitive version or
capability disclosure, documentation/UX mistakes that do not weaken enforced controls, or failures
requiring the same-user attacker already to possess all affected data and authority. Developer/test-
only issues are low unless their output enters selected release artifacts or qualification evidence.

Repository: codex-security-target/v1:sha256:46e8a3affeaff95ece9b51ad8a54725e01cffd15e25c1992f4bf3889746a4b4e
Version: 1ceea65e84fa59b3a4bff5027a0cced325cd2310
