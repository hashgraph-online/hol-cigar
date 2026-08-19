# Demo walkthroughs

Honey v0.9.3 packages four installed-artifact stories: offline deterministic context compilation with
prompt-injection/secret-canary defense, two-agent handoff, effect recovery with observational replay,
and Claude/MCP lifecycle. Its runner verifies independently supplied artifact digests, uses the
installed runtime and SDK/plugin bytes, runs each component twice from clean state under no-egress
enforcement, and rejects differing semantic identities. The Honey suite remains a developer-preview
qualification; it is not longevity, scale, or production availability evidence.

Release qualification runs each recorded scenario from exact candidate bytes in an isolated home.
The runner verifies the fixed fixture, seed, driver and canary bindings, runs mapped product checks,
scans outputs and state, performs teardown, and emits stable content-free JSON. A scenario passes
release qualification only when every declared assertion is observed through a public product
surface and the runner records an enforced OS no-egress boundary. A successful fixture driver alone
is not a release pass.

## Generated v4-to-v5 storage migration

The source POC at `demos/storage-migration/README.md` runs the real generated v4-to-v5 workflow
twice with no protected input: 1,028 revisions, a separate signed backup, a distinct target,
activation, bounded restart readiness, compaction, and deep verification. It is intentionally
reported as source-product evidence, not installed-candidate evidence.

## Offline context compiler

The [digest-bound manifest](../../demos/quickstart/demo.json) creates a 120-file repository, compiles
twice under a fixed seed, mutates one file, and checks deterministic bundle identity, strong index
watermarks, complete selected provenance, exact delta round trip, omission of superseded decisions,
and at least 40% physical-input reduction. The recorded driver registers the source locally and sends
the fixture through public ingest, plan, compile, materialize, delta, and explain CLI operations.
The same installed story also runs the prompt-injection defense component below, so its canary gate
is part of the four-story Honey projection rather than an unselected source-only scenario.

## Multi-project isolation

The [digest-bound manifest](../../demos/multiproject-payments/demo.json) attaches, links, switches and
resumes across four projects. Expected outcomes are content-free denial of unattached and forbidden
projects, removal of old-focus detail, resume at the current revision, and no change to filesystem
authority. Public focus-creation operations expose the exact candidate set, visible-project scope,
removed context detail, and revision-bound recompilation evidence.

## Scoped agent handoff

The [digest-bound manifest](../../demos/agent-handoff/demo.json) creates deterministic parent and
child agents. It requires grant attenuation, a handoff package no larger than 20% of parent context,
a useful first action, typed child evidence, content-free denial, and exact optimistic merge
behavior. The recorded workflow uses public handoff CLI operations plus the public Python SDK's
typed result operation, then performs both revision-bound merges. Installed-package qualification
remains a separate receipt.

## Durable effect recovery

The [digest-bound manifest](../../demos/effect-recovery/demo.json) uses a deterministic loopback issue
service and crashes at the remote-commit/local-receipt boundary. Passing evidence proves durable
intent before send, transition to unknown, journal recovery after restart, one mutation under the
idempotency key, rejection of unsafe retry, and compensation as a linked child effect. Six public
effect operations drive the state transitions while the loopback issue service proves the remote
mutation and reconciliation evidence.

## Cross-runtime replay

The [digest-bound manifest](../../demos/replay-comparison/demo.json) reproduces one retained decision
through Rust, TypeScript, Python and Go identities with network denied. It requires identical
semantic bundle identity, explicit target differences, exact evidence reproduction, no egress in
observational replay, and separation of live comparison. The recorded workflow creates separate
evidence, observational, and live-comparison jobs through the public CLI; the mapped cross-SDK check
executes the same retained vector in all four source runtimes. Installed SDK packages remain a
separate qualification scope.

## Prompt-injection defense

The [digest-bound manifest](../../demos/prompt-injection-defense/demo.json) ingests hostile documents
and canaries as untrusted data. It requires that payload text cannot grant tool authority, canaries
never appear, approved instructions remain exact and mandatory, and explanation disclosure stays
governed. The driver embeds the canary in hostile source bytes, then uses public ingest, plan,
compile, explain, and materialize operations to prove that only approved instructions and
digest-only hostile evidence become observable.

## Claude Code experience

The [digest-bound manifest](../../demos/claude-code/demo.json) exercises the packaged hook, MCP server
and plugin against a deterministic fake backend. It checks a bootstrap at most 500 tokens, bounded MCP
output, duplicate-event idempotence, exact checkpoint/resume, visible degradation, inspectable
manifests, and byte-preserving uninstall. Its optional paid smoke is separate, spend-capped, tool-free
and never records model or credential content.

Generated terminal transcripts and stable JSON belong in digest-bound release evidence, not in this
source page, so they cannot become stale or expose a developer path. The mandatory `demo` receipt
must report zero failed scenarios and attach the raw redacted records for all seven manifests.
