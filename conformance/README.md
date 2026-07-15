# CIGAR conformance kit

## macOS development package

The selected Apple-silicon development projection has a deterministic
`cigar-conformance-1.0.0-dev.1-aarch64-apple-darwin.tar.gz` producer. Its exact contract permits
only the thin-arm64 `bin/cigar-conformance` runner, the thin-arm64
`bin/cigar-install-qualifier` installed-runtime driver, the two checked-in profile documents, the
PRD and invariant manifest, the checked conformance result used by source traceability, the two v1
vector files, the eight expected-summary files, release metadata, checksums, and license text.
The installed vector root is `share/cigar/conformance/vectors/v1`; callers must pass it explicitly
with `--vectors`.

The producer performs only invocation probes for both binaries. Its receipt is intentionally
`built-unqualified`: it is not candidate evidence, does not run target conformance, and does not
claim installation, signing, notarization, publication, support, or release qualification. See
`scripts/release/README.md` for the protected development build command and the external gates.

`cigar-install-qualifier` is not a synthetic smoke script. The external install qualifier runs it
inside a private macOS Seatbelt no-egress workspace against the exact installed `cigar` and
`cigard` bytes. A passing artifact-bound receipt requires governed source discovery, idempotent
ingestion, query/plan/compile/explain across process restarts, doctor, signed backup/verify/restore,
two real daemon start/status/graceful-stop cycles, local replay/effect-recovery/handoff request
contracts, and an installed-daemon migration of a retained SQLite v1 state root through the exact
v3 ledger. Timeouts, output floods, and descendant processes fail closed and settle the complete
candidate process group.

`cigar-conformance` is a standalone, fail-closed runner for the immutable v1
vector sets. It invokes an executable or SDK adapter through a one-request,
one-response JSON protocol, or invokes the same protocol over HTTP, Unix HTTP,
or gRPC. Every run binds the implementation, runner, vector set, and result by
SHA-256 digest.

All eight frozen v1 profiles have checked-in required cases. Every profile has
at least one production-backed success case and one production-backed
fail-closed case. The reference adapter calls the public production crates for
catalog identity/invalidation, deterministic compilation, signed handoff
attenuation, durable fenced effect dispatch, recorded-provider replay, authenticated
service cursors, and the Claude Code MCP runtime. Expected public digests are
stored only in the immutable vector archive; requests never reveal them to an
adapter.

```sh
cargo xtask conformance build
cargo run -p cigar-conformance -- run \
  --profile cigar-core-v1 \
  --profile cigar-catalog-v1 \
  --profile cigar-compiler-v1 \
  --profile cigar-handoff-v1 \
  --profile cigar-effect-v1 \
  --profile cigar-replay-v1 \
  --profile cigar-service-v1 \
  --profile cigar-runtime-claude-code-v1 \
  --executable target/debug/cigar-conformance-reference \
  --implementation cigar-reference-rust \
  --vectors conformance/vectors/v1 \
  --output reports/conformance-result.v1.json
cargo run -p cigar-conformance -- verify \
  reports/conformance-result.v1.json \
  --vectors conformance/vectors/v1
```

Executable and SDK adapters read one `cigar.conformance.request.v1` JSON object
from stdin and write exactly one `cigar.conformance.response.v1` JSON object to
stdout. The runner clears inherited environment state, creates a fresh temporary
home and work directory for every case, applies process resource limits, bounds
input/output, and enforces a wall timeout. Strict isolation is the default. It
uses Seatbelt on macOS and bubblewrap on Linux to deny network and writes outside
the case directory. A platform without a supported OS sandbox fails strict runs;
`--isolation portable` exists only for development diagnostics and is recorded
as non-release isolation in the result.

HTTP endpoints expose `POST /v1/conformance/run`; Unix endpoints use the same
HTTP exchange over a Unix socket. The gRPC method is
`/cigar.conformance.v1.ConformanceAdapter/RunCase` with a bytes field containing
the JSON request and response. Remote endpoints are explicitly selected by the
operator and bounded for time and output, but their server process cannot be
CPU, memory, filesystem, or network sandboxed by this client. Such results are
recorded with `remote_bounded` isolation and do not satisfy a strict local-run
qualification claim.

`cargo xtask test conformance` builds the adapters, runs the complete scoped
test suite, executes all 24 required cases under strict local isolation,
verifies the result digest against the vector tree, and validates normative
traceability. Required cases cannot be skipped. Intentionally faulty adapters
are exercised against every claimed profile.

`conformance/profiles/faults-v1.json` is the frozen injected-fault authority. It binds the exact
fault-adapter source digest, all eight reviewed adapter modes, their complete profile scopes, the
single intended invariant and requirement for each of 22 mode/profile injections, the exact proof
test, and the expected case-level diagnostic or blocked adversarial probe. The traceability
validator rejects missing, duplicate, invented, or misdirected entries, source drift, unrelated
proof tests, weakened diagnostics, and incomplete all-profile coverage. The behavioral tests
assert every affected case and exact diagnostic; an aggregate failed run is not accepted as fault
detection evidence. The `escape` and `stateful` probes pass only when strict isolation blocks both
external side effects and when every case receives a fresh namespace, respectively.

## Normative traceability

`conformance/profiles/requirements-v1.json` is a checked baseline, not a manually selected list of
claims. The v2 registry records a stable ID, exact line span, enclosing section, normalized source
text, SHA-256 text digest, classification, criticality, and uppercase MUST/SHALL occurrence count
for every source span extracted from `prd.md`. The frozen extraction contract covers normative
MUST/SHALL statements, `Gate:` and work-packet `Exit` lines, beta/final checklists, the critical
invariant table, and the hard-gate, required-policy, and stop-ship sections. It currently accounts
for 142 source spans plus 35 independent derived conformance requirements.

The validator re-extracts the PRD on every invocation and compares the complete ordered surface,
including line locations. Deleting, adding, moving, reclassifying, or editing a requirement fails;
editing the checked text or either digest fails independently. `tests/invariants.yaml` maps the
source classes and all derived IDs to exact active functions/commands and binds every mapping to a
current-run JSON output. Critical invariants always require positive, negative, and property/model
evidence; process-boundary, cross-runtime, and installed-byte applicability is explicit and must
have a bounded rationale. Applicable classes without a mapping, and mappings declared inapplicable,
both fail closed.

This is traceability structure, not a release waiver. The current native macOS development scope
has no candidate-bound installed-byte traceability mapping, and the manifest says so explicitly.
That gap remains release-blocking until the exact distributed archive is exercised by
`scripts/release/qualify_install.py` and its fresh signed evidence is assembled by the release
verifier. Fuzz and soak are intentionally outside the current run and are not reported as passing.
