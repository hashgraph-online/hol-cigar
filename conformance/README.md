# CIGAR conformance kit

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
