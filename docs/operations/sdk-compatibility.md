# SDK and protocol compatibility

## Preconditions

Inventory the installed SDK artifact digest, semantic version, Context ABI constant, supported
protocol range, generated-manifest digest, runtime/toolchain version, target daemon version, and
server compatibility response. Test the packaged SDK in an empty consumer project; a workspace
import or source-path override is not qualification.

## Compatibility exercise

Run the language's generated protocol vectors, version negotiation, structured error registry,
pagination, stream resume, cancellation, bounded deadlines, retry classification, idempotency-key
preservation, handoff acceptance, effect reconciliation, and observational replay. Compare Rust,
TypeScript, Python, and Go semantic digests for the same canonical fixtures. Verify unknown enum and
schema values follow the documented closed/open behavior and never broaden authority.

Exercise the minimum supported runtime and each adjacent retained server version. A client may use
only the negotiated intersection; it must fail with the stable compatibility problem before sending
an unsupported mutation. Do not downgrade TLS, skip digest verification, parse message text, or retry
unknown effects to work around incompatibility.

## Stop conditions and evidence

Stop publication or rollout on version/ABI disagreement, generated-file drift, canonical digest
difference, unsupported operation exposure, stream semantic difference, or a retry-class mismatch.
Keep the previous compatible client/server pair available and correct the package or compatibility
declaration before retrying. Evidence binds each SDK and server artifact digest to runtime versions,
protocol/ABI ranges, conformance result digests, and the exact source revision.
