# Extension host records v1

The extension boundary is capability-limited and fail closed. `ExtensionManifestV1` binds one
normalized extension and publisher identity, integer semantic version, runtime, supported ABI and
CIGAR ranges, exact implementation and package digests, publisher public key and signature,
package-relative entry point, all implemented kinds, one input/output schema pair per kind,
classifications, processors, determinism, requested host capabilities, network endpoints,
filesystem preopens, and resource ceilings. The signature is structurally required here;
canonical signature framing, publisher trust, revocation, package verification, and activation are
host responsibilities.

The twelve closed kinds are SourceConnector, Atomizer, Retriever, RankingFeature, Transform,
SummaryVerifier, Tokenizer, Materializer, PolicyProvider, StorageBackend, EffectConnector, and
Reconciler. Third-party runtimes are WASI Preview 2, isolated subprocess, and shared-profile remote
gRPC. Built-in is a distinct trusted runtime. Unknown kinds, runtimes, capabilities, and message
fields fail decoding.

`SandboxPath` is bounded ASCII, relative, slash-separated, and rejects empty, dot, parent,
backslash, absolute, and ambiguous segments. A `NetworkEndpoint` is structured as an authenticated
transport, canonical lowercase DNS name or canonical textual IP address, and nonzero port; it is
not a URI and permits no wildcard. Endpoint and preopen lists are sorted and unique. Declaring
either authority requires its matching broker capability, and remote extensions cannot receive
filesystem preopens. These records describe a maximum request only; current host configuration and
policy may further reduce or reject it.

`ExtensionInvocationV1` carries exact protected input bytes and digest, schema and manifest
bindings, sorted invocation-scoped opaque handles and effective capabilities, deterministic clock
and random inputs when authorized, effective limits, and an exclusive deadline. Handles are exact
256-bit opaque values and formatting never exposes them. `ExtensionResponseV1` carries protected
output only on success and binds both its schema and content digest. Failure outcomes contain no
free-form guest error text.

`ExtensionHostCallV1` records one ordered completed broker call. Every closed call kind maps to one
exact capability, and only handle-requiring operations may carry a handle. Request and response
bytes are bounded and protected in debug output. `ExtensionCancelV1` contains only a closed reason.
`ExtensionObservationV1` binds the invocation, extension, manifest, package, implementation,
input, exact effective limits, ordered host-call transcript, outcome, and successful output
digests. Nondeterministic extension observations are retained as explicit replay dependencies.
The transcript digest is the raw SHA-256 multihash of the strict deterministic-CBOR array of exact
ordered `ExtensionHostCallV1` records. A complete response digest uses the same construction over
the exact `ExtensionResponseV1` map. The host's observed invocation outcome carries the protected
invocation, response, transcript, observation, and response digest together; it exists only after
all records and cross-record bindings validate. The response-only compatibility API rejects a
nondeterministic manifest before execution so its mandatory replay dependency cannot be dropped.

Every byte, duration, memory, fuel, recursion, call, and concurrency field has a named hard upper
bound in `cigar_protocol::limits`. All configured limits are nonzero. Collections that represent
sets are sorted and unique, version ranges are inclusive and ordered, terminal timestamps cannot
regress, and unsupported schema majors fail closed.

## Canonical signing and activation

The exact Ed25519 message is `CIGAR-EXTENSION-MANIFEST || 0x00 || "v1" || 0x00 || cbor`, where
`cbor` is deterministic CBOR for semantic envelope `[7, fields]` and `fields` contains every
serialized manifest field except `signature`. The manifest digest uses the same envelope and
`CIGAR-EXTENSION-MANIFEST` digest domain. Activation verifies an operator-trusted publisher key
for `publisher_key_id` (never the manifest's self-asserted key alone), signature, exact raw package
and implementation digests, ABI and CIGAR ranges, every schema pair, runtime/capability/endpoint/
preopen policy, compute type, and every resource ceiling before compiling or launching code.

## Runtime wire boundary

Isolated subprocess and remote messages use a four-byte network-order length followed by one
deterministic-CBOR value. Non-shortest CBOR, duplicate or misordered map keys, indefinite values,
floats, tags, excessive depth, oversized lengths, and trailing bytes fail closed. The first frame
is `ExtensionInvocationV1`. A guest may then emit bounded host-call requests containing the exact
invocation ID, contiguous one-based ordinal, closed call kind, optional opaque handle, and request
bytes. The host replies with the same invocation/ordinal, a closed numeric failure code, and
bounded response bytes. Per-frame and cumulative invocation limits apply. The final frame is
`ExtensionResponseV1`; a native process must then close output and exit successfully. A response
followed by a crash is untrusted.

The Preview 2 component backend uses Wasmtime 44's Component Model with the versioned scalar CIGAR
world in `cigar-extension-world-v1.wit`. In this contract, “WASI Preview 2 component” identifies the
Preview 2 Component Model binary/ABI generation; it does not mean the general-purpose
`wasi:cli/command` world. Linking that command world would grant or emulate interfaces that the
no-ambient-authority rule below deliberately withholds.

The component reads the same framed invocation byte-by-byte, writes one framed response
byte-by-byte, and reaches broker calls through host imports backed by scratch/response byte views.
`invoke` returns the exact number of response-frame bytes written. Append operations must use the
next contiguous index. A byte read, append, handle index, host-call kind, or response length that
cannot be honored returns `u32::MAX`; any denied host call makes the entire invocation fail closed.
The `host-call` kind values are the frozen `ExtensionHostCallKind` discriminants, and its handle
operand is an index into the invocation's authenticated opaque-handle vector, never a raw handle.

No `wasi:*` imports are linked: environment, preopens, sockets, clocks, random sources,
credentials, and process creation are absent. A component requesting a standard WASI interface or
any import outside the CIGAR world cannot instantiate. Clock, random, filesystem, network, and
secret operations remain explicit broker calls and require both manifest declaration and
invocation authorization. Store limits bound memory, tables, memories, and instances; fuel, epoch
interruption, stack sizing, deadline, cancellation, output, concurrency, host-call, and cumulative
byte limits are enforced.

Native macOS execution requires `sandbox-exec` with deny-default, exact executable/package reads,
and no network rule. Linux execution requires rootless bubblewrap with user, mount, PID, network,
IPC, and UTS namespaces; only signed package/system-runtime read mounts and `/dev/null` are exposed.
If the qualified sandbox is unavailable, activation fails closed. Logical filesystem preopens and
network endpoints remain broker calls and are never ambient mounts or sockets.

Remote bridges must authenticate a peer credential digest and rebind extension, manifest,
implementation, package, and ABI identity before every exchange. They run the same repeated
invocation/host-call-reply/final-response loop and the same per-message and cumulative limits.
