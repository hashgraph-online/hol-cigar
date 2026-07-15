# cigar-extension-host

Stability: application, pre-v1. Owns signed extension loading, isolation, capabilities, resource
limits, and host calls. The first qualified native target is macOS arm64; Linux launcher code is
retained for development but is not part of this release gate.

The host authenticates signature-excluded canonical manifests before execution, exposes only
invocation-scoped opaque broker handles, and supports a no-ambient-authority Wasmtime component
world, sandboxed one-shot native processes, and authenticated remote logical-ABI bridges. Runtime
messages are length-delimited deterministic CBOR. Trusted callers supply the wall/monotonic clock
pair; the host never commits application state on behalf of guest code.

Every `InvocationRequest` launches a third-party runtime exactly once. The v1 manifest does not
carry an operation-level read-only proof, so the host intentionally offers no caller-controlled
automatic retry. Durable operation recovery belongs above this boundary and must create a fresh
invocation and a fresh capability broker after applying the operation's own idempotency contract.
Capability brokers are atomically claimed when attached to a request and cannot be attached to a
second attempt, preventing reuse of handles, partial transcripts, deterministic-random counters,
or cancellation state after a crash. Claiming also binds the broker to the request's exact
`InvocationCancellation` and absolute monotonic deadline. Every broker call checks that context
before admission. Operator `NetworkBoundary` and `FinalSecretBoundary` implementations receive a
cloneable `BrokerCallContext`; they must poll `check()` around blocking I/O. Responses returned
after cancellation or deadline expiry are rejected even if an adapter fails to check.

Filesystem preopens are capabilities over open directory descriptors, not remembered pathnames.
Every path segment is opened relative to that descriptor without following symlinks, the final
object must be a single-link regular file, and reads consume at most the signed output limit plus
one sentinel byte. Renaming or replacing the operator path after grant does not retarget an
existing handle. Writes operate on the already-opened descriptor and never create a new file.

`DeterministicVectorRunner` checks a published semantic input/output vector over a bounded,
seed-permuted set of fresh host threads. Each request factory invocation must create a fresh broker;
subprocess backends therefore launch a fresh process for every vector sample. CI repeats the same
vectors across the Tier-1 target and locale/timezone matrix. Native guests themselves always see
`C`/`UTC`, while Component Model guests receive no ambient locale, timezone, or clock interface.

The Wasmtime backend accepts Preview 2 Component Model binaries implementing CIGAR's versioned
scalar extension world; it is intentionally not a general-purpose `wasi:cli/command` host. No
`wasi:*` interface is linked. Clock, random, filesystem, network, and secret access are available
only through manifest- and invocation-authorized broker calls.

Native subprocess activation copies the exact implementation bytes that matched the signed digest
into a private host-owned executable snapshot. Every invocation launches that snapshot in a fresh
process, so replacing the package entry point after activation cannot change executed code. The
snapshot is executable/readable only by its owner and remains alive exactly as long as the sandbox
configuration. Native entry points must therefore be self-contained executables; arbitrary package
resources are not ambiently mounted into the sandbox.

The remote backend is a logical ABI bridge, not a bearer of ambient trust. Its adapter must provide
an authenticated peer digest (for example, a digest bound to an mTLS/SPIFFE identity and trust
bundle). The host checks extension ID, manifest digest, implementation digest, package digest, ABI
range, and peer digest at construction and again before every bounded canonical exchange.

On the initial macOS arm64 target, native guests execute through `/usr/bin/sandbox-exec` under a
deny-default profile. The launcher clears the environment, fixes locale/timezone to `C`/`UTC`,
applies a CPU rlimit before execution, and terminates a guest whose sampled resident memory exceeds
its signed limit. The profile permits only the verified snapshot and required system dynamic
libraries, denies sockets and arbitrary filesystem access, and does not permit guest process
creation. The hostile-runtime gate compiles and runs a real probe that attempts host file reads,
trusted-state writes, loopback networking, environment inheritance, and `fork()`. Crash,
infinite-loop, output-flood, forged-handle, post-cancel call, deadline, package-substitution,
resident-memory exhaustion, and fresh-process restart cases are separate deterministic package
tests. Fuzz and soak suites are not part of this macOS qualification run.
