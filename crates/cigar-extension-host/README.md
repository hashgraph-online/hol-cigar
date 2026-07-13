# cigar-extension-host

Stability: application, pre-v1. Owns signed extension loading, isolation, capabilities, resource limits, and host calls.

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
or cancellation state after a crash.

`DeterministicVectorRunner` checks a published semantic input/output vector over a bounded,
seed-permuted set of fresh host threads. Each request factory invocation must create a fresh broker;
subprocess backends therefore launch a fresh process for every vector sample. CI repeats the same
vectors across the Tier-1 target and locale/timezone matrix. Native guests themselves always see
`C`/`UTC`, while Component Model guests receive no ambient locale, timezone, or clock interface.

The Wasmtime backend accepts Preview 2 Component Model binaries implementing CIGAR's versioned
scalar extension world; it is intentionally not a general-purpose `wasi:cli/command` host. No
`wasi:*` interface is linked. Clock, random, filesystem, network, and secret access are available
only through manifest- and invocation-authorized broker calls.

On Linux, native guests require `bubblewrap` and `prlimit`. The launcher creates new user, PID,
network, IPC, and UTS namespaces; clears the environment; drops every capability; switches to the
unprivileged 65534 UID/GID; exposes only the verified executable, dynamic runtime libraries, and
`/dev/null`; and applies an in-sandbox hard `RLIMIT_NPROC` of one before executing the guest. A
Linux hostile-runtime test exercises the real launcher and skips explicitly only when bubblewrap is
absent or the required namespaces are unavailable. macOS uses the deny-by-default sandbox profile
and has its own hostile-runtime test. Remaining release-platform qualification belongs to the
Tier-1 CI matrix rather than to a weaker fallback launcher.
