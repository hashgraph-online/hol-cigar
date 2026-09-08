# Python and TypeScript 0.10.0 RC1

## Scope and gates

Prepare `hol-cigar==0.10.0rc1` and `@hol-org/cigar@0.10.0-rc.1` locally; do not
publish, move registry tags, or promote the frozen Honey 0.9.4 daemon contracts.
Keep the 45 existing operations, Context ABI, bundle verification, and workflow APIs.

1. Add a bounded, versioned, persistent stdio worker around the *same* Rust
   `cigar-context` implementation. No network, automatic ingestion, shell, or downloads.
   Preserve incremental indexing, exact cached BPE, atomic source replacement,
   authorization filtering, citations, verified snapshots, and exact-base deltas.
2. Add typed Python and asynchronous TypeScript local graph facades with explicit
   lifecycle, bounded frames/deadlines/queues, content-free errors, worker handshake,
   and fail-closed transport errors (never silently restart a graph or retry a mutation).
3. Stage installable archives with a bundled host worker, checksummed inventory,
   licenses, release metadata, source distribution, and repeatable build instructions.
   Platform wheels must not pretend to be OS-independent. Unsupported native platforms
   may use an explicitly supplied locally built worker; no cross-platform qualification
   is implied by successful SDK imports.
4. Run Rust core/worker tests; the old and new SDK tests; strict type checks;
   shared cross-language oracle comparisons; clean wheel/sdist/npm installs; timeout,
   malformed input, authorization, atomicity, cache and delta tests. Retain exact
   artifact hashes and logs. Distinguish local qualification from publication approval.

## Architecture and tradeoffs

Each graph owns one child process and one privacy-domain-local token cache. JSONL
commands carry caller-supplied data only; graph operations execute serially. The
bridge avoids separate retrieval algorithms, Python extension ABI coupling, and
Node native-addon ABI coupling. It adds subprocess startup, IPC copies, and process
memory versus embedding Rust directly; warm calls amortize tokenizer/index startup.
RC1 is not an in-process binding, browser package, hosted service, or Honey daemon.

The worker rejects unknown fields and over-limit frames, returns stable error codes
without echoing source data, and verifies snapshots in Rust before rendering/reuse.
SHA commitments detect changes; they do not authenticate authors or grant access.
Applications must authorize inputs and place rendered context in a data role.

Initial bundled artifact qualification is macOS ARM64 on this host. Linux/Windows
and minimum-runtime release qualification remain explicit gates, not inferred passes.
