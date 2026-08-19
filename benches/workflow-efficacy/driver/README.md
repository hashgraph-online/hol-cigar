# Independent Hiero workflow driver

The qualifying Rust driver is deliberately owned by the independent `hiero-pentest` checkout at
`benchmarks/cigar-version-comparison/main.rs`. The candidate repository must not supply executable
runner code to a historical treatment after that treatment has been built. The Hiero comparator
copies the independently reviewed driver into a new owner-only crate, generates a locked manifest
against exactly one treatment source root, builds release/offline, and binds the resulting binary,
driver, manifest, lockfile, fixture, harness, host, toolchain, configuration, and source-set digests.

The driver calls only public `cigar-policy`, `cigar-retrieval`, `cigar-compiler`, `cigar-protocol`,
and `cigar-store` APIs. It performs actual bounded retrieval, deterministic compilation, exact
materialization, two sealed-delta applications, root verification, and fail-closed substitutions.
The independent Python harness alternates the public embedded and local-sidecar process boundaries
and launches every measured execution under OS-level network denial.

Keeping this directory as a non-executable ownership marker is intentional: duplicating the driver
inside the candidate source would weaken independence and create two mutable runner authorities.
