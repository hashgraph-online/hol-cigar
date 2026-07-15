# Install and uninstall

Only artifact/platform combinations with installed-byte evidence in the
[artifact matrix](../../packaging/artifact-matrix.v1.json) are supported. Do not infer support from a
successful source build. Every download must be verified offline before extraction.

## Binary archives

The selected Apple-silicon full-product archive contains `cigar`, `cigard`, `cigar-mcp`,
`cigar-claude-hook`, completions, the man page, `LICENSE`, `NOTICE`, checksums, and release metadata.
The optional dashboard and internal conformance, benchmark, and soak tools are deliberately absent.
Installation must work as a non-admin user without a compiler and without network access. The
qualification harness rejects both effective root and membership in macOS's `admin` group through
the real, effective, or supplementary group sets. It creates a short private qualification root
under canonical, root-owned, sticky-mode `01777` `/private/tmp`, bounds every driver Unix-socket
path to 96 encoded bytes, and still installs under a nested prefix containing spaces and Unicode,
runs the closed CLI smoke and daemon lifecycle, checks read-only-parent behavior, and removes every
installed path it created. On the selected macOS cohort the Python harness wraps each direct
installed-runtime probe in the fixed root-controlled `/usr/bin/sandbox-exec` profile. It does not
wrap the verified Rust qualification driver: that driver owns the single Seatbelt boundary around
each runtime child it launches, avoiding nested or competing sandbox boundaries. The only network
exception is Unix-domain IPC beneath the private
qualification workspace, which is required for the owner-only daemon socket; IP, DNS, and
ambient Mach-service lookup remain denied. Candidate processes cannot signal unrelated processes,
fork descendants, or write the staged archive/tool and installed prefix; threads remain available.
Executable probes verify the session, descriptor, signal, preferences-daemon, networking, and
write-confinement properties covered by the fixed profiles. Seatbelt is not complete process
isolation: macOS does not mediate every same-user resource-control operation through these profile
predicates, so a hostile candidate can still affect another same-user process's scheduling
availability. Qualification therefore must run in a disposable, dedicated standard-user VM/account
with no valuable same-user processes, which is destroyed after the run. The receipt records
`darwin-seatbelt-deny-network-mach-confine-writes-protect-candidate-workspace-unix-v1`. The outer
isolated runner must still set
`CIGAR_NO_EGRESS_ENFORCED=1`; that variable is an attestation and is never treated as the network
control by itself. It also records the independent process control as
`darwin-seatbelt-deny-process-fork-signal-v1`.

The receipt's `no_compiler_path=true` field proves only that the sanitized child `PATH` contains no
compiler command. It is not evidence that the host lacks compiler tooling; a compiler-free VM is a
separate external installed-artifact prerequisite. The qualifier also cannot self-prove that its
host is disposable, so the outer environment evidence must bind that property independently.

Before extraction, the package verifier requires `SHA256SUMS` to list every regular payload file
other than itself and generated `RELEASE-METADATA.json`, exactly once and in UTF-8 byte order. A
missing, extra, reordered, or stale internal checksum is a contract failure; the outer release
checksum and signature still bind the archive as a whole.

<!-- docs-check: command install-archive -->
```sh
python3 scripts/release/qualify_install.py ${BINARY_ARCHIVE} \
  --contract packaging/contracts/macos-runtime-archive.v1.json \
  --runtime-build-receipt ${CIGAR_RUNTIME_BUILD_RECEIPT} \
  --qualification-tool-archive ${CIGAR_QUALIFICATION_TOOL_ARCHIVE} \
  --qualification-tool-contract packaging/contracts/macos-conformance-runner.v1.json \
  --qualification-tool-build-receipt ${CIGAR_QUALIFICATION_TOOL_BUILD_RECEIPT} \
  --expected-artifact-id cli-daemon-macos-aarch64 \
  --expected-target aarch64-apple-darwin
```

For a manual install, verify the release first, extract into a new empty directory, and place the four
binaries on `PATH`. Uninstall by removing that directory; retain project `.cigar` state only when an
upgrade or explicit data retention is intended. Never delete catalog, journal, or key material as an
uninstall side effect.

Pass the separately built macOS conformance-tool archive as
`CIGAR_QUALIFICATION_TOOL_ARCHIVE`; the harness contract-verifies that archive, requires the exact
same clean, committed source object (revision and tree digest) as the runtime candidate, and
extracts its fixed
`bin/cigar-install-qualifier` member. Callers cannot substitute a handwritten driver or synthetic
receipt script. The runtime and tool build receipts are securely staged and validated for their
exact schemas, target, version, Context ABI, source, archive digest and byte count, contract,
build-tool identities, and payload identities. Their shared product-version, artifact-matrix, and
local-macOS profile authority records must match byte-for-byte by digest and size. All four runtime
binaries plus the conformance runner and install driver must be thin arm64 Mach-O executables.
The final report digest-binds both build receipts and both qualification executables. These receipt
checks provide integrity and cross-binding only: they are explicitly not cryptographically
authenticated until external signing evidence is verified. The runtime build receipt fixes the
package profile to `cigar.full.local-macos-aarch64.v1`; the producer selects Cargo's `full` feature
explicitly with default features disabled. A narrow beta executable fails both the exact version
identity and the installed full-help surface probe. That probe requires byte-for-byte equality with
the checked-in authoritative full help asset, so an added command, removed command, changed option,
or narrow-beta help document fails before a workflow claim is emitted. The verified driver's strict
content-free receipt binds the artifact ID, archive digest, source revision, exact extracted
`cigar`/`cigard`
digests, full-surface digest, governed semantic-identity digest, and the
`cigar.full.offline-read-only.macos-aarch64.v1` workflow profile. The real workflow covers approved
source configuration and discovery, idempotent ingestion, query/retrieval, policy-denial
non-disclosure, dry-run and committed planning, compile/provenance, explain, revalidate,
materialize, exact-base delta, and persistence across independent CLI processes. A loopback HTTPS
probe verifies that the Seatbelt child cannot establish an IP connection, while remote-only local
administration surfaces fail with the exact content-safe unsupported-surface response. The driver
also covers doctor, local initialization/source state, replay/effect/handoff request contracts,
signed backup/verify/restore, two daemon lifecycle cycles, and retained SQLite v1-to-v4 migration
through the installed daemon. The harness also proves that
the staged archive, driver, installed binaries, and their executable identities did not change
during the exercise; output floods, timeouts, and descendant processes fail closed.

These contracts and tests are implementation evidence only until they run against one clean,
immutable, signed/notarized candidate in the dedicated non-admin VM described above. A source-built
or development archive result is not installed-candidate release evidence.

## Ecosystem packages and service image

The TypeScript package is installed from the exact npm tarball, Python from the exact wheel or sdist,
and Go from the signed module tag. Validators run with an empty cache and disabled egress. The shared
OCI index must resolve to non-root linux/amd64 and linux/arm64 manifests by digest. Package-manager,
registry, notarization, and installer claims are absent until their matrix evidence exists.
