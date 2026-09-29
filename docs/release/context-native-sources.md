# Packaged native source builds

The native worker uses `cigar-context` and, on Windows, the private-file and
directory adapter in `cigar-windows-ipc`. A source build must include both crates.
The context SDK and the existing Honey workspace have separate release versions;
the adapter keeps its workspace version. Do not change that version to match an
SDK release without reviewing the other workspace consumers.

The native builder packages both crates in one Cargo invocation, copies the two
archives, and builds from their extracted contents. It does not compile either
crate from the checkout. The release inventory contains two Rust source archives,
one npm archive, one Python sdist and seven native Python wheels.

Cargo rewrites path dependencies to registry dependencies in a packaged manifest.
The release helper therefore adds an explicit Cargo patch pointing at the
verified sibling adapter archive. Before changing the extracted lockfile, it
checks that the adapter's archive SHA-256 equals the checksum Cargo committed to
in the context archive's lockfile. It removes only the adapter's registry source
and checksum fields. Every dependency version and edge, including all other
registry checksums, must remain identical. Compilation, native tests and metadata
resolution still require `--locked`.

The generated configuration also carries the reviewed workspace release profile
(`codegen-units = 1`, thin LTO, abort on panic and symbol stripping). Cargo package
normalization omits the workspace manifest, so those settings otherwise disappear
from the standalone build. The helper rejects profile drift, and the receipt
binds the effective profile. This preserves the repository's declared worker
build policy; performance and two-builder reproducibility must still be measured.
See the [Cargo profile rules](https://doc.rust-lang.org/cargo/reference/profiles.html).

`source-closure.json` records the archive hashes and the original/effective lock
and Cargo configuration hashes. The worker manifest binds both archives. The
distribution verifier independently reconstructs this receipt, verifies it inside
every wheel/npm native directory, and requires both independent builds to agree.
Both crate directories participate in the checkout source binding. Changing the
adapter after build admission invalidates the build.

To prepare extracted source for inspection or a local rebuild, use the helper
from the matching source revision with the two release archives:

```sh
python scripts/release/context_native_sources.py \
  --sources /absolute/path/to/release-archives \
  --output /absolute/path/to/new-extracted-directory
```

The output directory must not already exist. Build from its context crate
directory with the pinned Rust toolchain and `--locked --release --features
bpe,broker-persistence --bins`. The native builder additionally applies platform
flags, runs core and adapter tests, checks binary format/deployment floors and
records dependency notices. Preparing source alone does not qualify a release.

This procedure does not publish the adapter to crates.io. Users of the shipped
npm and Python native wheels need neither Rust nor any service. The older macOS
SDK compatibility handoff retains its historical artifact layout; the complete
distribution pipeline is authoritative for released native source and binaries.
