# Install and uninstall

Only artifact/platform combinations with installed-byte evidence in the
[artifact matrix](../../packaging/artifact-matrix.v1.json) are supported. Do not infer support from a
successful source build. Every download must be verified offline before extraction.

## Binary archives

The archive contains `cigar`, `cigard`, completions, the man page, `LICENSE`, `NOTICE`, checksums, and
release metadata. Installation must work as a non-admin user without a compiler and without network
access. The qualification harness installs under a temporary prefix containing spaces and Unicode,
runs the closed CLI smoke and daemon lifecycle, checks read-only-parent behavior, and removes every
installed path it created. Run candidate executables only inside a disposable, unprivileged
OS-enforced filesystem and network sandbox; setting `CIGAR_NO_EGRESS_ENFORCED=1` is a receipt from
that sandbox, not a network control by itself.

Before extraction, the package verifier requires `SHA256SUMS` to list every regular payload file
other than itself and generated `RELEASE-METADATA.json`, exactly once and in UTF-8 byte order. A
missing, extra, reordered, or stale internal checksum is a contract failure; the outer release
checksum and signature still bind the archive as a whole.

<!-- docs-check: command install-archive -->
```sh
python3 scripts/release/qualify_install.py dist/cigar-platform.tar.gz \
  --contract packaging/contracts/binary-archive.v1.json \
  --qualification-driver /isolated/installed-qualification-driver \
  --expected-artifact-id cli-daemon-linux-x86_64-gnu \
  --expected-target x86_64-unknown-linux-gnu
```

For a manual install, verify the release first, extract into a new empty directory, and place the two
binaries on `PATH`. Uninstall by removing that directory; retain project `.cigar` state only when an
upgrade or explicit data retention is intended. Never delete catalog, journal, or key material as an
uninstall side effect.

The self-contained qualification driver is copied and digest-bound before execution. Its strict
receipt binds the artifact ID, archive digest, semantic version, Context ABI, and each required
workflow check. The harness also proves that the staged archive, driver, and installed binaries did
not change during the exercise.

## Ecosystem packages and service image

The TypeScript package is installed from the exact npm tarball, Python from the exact wheel or sdist,
and Go from the signed module tag. Validators run with an empty cache and disabled egress. The shared
OCI index must resolve to non-root linux/amd64 and linux/arm64 manifests by digest. Package-manager,
registry, notarization, and installer claims are absent until their matrix evidence exists.
