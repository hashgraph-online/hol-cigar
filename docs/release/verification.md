# Release verification

Offline verification starts from a distribution directory, a trusted public-root policy and adjacent
public keys obtained by an independent channel, and no network access. It checks key purpose, signer
scope, activation/retirement/revocation and expiry as well as allowlisted archive contents, checksums,
version/ABI agreement, SBOM bindings, provenance subjects and materials, signature envelopes, source
revision, thresholds, evidence categories, and every required artifact in the matrix. Each artifact
must also carry a digest-bound final-byte security receipt covering packed and unpacked vulnerability,
malware-indicator, secret, and unexpected-endpoint scans; an OCI artifact additionally requires its
image-layer scan.

The built-in OCI contract first performs bounded structural checks without installing the image: it
requires exactly `linux/amd64` and `linux/arm64`, descriptor-to-blob digest and size agreement,
matching config diff IDs, safe regular layer entries with allowlisted modes and ownership, basic
secret/path scanning of decompressed layer content, an explicit non-root user and group, and exact
version and Context ABI annotations. This does not replace the approved vulnerability, malware, and
unexpected-endpoint scanners required for final-byte security evidence.

The signed release manifest also digest-binds the exact build manifest. Artifact basenames must
match the matrix, the checksum file may contain exactly the artifact paths and no extras, both SBOM
formats carry the same canonical artifact binding, and every regular file in the distribution must
be an artifact, referenced evidence/attachment, required supply-chain document, or expected signature
envelope. An unreferenced file is a verification failure.

Every qualification receipt identifies the producing tool and version, records its tool digest and
redacted argument vector, and binds at least one nonempty raw report attachment by relative path, media type,
byte length, and SHA-256. The verifier resolves every attachment beneath the distribution directory;
a pass flag or metric without its raw report cannot satisfy a release gate. Conformance and benchmark
receipts and all of their attachments are signed directly in addition to the signed release manifest.

<!-- docs-check: command release-metadata-local -->
```sh
python3 scripts/release/validate_metadata.py
```

<!-- docs-check: command release-verify -->
```sh
cigar release verify dist/
```

The repository also builds a minimal synthetic signed release solely to test the evidence assembler
and offline verifier's success path, then substitutes a wrong build-manifest contract and mutates its
artifact and raw evidence to prove fail-closed behavior. This fixture is not product qualification
evidence.

<!-- docs-check: command release-verifier-selftest -->
```sh
python3 scripts/release/selftest_release_verifier.py
```

The command must fail after deleting or changing any required byte, after swapping an artifact under
another name, for an untrusted signing key, for stale/wrong-source evidence, for skipped or waived
checks, or below a required threshold. Successful verification authorizes promotion of those exact
bytes only; rebuilding after verification creates a different candidate.

Machine gates cover test/traceability/work-packet completeness, toolchain drift, coverage, mutation,
seven-day-equivalent fuzz, sanitizers, model checks, chaos/effect faults, migration, 10-million-atom
scale, 24-hour soak, conformance, every published performance and outcome threshold, package/install/
uninstall/offline/upgrade failures, license/SBOM review, signatures, provenance, reproducibility,
documentation, demos, operations, and final security scan coverage. A signed prose summary without
the required finite metric and raw attachment does not satisfy a gate.

The low-level verifier is invoked with `--trust-policy /independent/root/release-trust-policy.json`.
The production `cigar release verify` command supplies the same policy through its configured trusted
root bundle and never accepts an unscoped public key by itself.

See [reproducibility and signing](reproducibility-signing.md) and the recorded
[qualification gaps](qualification-gaps.md).
