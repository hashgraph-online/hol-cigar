# Release qualification tools

These scripts are deliberately network-free unless an environment-owned platform driver performs an
explicit external release operation. They accept paths and key files explicitly, reject duplicate
JSON keys and unsafe relative paths, and write canonical JSON.

Local source-derived qualification:

```text
SOURCE_DATE_EPOCH=1700000000 python3 scripts/release/validate_metadata.py
SOURCE_DATE_EPOCH=1700000000 python3 scripts/release/build_archives.py --out /tmp/cigar-dist
python3 scripts/release/verify_package.py /tmp/cigar-dist/cigar-0.1.0-source.tar.gz --contract packaging/contracts/source-archive.v1.json
SOURCE_DATE_EPOCH=1700000000 python3 scripts/release/check_reproducibility.py
python3 scripts/release/check_docs.py
python3 scripts/release/exercise_runbooks.py --mode static --out /tmp/cigar-runbooks
python3 scripts/release/selftest_release_verifier.py
```

Candidate flow:

1. Run `python3 scripts/release/validate_metadata.py --release`, then build every entry in
   `packaging/artifact-matrix.v1.json` on its isolated native builder.
2. Verify archive contracts and run clean installed-byte qualification with enforced no egress.
3. Generate SPDX/CycloneDX SBOMs and the third-party license inventory from final bytes.
4. Generate provenance with explicit source revision, source archive, workflow, builder, command, and
   network mode; every lock is added as a resolved dependency. `disabled` requires the isolated
   runner's `CIGAR_NO_EGRESS_ENFORCED=1` marker.
5. Sign checksums, every artifact, SBOMs, plugin manifest, conformance/benchmark results, and
   provenance using an existing approved Ed25519 private key. Supply signer, purpose, signing time,
   and optional expiry explicitly; never generate a production key here.
6. Assemble complete evidence, sign `release-evidence.json`, then run offline verification using
   a scoped `cigar.release-trust-policy.v1` bundle and public roots obtained independently.
7. Promote the exact verified bytes without rebuild.

`assemble_evidence.py` and `verify_release.py` reject uncommitted/dirty source, missing artifact IDs,
missing evidence categories, failed/skipped/waived checks, wrong source revisions, metric failures,
digest changes, missing or altered raw-report attachments, unsigned artifacts, untrusted keys,
incomplete SBOM bindings, and incomplete provenance subjects. Every receipt must name its producer
and bind at least one raw attachment. `--allow-development` exists only on the assembler so local contract plumbing
can be tested; offline release verification has no development bypass.

The release requirements and artifact-qualification map are canonical-SHA-256-pinned in the v1
assembler and verifier. This prevents a candidate directory from weakening metric thresholds,
required categories/signatures, universal operation/security coverage, or SDK version/ABI checks by
supplying an edited policy document.

Live runbooks require eight explicit self-contained executable drivers owned by the isolated
operations environment. They consume the exact `cigar.release-build.v1` manifest rather than the
later `release-evidence.json` that their receipts help assemble. Before driver execution the
orchestrator verifies the complete matrix artifact set and every filename, contract, size, and
SHA-256 binding. Each driver is staged and digest-bound, and every receipt also binds the unchanged
build manifest. Static runbook validation never claims live qualification. Likewise, local archive
reproducibility covers only source-derived archives; native binaries, installers, ecosystem
packages, and OCI layers still require the two-builder matrix.

The OCI contract validates the outer OCI 1.0 layout and bounded decompressed layer tar streams. It
checks both Linux architectures, descriptor and diff-ID bindings, non-root runtime identity, safe
paths/types/modes/ownership, line endings, and the built-in secret/developer-path patterns. Approved
final-image vulnerability, malware, and endpoint scans remain separate mandatory release evidence.
