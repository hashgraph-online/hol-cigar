# Dashboard non-soak macOS closure evidence — 2026-07-14

Scope: native Apple-silicon macOS development-source verification for the optional
`cigar-dashboard` sidecar. Fuzzing, soak execution, the soak driver, non-macOS support,
destructive full-volume testing, and escaped-descendant/kernel-hard containment qualification were
explicitly excluded.

This is not candidate-bound or release-qualifying evidence. The tests ran at Git HEAD
`56a5a1346bdfd362f67c279f4f8cd5d4ba7c46b2` in a shared worktree with 609 porcelain status entries;
they therefore make no clean-tree, source-archive, installed-package, signing, notarization,
provenance, or reproducibility claim.

Environment:

- macOS 15.6, `arm64`
- `rustc 1.92.0 (ded5c06cf 2025-12-08)`
- `cargo 1.92.0 (344c4567c 2025-10-21)`
- Python 3.9.6

Verified commands and results:

```text
cargo test --locked --offline -q -p cigar-dashboard --all-targets -- --test-threads=1
86 library tests passed; 4 resource-launcher integration tests passed; exit 0

cargo clippy --locked --offline -p cigar-dashboard --all-targets --all-features -- -D warnings
exit 0

RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline -p cigar-dashboard --no-deps
exit 0

cargo fmt --package cigar-dashboard -- --check
exit 0

/usr/bin/python3 -B tests/dashboard/validate_schemas.py
18 dashboard schemas and 84 local references validated; exit 0
```

The Rust cohort includes these focused native behaviors:

- a real supervisor test process exits with status 73 without running destructors while its child
  process remains alive; a new controller refuses recovery without signalling the child, then marks
  the run `lost` only after the recorded process identity is absent;
- actual CPU-time termination, file-size partial-write enforcement, open-file exhaustion, aggregate
  resident-memory enforcement, and aggregate process-count enforcement;
- durable event-byte retention, terminal age/count retention, and preservation of evidence-linked
  terminal rows across database reopen;
- exact supervisor-receipt bindings for the dashboard executable, profile, selected child
  executable, argv, registry, execution inputs, clean-source descriptor, tool version, timing,
  output, and outcome;
- fail-closed local installed-artifact byte binding for a thin arm64 Mach-O dashboard executable,
  archive, asset manifest, package contract, and exact source identity. This verifier emits only a
  `partial` installed-artifact descriptor and rejects source drift, mutation, links, and non-native
  binaries. The accepted contract bytes are compiled from the reviewed development-only contract,
  so a matching forged receipt cannot substitute a weaker contract; the verifier does not verify a
  signature or claim that an installed smoke ran;
- a source invariant excluding dashboard/soak bytes from Cargo default members, the ordinary macOS
  runtime archive contract, the daemon Dockerfile, base Compose YAML, and shared Kubernetes YAML.

Implemented package-definition source:

- `packaging/development/contracts/macos-dashboard-archive.v1.json` defines a separate development-
  only optional archive contract with an exact required inventory and denies soak, source maps,
  credentials, state, runtime, evidence, sandbox, and build-tree content. Keeping it outside
  `packaging/contracts` prevents an unproduced artifact from entering the release-contract
  inventory.
- `schemas/dashboard/dashboard-installed-artifact-v1.schema.json` defines the corresponding local
  unqualified byte-binding receipt. Its closed fields explicitly state `signature_status` as
  `not-verified`, `smoke_status` as `not-run`, and `status` as `installed-unqualified`.

Still open after this cohort: a package producer; actual pack/unpack/install/upgrade/uninstall and
empty-directory smoke; SBOM/license/vulnerability/secret scans of the packed artifact; provenance,
reproducibility, signing, notarization, and artifact-matrix selection; live browser run/receipt
flows; dynamic daemon-before/after optionality comparison; structured progress; exhaustive
escaped-child handling; destructive disk exhaustion; kernel-hard aggregate memory/process
containment; every fuzz/soak gate; and all non-macOS work.
