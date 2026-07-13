# Rust SDK publication runbook

The complete Rust SDK dependency chain is locally package-qualified, but it is not yet cleared for
an external crates.io release. The local qualification packages all 19 crates in dependency order,
inspects their normalized manifests and archives, inserts each exact archive into an offline local
registry, and compiles a clean default-feature SDK consumer from that registry. It does not reserve
names, establish registry ownership, or produce crates.io publication receipts.

The current release gap remains stop-ship until the final candidate is committed and an approved
registry owner publishes and verifies the exact chain described below.

## Publication order

Publish one crate at a time and wait until crates.io resolves the exact version before continuing:

1. `cigar-aws-creds = 0.39.1-cigar.1`
2. `cigar-rust-s3 = 0.37.2-cigar.1`
3. `cigar-canon = 0.1.0`
4. `cigar-protocol = 0.1.0`
5. `cigar-testkit = 0.1.0`
6. `cigar-windows-ipc = 0.1.0`
7. `cigar-crypto = 0.1.0`
8. `cigar-replay = 0.1.0`
9. `cigar-policy = 0.1.0`
10. `cigar-store = 0.1.0`
11. `cigar-effects = 0.1.0`
12. `cigar-retrieval = 0.1.0`
13. `cigar-space = 0.1.0`
14. `cigar-catalog = 0.1.0`
15. `cigar-code-intel = 0.1.0`
16. `cigar-compiler = 0.1.0`
17. `cigar-api = 0.1.0`
18. `cigar-daemon = 0.1.0`
19. `cigar-sdk = 0.1.0`

`cigar-testkit` is a versioned development dependency used during package verification.
`cigar-windows-ipc` is a normal Windows-only daemon dependency, so a macOS-only check is not a
substitute for publishing it.

## Security invariants

The first two packages are distinctly named, reviewed distributions of the repository's vendored
`aws-creds` and `rust-s3` sources. Publication and consumer checks must preserve all of these facts:

- `cigar-rust-s3` depends on exactly `cigar-aws-creds = 0.39.1-cigar.1`, with default features
  disabled. It cannot resolve to the similarly named upstream package.
- `cigar-store` depends on exactly `cigar-rust-s3 = 0.37.2-cigar.1`, with default features disabled
  and only the synchronous Rustls feature enabled. It cannot fall back to upstream `rust-s3`.
- both reviewed packages select `attohttpc/tls-rustls-webpki-roots-ring` explicitly, and the default
  path uses Ring rather than an implicit provider;
- both reviewed packages pin `quick-xml` exactly to `0.41.0`;
- the unmaintained `surf`/async-std transport and its vulnerable legacy HTTP/TLS stack are not
  dependencies or exposed features of the publishable `cigar-rust-s3` package;
- the publishable source trees remain byte-for-byte equivalent to the reviewed vendored source
  trees. The qualifier records only their deterministic SHA-256 tree digests.

The root `[patch.crates-io]` entries exist only to qualify local workspace source. Cargo removes
path overrides from normalized publication manifests. The offline registry test therefore proves
that packaged consumers resolve the exact registry identities above without relying on a workspace
patch.

## Package contracts

Every package contains a package-local `LICENSE`, `NOTICE`, `release.json`, generated `Cargo.lock`,
normalized `Cargo.toml`, and library sources. Package allowlists exclude repository tests and
unrelated workspace files. In addition:

- `cigar-api` carries `proto/cigar_service.proto`, and its build script reads that packaged path;
- `cigar-store` carries all SQLite and PostgreSQL migrations referenced by `include_str!`;
- the SDK package contract requires `.cargo_vcs_info.json` from the final committed candidate.

The repository has an initial commit, but the next release candidate is not frozen and the current
worktree is dirty. Local development qualification therefore does not claim that the final
VCS-binding contract has passed.

## Repeatable local qualification

Install `cargo-local-registry`, create a fresh registry populated from the locked external
dependencies, and run the chain qualifier:

```sh
: "${CIGAR_EVIDENCE_DIR:?set an external evidence directory}"
REGISTRY="$(mktemp -d)"
cargo local-registry sync Cargo.lock "$REGISTRY"
python3 sdk/rust/qualify_publication_chain.py \
  --registry "$REGISTRY" \
  --report "${CIGAR_EVIDENCE_DIR}/rust-publication-chain-local.json"
cargo audit --deny warnings
cargo deny check
```

The qualifier runs `cargo package --locked --allow-dirty --offline` for every crate in the order
above. For every archive, it rejects unsafe paths and links, missing release assets, path
dependencies in the normalized manifest, unexpected tests, a changed security-fork identity, a
lost Ring selection, restored Surf/async-std exposure, or missing proto/migrations. It then compiles
a clean project depending only on `cigar-sdk = 0.1.0` from the local registry.

The evidence document uses the closed schema
`cigar.rust-publication-chain-qualification.v1`. Its writer validates that it contains only package
identities, versions, SHA-256 digests, fixed status fields, and fixed limitation statements; it does
not record source text, archive payloads, commands, environment values, or credentials.

Write each newly generated local result to
`${CIGAR_EVIDENCE_DIR}/rust-publication-chain-local.json`, outside the source tree. The previously
tracked result is retained only as a byte-preserved historical development receipt; it is not
current, clean-source-bound, or release-candidate qualification. Regenerate the external receipt
after any manifest, lockfile, source, packaging-input, or release-metadata change.

## External release closure

Before calling this chain release-ready:

1. Commit the exact candidate, rerun all local qualification and package-contract checks, and
   verify `.cargo_vcs_info.json` binds every final archive to that revision.
2. Confirm the approved crates.io owner controls every name. A crates.io API lookup on 2026-07-13
   returned not-found for all 19 names, but that is only a point-in-time availability signal and
   does not reserve them.
3. Publish sequentially from the committed candidate. Capture the registry version and checksum
   receipt for each crate, compare it with the approved package, and stop immediately on any
   identity, version, checksum, feature, or ownership mismatch.
4. From a clean environment with no workspace patch or local registry replacement, compile and
   test `cigar-sdk = 0.1.0` from crates.io on the supported platform matrix.
5. Reconcile the published archives with release signing, SBOM, license, provenance, artifact
   inventory, and final release-policy evidence.

Direct `cargo package` cannot resolve an unpublished internal dependency from crates.io; for
example, packaging `cigar-rust-s3` before its credential package exists fails with “no matching
package named `cigar-aws-creds`”. That is why the local registry qualifier is required before
external publication and why the real publication must follow the exact order above.
