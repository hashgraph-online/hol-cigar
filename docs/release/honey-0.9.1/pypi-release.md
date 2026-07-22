# PyPI release gate: `hol-cigar==0.9.1.dev1`

This publishes only the HOL.org CIGAR Python SDK alpha. It does not make Honey supported,
production-qualified, or fully qualified as a product.

## One-time setup

- [ ] In PyPI, create a pending Trusted Publisher for project `hol-cigar`.
- [ ] Set owner `HGraphPunks`, repository `cigar`, workflow `pypi-honey.yml`, environment `pypi`.
- [ ] Create the protected GitHub environment `pypi` with required reviewers.

The name was unregistered when checked on 2026-07-22; a pending publisher does not reserve it.

## Release

- [ ] Freeze one clean commit after product/Honey authority, generated clients, documentation,
  Python SDK checks, all release-tool tests, Rust workspace tests, and warnings-denied Clippy pass.
- [ ] Build the exact 13-file candidate from that commit and require the public verifier to return
  `passed-artifact-integrity`.
- [ ] Confirm the `hol-cigar` wheel and sdist pass package contracts, strict Twine metadata, and
  clean Python 3.14 installs in the non-admin qualification environment.
- [ ] Confirm `import cigar_sdk`, all 45 operation descriptors, the shared fixture, and both console
  entry points from both distributions.
- [ ] Publish the exact 13-file GitHub prerelease only after owner approval.
- [ ] Dispatch `publish-hol-cigar-honey` from tag `v0.9.1-honey.1` with the approved manifest
  SHA-256 and exact confirmation phrase.
- [ ] Approve the `pypi` environment only after the byte-verification job passes.
- [ ] Verify PyPI provenance, hashes, and a clean index install of
  `hol-cigar==0.9.1.dev1` in a disposable non-admin Python 3.14 environment.

Full Honey efficiency-cohort generation, downstream shadow verification, longevity, production
chaos, cross-platform qualification, signing, and notarization are not PyPI alpha gates. They
remain required before making the corresponding product or production claims. Publication must
retain `supported=false`, `production_qualified=false`, and an unevaluated full-product
qualification status.

Never use `skip-existing` or replace a published version. Cut a new PEP 440 prerelease on failure.
