# PyPI release gate: `hol-cigar==0.9.2`

This publishes only the CIGAR Honey balanced-profile Python SDK developer preview. It does not make Honey
supported, production-qualified, or fully qualified as a product.

## Upgrade contract

- The distribution remains `hol-cigar` and the import package remains `cigar_sdk`.
- The Context ABI remains `cigar.context.v1` with the same 45 operation descriptors.
- Users upgrade with `python -m pip install --upgrade "hol-cigar==0.9.2"`.
- Existing 0.9.1 imports and entry-point names remain unchanged.

## Release

- [ ] Freeze one clean private Shadow CIGAR commit after product/Honey authority, generated clients,
  documentation, Python SDK checks, release-tool tests, Rust workspace tests, and warnings-denied
  Clippy pass.
- [ ] Build the exact 13-file Honey candidate from that commit and require the public verifier to
  return `passed-artifact-integrity`.
- [ ] Confirm the `hol-cigar` wheel and sdist pass package contracts, strict Twine metadata, and
  clean Python 3.14 installs.
- [ ] Confirm `import cigar_sdk`, all 45 operation descriptors, the shared fixture, and both console
  entry points from both distributions.
- [ ] Open the public source PR only after the private qualification packet is approved.
- [ ] After that PR is merged, create `v0.9.2` from the exact approved commit and attach the exact
  verified 13-file candidate as a GitHub prerelease.
- [ ] Dispatch the approval-gated `publish-hol-cigar-honey` Trusted Publishing workflow from the
  PyPI-authorized `.github/workflows/publish-hol-cigar.yml` file with the approved manifest
  SHA-256, then verify provenance, hashes, and a clean index install of `hol-cigar==0.9.2`.

Full Honey efficiency-cohort generation, downstream shadow verification, longevity, production
chaos, cross-platform qualification, signing, and notarization are not Python SDK alpha gates.
Publication must retain `supported=false`, `production_qualified=false`, and an unevaluated
full-product qualification status.

Never use `skip-existing` or replace published bytes. Cut a new version if publication fails after
the version has become immutable.
