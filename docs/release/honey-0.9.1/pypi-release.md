# PyPI release gate: `cigar-sdk==0.9.1.dev1`

This publishes only the Honey Python SDK developer preview. It does not make Honey supported or
production-qualified.

## One-time setup

- [ ] In PyPI, create a pending Trusted Publisher for project `cigar-sdk`.
- [ ] Set owner `HGraphPunks`, repository `cigar`, workflow `pypi-honey.yml`, environment `pypi`.
- [ ] Create the protected GitHub environment `pypi` with required reviewers.

The name was unregistered when checked on 2026-07-21; a pending publisher does not reserve it.

## Release

- [ ] Complete H91-1000 through H91-1120 against one clean committed candidate.
- [ ] Confirm wheel and sdist pass the package contracts, clean offline installs, and strict Twine
  metadata check.
- [ ] Publish the exact 13-file GitHub prerelease only after owner approval.
- [ ] Dispatch `publish-cigar-sdk-honey` from tag `v0.9.1-honey.1` with the approved manifest
  SHA-256 and exact confirmation phrase.
- [ ] Approve the `pypi` environment only after the byte-verification job passes.
- [ ] Verify PyPI provenance, hashes, and a clean install of
  `cigar-sdk==0.9.1.dev1` in the offline non-admin qualification VM.

Never use `skip-existing` or replace a published version. Cut a new PEP 440 prerelease on failure.
