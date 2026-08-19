# Honey 0.9.4 PyPI release gate

The bounded Python publication target is `hol-cigar==0.9.4`, imported as `cigar_sdk`. It is an
alpha developer preview. The source pull request makes the package and its CI publication contract
available on public `main`; merging that pull request does not publish anything.

## Required publication chain

- Merge the reviewed source pull request into `hashgraph-online/hol-cigar` `main` only after its
  required checks pass.
- Create `v0.9.4` from that exact merge commit. Do not move or reuse the tag.
- Attach the exact verified 13-file candidate to a non-draft GitHub prerelease named `v0.9.4`.
- Independently record and approve the SHA-256 of `honey-release-manifest.json`.
- From public `main`, dispatch the approval-gated `publish-hol-cigar-honey` workflow in the
  PyPI-authorized `.github/workflows/publish-hol-cigar.yml` file. Supply the approved manifest
  digest and the exact confirmation `publish hol-cigar 0.9.4`.
- Approve the protected `pypi` environment only after the verification job confirms the tag,
  source revision, release state, 13-file inventory, manifest digest, release verifier, exact wheel
  and sdist names, and strict Twine metadata check.
- After Trusted Publishing completes, verify the PyPI attestations, hashes, metadata links, and a
  clean index installation of `hol-cigar==0.9.4`.

## Fail-closed boundaries

The workflow has no pull-request or push trigger. Its verification job has read-only repository
permission and no OIDC permission. Only the final data-only publication job receives
`id-token: write`; that job has no checkout or shell step. `skip-existing` is false, so a conflicting
published version fails instead of being silently accepted.

Publication must stop if the GitHub release is a draft or not a prerelease, the tag does not resolve
to the manifest's source revision, any attachment is missing or replaced, the approved manifest
digest differs, metadata validation fails, or the protected environment is not explicitly
approved. Python package qualification does not imply full Honey runtime, platform, signing,
notarization, soak, production, or support qualification.
