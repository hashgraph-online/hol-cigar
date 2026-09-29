# Distributing CIGAR 0.11.0

The local context library is published as **`@hol-org/cigar` on npm** and
**`hol-cigar` on PyPI**. Its context operations require no HOL service, account,
database or API key. Node consumers import `@hol-org/cigar/context`; Python
consumers import `cigar_sdk.context`. Existing remote clients remain available.

This document describes the publication procedure. A passing branch run prepares
a candidate; it does not publish a GitHub release or change either registry.

## Qualification required before tagging

Run `context-sdk-release` on the exact clean release branch. Its reusable
`context-distribution` workflow requires:

- Two native builds per platform, with packaged Rust core tests, a worker compile
  probe, binary/dependency inspection and bound source inputs.
- Two independent SDK builds with identical npm, wheel, source and worker bytes.
- Fourteen fresh-install qualifications: each platform on Node 24.10.0/Python
  3.14.0 and Node 24.19.0/Python 3.14.7. Each installs the wheel, source archive and
  npm archive, executes the SDK tests and runs 172 oracle cases through all three
  installed consumers under an OS network-denial policy.
- Packaged `doctor` and complete `demo` commands, including missing-worker,
  missing-review and stale-review controls. The scripted reviewer demonstrates
  the review contract; it does not measure model factuality.
- The existing public SDK compatibility suite, complete archive checks,
  licenses, runtime dependency inventories and a current advisory lookup.

| Native platform | Python wheel platform tag |
|---|---|
| macOS ARM64 | `macosx_11_0_arm64` |
| macOS x64 | `macosx_11_0_x86_64` |
| Linux glibc x64 | `manylinux_2_28_x86_64` |
| Linux glibc ARM64 | `manylinux_2_28_aarch64` |
| Linux musl x64 | `musllinux_1_2_x86_64` |
| Linux musl ARM64 | `musllinux_1_2_aarch64` |
| Windows x64 | `win_amd64` |

The npm archive bundles all seven workers. Each wheel bundles its own worker.
The portable Python source archive needs an explicit trusted matching worker;
normal supported-platform installation should select a wheel. Runtime ranges are
Node `>=24.10.0 <25` and Python `>=3.14 <3.15`.

The final `context-sdk-release-release` artifact contains ten distributable
archives, retained qualification evidence, CycloneDX/SPDX inventories, release
notes, `release-manifest.json` and `SHA256SUMS`. The verifier rejects diagnostic
builds, partial platform sets, missing tests, altered logs or differing archives.
Windows offline evidence covers external outbound traffic; it does not claim
Windows loopback denial. Linux uses a container network namespace with no external
interface; macOS denies all network operations.

## Publish the approved candidate

1. Inspect the complete branch run and final candidate manifest. Create the
   `v0.11.0` tag at that exact reviewed revision. Do not move an existing tag.
   The tag workflow repeats qualification, signs all release payloads with GitHub
   provenance, creates the stable GitHub release, downloads it and verifies the
   public bytes. A branch run does not supply tag-bound signatures.
2. Record the SHA-256 of the signed release's `release-manifest.json`. Dispatch
   `publish-hol-cigar` at `v0.11.0` with that digest and confirmation
   `publish hol-cigar 0.11.0`. It verifies signatures, source/tag identity,
   all qualification evidence and current advisories, then sends only the seven
   wheels and source archive through the protected `pypi` trusted publisher.
3. Dispatch `stage-hol-cigar-npm` at `v0.11.0` with the same manifest digest and
   confirmation `stage @hol-org/cigar 0.11.0 with latest dist-tag`. The protected
   `npm` publisher stages the exact qualified archive without rebuilding it.
   An authorized npm maintainer must approve the displayed package/version,
   public visibility and `latest` tag in npm Staged Packages using its
   proof-of-presence/2FA flow. Staging alone is not publication.
4. Run `context-registry-readback` at `v0.11.0`, with the manifest digest and
   registry `both`. It downloads actual registry archives and checks them against
   the signed hashes, checks the complete PyPI file set, and requires the npm
   default `latest` tag and PyPI default version to select 0.11.0. Retain its JSON
   receipt. Select one registry if publication is temporarily staggered.

These workflows retain the existing trusted publisher filenames and protected
environments. They do not require long-lived npm or PyPI tokens. Review the
registered publishers if either registry rejects its OIDC identity; do not switch
to an unreviewed publishing route.

After readback passes, verify the public entry path in a fresh directory:

<!-- docs-check: illustrative -->
```sh
npm install @hol-org/cigar
npx --no-install cigar-context doctor --json
npx --no-install cigar-context demo --json
```

In a fresh Python 3.14 virtual environment:

<!-- docs-check: illustrative -->
```sh
python -m pip install hol-cigar
cigar-context doctor --json
cigar-context demo --json
```

Update the repository's published-install status after successful registry
readback. Keep the fixture-review limitation and the distinction between the
local graph and separate remote client in the README and agent instructions.
