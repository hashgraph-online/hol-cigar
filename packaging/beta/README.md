# Initial beta release profile

This directory is a release-channel contract, not a claim that the general-availability matrix is
complete. It pins the initial beta to `0.1.0-beta.1`, tag `v0.1.0-beta.1`, and profile
`cigar.beta.embedded-local.linux-x86_64.v1`. The profile is a prerelease, is not production-ready,
and restricts qualification to embedded-local use on Ubuntu 24.04 x86-64 with glibc 2.39
(`ubuntu-24.04-x86_64-glibc-2.39`, target `x86_64-unknown-linux-gnu`).

The artifact matrix contains exactly five source-derived archives plus one `cigar`-only Linux
binary archive. The capability policy is fail-closed: any surface not included by the profile is
unsupported, and the enumerated daemon, MCP, SDK, plugin, OCI, installer, non-Linux/non-x86_64,
remote/shared, effects, extensions, vector, and OTLP surfaces are explicitly excluded.

The source archive is the exact committed beta build projection, not the broader development
workspace. Sanitized root, `cigar-canon`, and `cigar-cli` manifests are remapped from
`build-projection`; they contain no unverified repository, homepage, author, or publishing claims.
Create it first with the host-independent `beta_artifacts.py freeze-source` command in an external
owner-only workspace, then run `verify-source` with an explicit Git executable against that exact
two-file archive/descriptor freeze; verification recomputes the complete committed projection
from Git object bytes. Native `build` requires the verified freeze, rejects a mismatched clean
checkout, builds only from its read-only materialized archive contents, and preserves the frozen
archive and descriptor bytes unchanged in the candidate.
`freeze-source` and `build` select their create-new external workspace with `--evidence-dir` or
`CIGAR_EVIDENCE_DIR`; legacy `--out` is mutually exclusive. The signed-release `plan` and
`assemble` actions use the same selector. Verification-only actions are stdout-only and reject an
inherited selector, so callers must unset `CIGAR_EVIDENCE_DIR` before independent verification.
Cargo metadata and both clean-target builds request Cargo offline mode against 47
checksum-verified resolver sources; only external OS-enforced evidence may claim no-egress. The
target-specific Cargo closure contains two workspace packages and 43 external runtime packages.
The legal archive preserves all 91 license/notice files from those 43 external runtime packages
plus the exact Rust 1.92.0 standard-library notice; the four resolver-only sources are identified
in provenance and are not misrepresented as distributed runtime components.

From the verified source archive or repository (not the docs archive), generate the pinned
manifests after an intentional contract update, then validate them:

```text
python3 scripts/release/beta_profile.py generate
python3 scripts/release/beta_profile.py check
```

The checker requires canonical generated JSON, an exact schema inventory, and pinned schema
digests. Beta receipts use `cigar.beta.qualification-evidence.v1` with the purpose
`cigar-beta-qualification-evidence-v1`, and the assembled bundle uses
`cigar.beta.release-evidence.v1`. Detached signatures must use one of the reserved `cigar-beta-*`
purposes. The GA `release-*` signature purposes and GA evidence schema identities are intentionally
not accepted as beta evidence, or vice versa.

A generated candidate is still unpublished and unsigned. Release requires a verified publisher
location and private security-contact channel, qualified Ubuntu builder evidence, independent
all-artifact reproduction, final scans, legal approval, trusted signatures, upload, and remote
readback. No repository or support URL is asserted until the publisher supplies and verifies it.
