# Release qualification tools

These scripts are deliberately network-free unless an environment-owned platform driver performs an
explicit external release operation. They accept paths and key files explicitly, reject duplicate
JSON keys and unsafe relative paths, and write canonical JSON.

Local source-derived qualification:

```text
SOURCE_DATE_EPOCH=1700000000 python3 scripts/release/validate_metadata.py
SOURCE_DATE_EPOCH=1700000000 python3 scripts/release/build_archives.py --out /tmp/cigar-dist
python3 scripts/release/verify_package.py /tmp/cigar-dist/cigar-0.9.0-honey.1-source.tar.gz --contract packaging/contracts/source-archive.v1.json
SOURCE_DATE_EPOCH=1700000000 python3 scripts/release/check_reproducibility.py --report /tmp/cigar-reproducibility.json
python3 scripts/release/check_docs.py
python3 scripts/release/exercise_runbooks.py --mode static --out /tmp/cigar-runbooks
python3 scripts/release/selftest_release_verifier.py
```

The absolute paths above are development outputs, not candidate evidence. Candidate-bound report,
qualification, runbook, reproducibility, provenance, and SBOM producers use one owner-only external
workspace selected with `--evidence-dir` or `CIGAR_EVIDENCE_DIR`, plus a safe relative report/output
path. The root must be outside the source and candidate, lexically canonical, mode `0700`, and free
of symlink traversal; files are canonical, create-new, and mode `0400`. On macOS, use the canonical
`/private/tmp/...` spelling rather than the `/tmp` symlink when temporary storage is intentional.
Selector conflicts, path escape, links, hardlinks, portable-name collisions, unsafe modes,
overwrite, and root rebinding fail closed. A producer's documented stdout-only or direct mode is
development-only and cannot be reused as release evidence.

The beta source-freeze and candidate builders treat the selected evidence directory as their exact
create-new output workspace; legacy `--out` is mutually exclusive. `beta_release.py plan` writes
the fixed `release-evidence.json` beneath its selected workspace, while `assemble` uses the
selected directory as the final private inventory. Their verification-only actions emit no report
and reject an inherited selector; unset `CIGAR_EVIDENCE_DIR` before invoking those actions.

The source-derived archive builder can publish its complete eight-file output set (six archives,
`SHA256SUMS`, and the archive manifest) beneath a safe relative prefix in that workspace:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-source-archive-evidence \
  python3 scripts/release/build_archives.py --out source-derived
```

The prefix is staged and contract-verified before publication. Every attachment is copied from a
stable digest/size-bound file and is create-new/read-only. `--replace` is forbidden with protected
output. This storage mode still does not substitute for a clean committed source descriptor or
two-builder candidate reproducibility.

The native Apple-silicon development producer always requires its own empty external workspace:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-macos-arm64-build \
  python3 scripts/release/build_macos_aarch64_archive.py
```

It builds locked release-profile `cigar`, `cigard`, `cigar-mcp`, and `cigar-claude-hook` bytes on an
arm64 macOS host. The command disables default features and explicitly selects the CLI `full`
feature; the receipt fixes that composition to `cigar.full.local-macos-aarch64.v1`, and both the
native and downstream Homebrew producers reject a narrow-beta runtime receipt. It verifies every
thin arm64 Mach-O identity plus the MCP and hook content-free schema probes and enforces the
macOS-specific runtime-archive contract before publishing exactly the unsigned archive and
`macos-aarch64-development-build.json`. The optional dashboard and
internal conformance, benchmark, and soak executables are not part of this runtime package. The
receipt deliberately reports
`built-unqualified`; Developer ID signing, notarization, installed-byte qualification,
publication, and support remain mandatory external gates.

The two macOS qualification-tool producers each require a separate empty external workspace. The
conformance producer compiles the native thin-arm64 runner and the native
`cigar-install-qualifier` installed-runtime driver, then freezes only those binaries and its exact
profiles, vectors, and expected-summary assets. The driver is consumed separately by
`qualify_install.py`; its build-time invocation probe is not installation evidence. The CIGARBench
producer packages the exact standard-library
harness, analysis tool, matrix validator, schemas, datasets, comparator manifest, pins, and canary
registry behind three relocatable launchers. Those launchers require the reviewed
`/opt/homebrew/bin/python3` at Python 3.11 or newer, clear Python and shell startup injection
variables, and exec that exact path with `-B -I -S`; no caller interpreter override is accepted:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-conformance-tool-build \
  python3 scripts/release/build_macos_qualification_tools.py conformance
```

Qualify the installed runtime with the complete conformance-tool archive and its package contract;
`qualify_install.py` also requires the official-format runtime and qualification-tool build
receipts, securely stages them, and verifies their exact artifact, archive, contract, input-tree,
authority, build-tool, and payload bindings before it extracts the fixed driver. The two receipts'
shared product-version, Honey artifact-matrix, Honey capability-profile, and Honey
release-requirements records must have identical
digests and sizes. Their source records must name the same clean committed Git revision; the
runtime and tool input-tree SHA-256 values remain independently bound. It does not accept a
caller-selected executable:

```text
CIGAR_NO_EGRESS_ENFORCED=1 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-installed-qualification \
  python3 scripts/release/qualify_install.py \
    /private/tmp/cigar-macos-arm64-build/cigar-0.9.0-honey.1-aarch64-apple-darwin.tar.gz \
    --contract packaging/contracts/macos-runtime-archive.v1.json \
    --runtime-build-receipt \
      /private/tmp/cigar-macos-arm64-build/native-build-receipt.json \
    --qualification-tool-archive \
      /private/tmp/cigar-conformance-tool-build/cigar-conformance-0.9.0-honey.1-aarch64-apple-darwin.tar.gz \
    --qualification-tool-contract packaging/contracts/macos-conformance-runner.v1.json \
    --qualification-tool-build-receipt \
      /private/tmp/cigar-conformance-tool-build/macos-conformance-development-build.json \
    --expected-artifact-id macos-runtime-aarch64 \
    --expected-target aarch64-apple-darwin \
    --report macos/install-qualification.json
```

The outer runner must itself enforce no egress before setting
`CIGAR_NO_EGRESS_ENFORCED=1`; the environment variable alone is not qualification evidence.
The qualifier must run as a standard account: effective root or macOS `admin` membership through
real, effective, or supplementary groups fails closed. It uses a short private root below canonical
root-owned sticky `/private/tmp`, bounds every driver socket path to 96 bytes, and preserves the
long, Unicode, and spaces install case beneath that root. Python Seatbelt-wraps only direct runtime
probes. The native Rust driver is not Python-wrapped; it establishes the single Seatbelt boundary
around each runtime child. The direct and driver-managed profiles deny IP networking, ambient Mach
lookup, process fork, and signals while confining writes and allowing only private-workspace Unix
IPC. The report labels these controls
`darwin-seatbelt-deny-network-mach-confine-writes-protect-candidate-workspace-unix-v1` and
`darwin-seatbelt-deny-process-fork-signal-v1`.

Seatbelt is defense in depth, not complete host process isolation. In particular, macOS does not
mediate every same-user resource-control operation through these profile predicates, so a hostile
candidate can still affect the scheduling availability of another process owned by the qualifier
account. Run this gate only in a disposable, dedicated standard-user VM/account with no valuable
same-user processes, and destroy that environment after the run. The receipt proves the tested
network, Mach lookup, write, fork, signal, and brokered-preference controls; it does not prove that
the host was disposable. Likewise, `no_compiler_path=true` proves only that the child `PATH` exposed
no compiler. A compiler-free VM remains a separate externally attested installed-artifact gate.

All four extracted runtime binaries and both extracted qualification executables must be thin arm64
Mach-O executables, and the report digest-binds both build receipts, the runner, and the driver.
Those development receipts remain explicitly unauthenticated: exact schema and digest validation
does not become cryptographic provenance until independent external signing evidence is verified.

Each producer validates an exact no-extra-member package contract, deterministic metadata and
checksums, protected-output semantics, and invocation-only `--help` probes. The CIGARBench
producer intentionally runs no efficacy benchmark. Both receipts remain `built-unqualified` with
candidate, distribution-signing, notarization, installed qualification, conformance qualification,
benchmark efficacy, publication, support, and release claims false. Candidate-byte conformance,
real pinned-host benchmarks, Developer ID signing, notarization, clean install/uninstall, SBOM,
provenance, publication, and support remain separate mandatory gates.

The development Homebrew producer consumes that exact archive and its build receipt from an
independent external workspace. It publishes a deterministic Apple-silicon bottle, a tap archive,
and one protected receipt into a new empty workspace:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-homebrew-build \
  python3 scripts/release/build_macos_homebrew_artifacts.py \
    --native-archive /private/tmp/cigar-macos-arm64-build/cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz \
    --native-build-receipt /private/tmp/cigar-macos-arm64-build/macos-aarch64-development-build.json
```

The bottle has Homebrew's Cellar layout, all four required runtime executables, a parseable
deterministic `INSTALL_RECEIPT.json`, an embedded formula, and a source-binding SPDX document. The
tap formula binds the exact native archive and bottle digests and its test probes the installed MCP
and hook binaries. Bottle construction is fail-closed to the exact Apple-silicon macOS 15.6 host
encoded by the `arm64_sequoia` bottle metadata; a different macOS family or patch release cannot
emit bytes that falsely carry that identity. Reverify an existing development pair independently
of its producer invocation:

```text
SOURCE_DATE_EPOCH=1700000000 \
  python3 scripts/release/verify_macos_homebrew_artifacts.py \
    --native-archive /private/tmp/cigar-macos-arm64-build/cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz \
    --native-build-receipt /private/tmp/cigar-macos-arm64-build/macos-aarch64-development-build.json \
    --bottle /private/tmp/cigar-homebrew-build/cigar--1.0.0-dev.1.arm64_sequoia.bottle.tar.gz \
    --tap-archive /private/tmp/cigar-homebrew-build/cigar-1.0.0-dev.1-homebrew-tap.tar.gz \
    --homebrew-build-receipt /private/tmp/cigar-homebrew-build/macos-homebrew-development-build.json
```

The verifier securely rereads owner-controlled inputs, revalidates all three package contracts,
reconstructs the exact bottle and tap bytes from the native archive, and requires the canonical
receipt to match that reconstruction without an added claim. Its development URL intentionally
cannot be published or installed as a supported release. The receipt and verifier output remain
`built-unqualified`; Developer ID signing, notarization, clean install, offline use, upgrade,
uninstall, publication, and support are separate mandatory gates.

The Claude Code plugin development producer likewise requires a distinct empty external workspace:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-claude-plugin-build \
  python3 scripts/release/build_claude_code_plugin.py \
    --runtime-archive /private/tmp/cigar-macos-arm64-build/cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz
```

It contract-verifies the exact native archive, copies that archive's `cigar-claude-hook` and `cigar-mcp` bytes
without rebuilding them, validates the public plugin package, freezes its exact allowlisted payload,
and publishes the archive plus `claude-code-plugin-development-build.json`. The release-mode CLI
embeds the manifest-bound adapter payload so an installed binary never depends on the checkout.

Run the installed development lifecycle against real Claude Code `2.1.207` in a separate protected
workspace:

```text
SOURCE_DATE_EPOCH=1700000000 \
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-claude-installed-qualification \
  python3 scripts/release/qualify_claude_code_plugin.py \
    --runtime-archive /private/tmp/cigar-macos-arm64-build/cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz \
    --runtime-archive-sha256 <independently-recorded-runtime-sha256> \
    --plugin-archive /private/tmp/cigar-claude-plugin-build/cigar-claude-code-1.0.0-dev.1.tar.gz \
    --plugin-archive-sha256 <independently-recorded-plugin-sha256> \
    --claude /absolute/path/to/claude \
    --claude-sha256 <independently-recorded-claude-sha256>
```

That qualifier uses only isolated user state and public plugin commands, checks exact runtime/plugin
hook and MCP identity, executes installed MCP/hook probes, and proves clean CIGAR uninstall restores
the complete isolated HOME, CIGAR, project, and provider roots. Inputs require independently supplied
SHA-256 values and execution uses a deny-default macOS Seatbelt profile. It makes no model request. Its receipt is explicitly
`passed-unqualified`: live daemon readiness, approved Developer ID signing,
notarization, candidate-clean source, publication, and support remain separate gates.

The four SDK development producers use the same protected-output model. Each requires a distinct
empty external workspace and emits only its exact ecosystem artifact(s) plus one
`built-unqualified` receipt:

```text
SOURCE_DATE_EPOCH=1700000000 CIGAR_EVIDENCE_DIR=/private/tmp/cigar-typescript-sdk-build \
  python3 scripts/release/build_typescript_sdk.py
SOURCE_DATE_EPOCH=1700000000 CIGAR_EVIDENCE_DIR=/private/tmp/cigar-rust-sdk-build \
  python3 scripts/release/build_rust_sdk_crate.py
SOURCE_DATE_EPOCH=1700000000 CIGAR_EVIDENCE_DIR=/private/tmp/cigar-python-sdk-build \
  python3 scripts/release/build_python_sdk_artifacts.py
SOURCE_DATE_EPOCH=1700000000 CIGAR_EVIDENCE_DIR=/private/tmp/cigar-go-sdk-build \
  python3 scripts/release/build_go_sdk.py
```

The TypeScript producer performs a frozen offline pnpm build, verifies the exact npm tarball
inventory and metadata, packages the reviewed protobuf dependency locally, and installs and runs
the semantic workflow from the package payload in a fresh owner-private project with network and
install scripts disabled. The Python producer creates the wheel and sdist together, validates core
metadata and `RECORD`, tests their package-local fixtures, and installs each exact artifact plus
the pinned protobuf runtime dependency from the offline cache into a separate clean CPython 3.14
environment before importing the complete public SDK and running its semantic workflow. This is
one native runtime, not an interpreter/platform matrix. The Go producer requires native Go 1.26.5
or newer, constructs the canonical module
ZIP, and verifies it through a fresh file-proxy cache with offline `go list`, `go vet`, `go test`,
`go mod verify`, and the packaged semantic-bundle workflow. Earlier Go toolchains fail closed.

The Rust producer packages all 20 unpublished internal crates into a private offline local registry
in dependency order, then publishes only the matrix-selected canonical `cigar-sdk` `.crate`. It
tests the extracted library, reviewed quickstart, semantic fixture, and a clean default-feature
consumer against that private registry. This proves deterministic development packaging; it does
not make the SDK independently installable from crates.io. The 19 dependency packages still need
approved registry ownership, sequential exact-byte publication, public checksum readback, and
clean public-registry consumer qualification before any install or release claim can advance.

All four producers reject stale version/profile/matrix authority, source mutation during the
build, unsafe archive members, changed dependency snapshots, output rebinding, and overwrite. None
signs or publishes bytes. Local clean-install semantic probes do not establish public-registry,
full dependency, multi-platform, support, or release qualification.

The bounded macOS development assembler consumes all ten producer workspaces after they have been
created independently. The portable archive producer places its files beneath the relative
`--out` prefix, so that child directory is the portable input:

```text
SOURCE_DATE_EPOCH=1700000000 \
  python3 scripts/release/assemble_macos_development_artifacts.py \
    --portable-workspace /private/tmp/cigar-portable-evidence/portable \
    --native-workspace /private/tmp/cigar-macos-arm64-build \
    --conformance-workspace /private/tmp/cigar-conformance-tool-build \
    --cigarbench-workspace /private/tmp/cigarbench-tool-build \
    --homebrew-workspace /private/tmp/cigar-homebrew-build \
    --typescript-workspace /private/tmp/cigar-typescript-sdk-build \
    --rust-workspace /private/tmp/cigar-rust-sdk-build \
    --python-workspace /private/tmp/cigar-python-sdk-build \
    --go-workspace /private/tmp/cigar-go-sdk-build \
    --claude-workspace /private/tmp/cigar-claude-plugin-build \
    --evidence-dir /private/tmp/cigar-macos-development-assembly

python3 scripts/release/verify_macos_development_assembly.py \
  --dist /private/tmp/cigar-macos-development-assembly
```

Every input must be a distinct absolute owner-only external workspace with its producer's exact
inventory and no extra files. The assembler validates all 17 selected IDs, canonical receipts,
current authority digests, source revision/state, version, Context ABI, target, pinned macOS 15.6
arm64 host, archive contracts, and the native-to-Homebrew byte binding before it creates any output.
It then copies the already-validated bytes and emits `release-build.json` and artifact-only
`SHA256SUMS` last. The independent verifier reconstructs both manifests from the assembled bytes,
revalidates every package contract, and rejects mutation or any unreferenced file.

Despite its filename, this development manifest is intentionally
`cigar.local-archive-build.v1`, not `cigar.release-build.v1`. Producer receipts are not promoted to
release evidence or copied into the artifact directory. The assembly remains unsigned,
unnotarized, uninstalled, unqualified, unpublished, unsupported, and ineligible for release or live
runbook execution. A clean committed candidate build, external signing/notarization, exact installed
qualification, complete release evidence, and publication verification remain separate gates.

The documentation checker keeps its no-report stdout mode and its direct absolute `--report` mode
for development. To publish its report through the protected workspace, select one canonical
external root and pass a safe relative report path:

```text
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-evidence \
  python3 scripts/release/check_docs.py --execute-local --report docs/local.json
```

When a documentation report uses the protected workspace, executed documentation commands do not
inherit `CIGAR_EVIDENCE_DIR` and therefore cannot write into the parent evidence root. Protected
storage does not itself make this report candidate-bound; the final evidence assembler must still
bind the clean immutable source and exact distributed artifacts.

The third-party license inventory retains its direct absolute `--out` mode for local development.
Protected publication instead requires a safe relative output beneath one external workspace:

```text
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-evidence \
  python3 scripts/release/generate_license_inventory.py \
    --out supply-chain/third-party-license-inventory.json
```

The protected inventory is canonical, create-new, and read-only; Cargo metadata cannot inherit the
parent evidence selector. Missing host-platform metadata may be filled only from
`packaging/licenses/locked-upstream-license-evidence.v1.json`. That source authority binds every
fallback to its exact lockfile identity and checksum, canonical upstream metadata subset, archive
URL/SHA-256/size, and extracted license-document digests; duplicate, stale, substituted, or
locally conflicting evidence fails closed. Its schema is
`packaging/schemas/locked-upstream-license-evidence.v1.schema.json`.

The authority is technical source metadata, not legal approval. This storage receipt also does not
bind a candidate, source revision, or final artifact bytes. Authorized review and reconciliation
against every final packaged member remain separate release gates.

The deterministic documentation-site builder also retains direct `--out` as development-only.
Protected publication stages and validates the complete site before copying each file into a safe
relative prefix beneath the external workspace:

```text
CIGAR_EVIDENCE_DIR=/private/tmp/cigar-evidence \
  python3 scripts/release/build_docs_site.py --out documentation/site
```

Every protected HTML, asset, and canonical site-manifest file is create-new and mode `0400`.
Stable staged SHA-256 and byte-count bindings are rechecked before each protected attachment, so a
same-user substitution after validation is rejected before those changed bytes are published.
`--check` remains a no-output development validation and therefore rejects a selected evidence
workspace. Protected storage alone does not bind the site to candidate bytes, a source revision, or
the final documentation deployment; those qualifications remain separate release gates.

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
   a scoped `cigar.release-trust-policy.v1` bundle and public roots obtained independently. Supply
   the absolute reviewed OpenSSL executable and its independently recorded SHA-256; the verifier
   does not discover a cryptographic tool from ambient paths.
7. Promote the exact verified bytes without rebuild.

`assemble_evidence.py` and `verify_release.py` reject uncommitted/dirty source, missing artifact IDs,
missing evidence categories, failed/skipped/waived checks, wrong source revisions, metric failures,
digest changes, missing or altered raw-report attachments, unsigned artifacts, an unpinned or
substituted OpenSSL verifier, untrusted keys,
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
