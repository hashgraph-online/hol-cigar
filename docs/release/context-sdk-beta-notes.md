# CIGAR 0.10.0 beta 1

This beta releases the offline Rust context core and the Python/TypeScript SDKs.
It does not replace the Honey 0.9.4 daemon, CLI, MCP, Rust remote SDK, or Go remote SDK.

## What's available

- `cigar-context` **0.10.0-beta.1**: incremental context graphs, exact rendered o200k token budgets,
  dependency/contradiction closure, authorization filters, source-line citations, source replacement,
  optional query excerpts, semantic candidate input, bounded token caching, and verified transport deltas.
- Python **hol-cigar 0.10.0b1**, import `cigar_sdk`: local `LocalContextGraph` plus the compatible remote client.
- TypeScript **@hol-org/cigar 0.10.0-beta.1**: local `LocalContextGraph`, a lightweight `/context` entry point,
  and the compatible remote client. ESM, Node 24.10–24.x; no install-time scripts or downloads.

The bundled worker is qualified on **macOS ARM64 only**. Python requires 3.14.x.
The Python source distribution is portable; on other platforms, local graph APIs require an explicit
trusted absolute path to a worker built from this exact beta source. The remote SDK APIs remain available.
The macOS 11 wheel deployment floor is not a test result on macOS 11. This is beta software, not a
production certification or a claim that every supported OS/runtime combination was tested.

## Install the GitHub assets

Download the matching files from this prerelease, verify them first, then install:

<!-- docs-check: command context-beta-asset-install -->
```sh
python3.14 -m pip install ./hol_cigar-0.10.0b1-py3-none-macosx_11_0_arm64.whl
npm install ./hol-org-cigar-0.10.0-beta.1.tgz
```

Registry publication is separate. Once the respective registry lists this exact version:

<!-- docs-check: command context-beta-registry-install -->
```sh
python3.14 -m pip install 'hol-cigar==0.10.0b1'
npm install '@hol-org/cigar@0.10.0-beta.1'
```

npm uses the `beta` channel, never `latest`, and requires independent maintainer approval.
The Rust `.crate` source is included here; crates.io publication is not part of this beta workflow.
The SDK READMEs include local graph examples and worker build instructions.

## Evidence and signatures

`beta-release-manifest.json` records the exact source commit, payload hashes, qualified target,
two fresh hosted builds, and the qualification run URL. Both builders must independently compile
the packaged native source, produce identical archive/worker bytes, and qualify fresh SDK installs
against the Rust oracle and the preserved 0.9.4 SDK suites. No model is required for these tests.

Each build also reruns all 516 installed-consumer oracle comparisons under OS-enforced network denial.
`qualification-evidence.tar.gz` retains both builders' test logs and raw results.
`sbom.cdx.json` and `sbom.spdx.json` cover the native worker closure and SDK runtime dependencies; bundled packages contain
the native third-party license notices. Current public dependency advisories are checked during each build.
These checks do not constitute an exhaustive source security audit.

Every payload, manifest, and checksum inventory is signed with short-lived GitHub/Sigstore provenance;
`provenance.sigstore.jsonl` retains the certificate, signature, and transparency evidence. Verification
must pin the repository, workflow, tag, and expected source commit, not just check a self-supplied hash.
From the exact tagged source checkout, with all eleven release assets in a new directory:

<!-- docs-check: command context-beta-attestation-verify -->
```sh
python3 scripts/release/context_sdk_beta.py verify --verify-attestations \
  --directory "${CONTEXT_BETA_DIRECTORY}" --commit "${CONTEXT_BETA_COMMIT}"
```

Use an independently obtained source commit; read `gh attestation verify --help` for direct verification.
Two VMs are independent builds within one GitHub trust domain, not separate signing organizations or
a claimed SLSA level. PyPI supplies its own additional publication attestations when publication succeeds.

## Compatibility and limitations

All previously qualified 43 Python and 104 TypeScript legacy exports and all 45 remote operations remain.
No new token-reduction, answer-quality, or performance percentage is claimed by SDK packaging.
The underlying core measurements remain available in the versioned reports with their benchmark limits.
Transport deltas save bytes, not stateless model prompt tokens. Source excerpts are opt-in and may omit
important context; source text is data, not an authority grant. Reuse graphs to amortize worker startup.

The SDK worker inherits caller OS privileges and environment; it is not a security sandbox. Package hash
checks detect changed worker bytes but do not replace publisher trust. Keep graph caches within a privacy
boundary and pass current authorized IDs for every access-filtered compilation.
