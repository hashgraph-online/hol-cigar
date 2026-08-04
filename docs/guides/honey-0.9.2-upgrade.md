# Upgrade from Honey 0.9.1 to 0.9.2

Honey 0.9.2 is an in-family developer-preview upgrade. It keeps the `cigar.context.v1` Context ABI,
the 45-operation public API, the 70 nominal payload types, the `cigar_sdk` Python import, and the
existing local-sidecar transport shape. Existing daemon configuration remains valid because the
optional `intelligence_profile` setting defaults to `balanced_v1` and accepts only that release
profile.

Context selection remains on the published Honey behavior. Honey 0.9.2 does not add a selectable
experimental intelligence profile; its improvements are in storage, recovery, telemetry,
installation, and compatibility.

The exact machine-readable contract is
[`packaging/honey/compatibility-matrix.v1.json`](../../packaging/honey/compatibility-matrix.v1.json).

## Before upgrading

1. Keep the 0.9.1 installation and its checksum; install 0.9.2 into a separate versioned directory.
2. Stop every local `cigard` process that uses the state being upgraded.
3. Create and verify a CIGAR backup. Never copy only a live SQLite database or WAL.
4. Record the current `cigar --output json version` result and configuration.
5. If the daemon uses v4 state, complete the storage-v5 preflight before activating a v5 target.

## Package and code upgrade

Python users keep the same distribution and import names:

<!-- docs-check: illustrative -->
```sh
python3.14 -m pip install --upgrade 'hol-cigar==0.9.2'
python3.14 -c 'import cigar_sdk; print(cigar_sdk.__version__)'
```

No import rename or public-operation migration is required. TypeScript, Rust-kit, plugin, and native
archive users replace only the version segment in the corresponding 0.9.2 artifact name and keep
their existing integration shape.

For a local sidecar, omitting the new field selects `balanced_v1`. You may make that choice explicit:

```toml
mode = "local"
intelligence_profile = "balanced_v1"
```

After starting 0.9.2, require `getVersion` to report `0.9.2` and `getCapabilities` to contain
`intelligence-balanced-v1`. Run the same application smoke workflow used with 0.9.1 before removing
the old installation.

## Binary and state rollback

Stop the sidecar. If v5 was activated, restore the verified pre-upgrade v4 backup into a distinct
empty location and activate that restored location before selecting the versioned 0.9.1
installation. Never point an older runtime at v5 and never downgrade a state directory in place.
Follow the [storage v5 migration guide](honey-storage-v5.md) for the exact preflight, activation, and
recovery rules.

Honey remains unsupported evaluation software before and after this upgrade. A successful upgrade
does not imply production qualification, signing, notarization, or cross-platform support.
