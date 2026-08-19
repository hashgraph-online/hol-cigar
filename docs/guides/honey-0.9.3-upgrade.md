# Upgrade from Honey 0.9.2 to 0.9.3

Honey 0.9.3 keeps the `cigar.context.v1` Context ABI, 45-operation public API, 70 nominal payload
types, `cigar_sdk` Python import, local-sidecar transport, and storage-v5 format. The intentional
behavior change is the default intelligence profile: omitting `intelligence_profile` now selects
`balanced_v3` instead of `balanced_v1`.

## Choose the context behavior

Use the new requirement-aware, coverage-saturating behavior:

```toml
mode = "local"
intelligence_profile = "balanced_v3"
```

Or reproduce the 0.9.2 context-selection behavior:

```toml
mode = "local"
intelligence_profile = "balanced_v1"
```

Existing explicit `balanced_v1` configuration remains valid. An existing configuration that omitted
the field is structurally valid but intentionally changes behavior, so pin `balanced_v1` before the
binary upgrade if exact replay is required.

## Upgrade

1. Stop every local `cigard` process using the target state.
2. Create and verify a CIGAR backup.
3. Install 0.9.3 into a separate versioned directory and verify its checksum.
4. Select the desired intelligence profile explicitly for the first comparison run.
5. Require `getVersion` to report `0.9.3` and `getCapabilities` to report the selected
   `intelligence-balanced-v3` or `intelligence-balanced-v1` capability.
6. Run the same smoke workflow used on 0.9.2 before removing the older installation.

Python users retain the distribution and import names:

<!-- docs-check: illustrative -->
```sh
python3.14 -m pip install --upgrade 'hol-cigar==0.9.3'
python3.14 -c 'import cigar_sdk; print(cigar_sdk.__version__)'
```

## Rollback

For behavior-only rollback, set `intelligence_profile = "balanced_v1"` and restart. For binary
rollback, stop the sidecar and select the retained 0.9.2 installation. Storage remains v5, but a
verified backup is still required before any version transition; never edit or downgrade a live
state directory in place.

Honey remains unsupported evaluation software before and after this upgrade. Passing local smoke
tests does not imply production qualification or generalized model-completion improvement.
