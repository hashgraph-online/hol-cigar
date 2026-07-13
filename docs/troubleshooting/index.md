# Troubleshooting

Start with `cigar doctor --security`; use `--deep` for hashes, journals, projections, and referenced
encrypted blobs. Diagnostics are read-only and content-safe. Do not delete revision anchors, WAL,
journal rows, unknown effects, ciphertext, or key references to clear an error.

- **Storage unavailable:** stop writers, preserve bytes, verify backup, restore to a new empty target.
- **Blob authentication failure:** quarantine bytes, keep metadata, restore exact ciphertext and key.
- **Index lag/corruption:** follow the [index rebuild](../operations/index-rebuild.md).
- **Unknown effect:** follow [unknown-effect recovery](../operations/unknown-effect.md); do not retry.
- **Journal failure:** follow [journal quarantine](../operations/journal-quarantine.md).
- **Adapter incident:** follow [adapter disable](../operations/adapter-disable.md).
- **Migration mismatch:** stop; restore/cut over instead of editing applied SQL or the ledger.
- **Release verification failure:** preserve the directory, identify the first missing or mismatched
  digest, and obtain the correct signed artifact. Never regenerate evidence after promotion.

Support bundles exclude content, credentials, configured paths, identities, prompts, and plaintext.
