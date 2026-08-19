# Upgrade Honey 0.9.2 or 0.9.3 to 0.9.4

Status: candidate operating guide. Use it only with a closed, checksum-verified 0.9.4 candidate.
The repository product authority is 0.9.4, but a source checkout that merely contains
`balanced_v4` is not installed-artifact or publication evidence.

Honey 0.9.4 preserves `cigar.context.v1`, the 45-operation public API, 70 nominal payload types,
protocol range `1.0` through `1.x`, and storage format v5. It adds the opt-in `balanced_v4`
intelligence profile without changing the frozen `balanced_v1` or `balanced_v3` definitions. No v6
storage migration is required.

## Select behavior explicitly

During candidate qualification, an omitted profile still selects `balanced_v3`. Pin the intended
behavior in the daemon's explicit configuration so a later release-default change cannot silently
alter a comparison or rollback:

<!-- docs-check: illustrative -->
```toml
mode = "local"
intelligence_profile = "balanced_v4"
```

Use `balanced_v3` to retain 0.9.3 selection/packing behavior or `balanced_v1` to retain 0.9.2
behavior. A 0.9.2 or 0.9.3 runtime does not understand `balanced_v4`; change the configuration back
to its compatible profile before selecting an older binary.

The selected runtime reports exactly one corresponding capability through `getCapabilities`:

| Configuration | Required capability |
| --- | --- |
| `balanced_v4` | `intelligence-balanced-v4` |
| `balanced_v3` | `intelligence-balanced-v3` |
| `balanced_v1` | `intelligence-balanced-v1` |

Do not infer profile activation from configuration bytes alone. Require the capability response and
replay the same representative workflow used before the upgrade.

## Before upgrading

1. Retain the exact 0.9.2 or 0.9.3 installation, its checksum, configuration, and recorded
   `getVersion`/`getCapabilities` responses.
2. Stop every daemon, embedded process, worker, and effect dispatcher that can use the target state.
3. Create a signed format-two backup and verify it against the current signer/key trust policy and
   external monotonic effect checkpoint.
4. Restore that backup into a separate empty location and verify its canonical root. Never copy a
   live SQLite database or WAL and never overwrite the active state directory.
5. Install the closed 0.9.4 candidate into a separate versioned root and verify its published
   checksum and release metadata. Do not use a source-tree binary as installed-artifact evidence.

The local backup command shape is:

<!-- docs-check: illustrative -->
```sh
cigar backup create /absolute/backups/pre-0.9.4.cigar --yes
cigar backup verify /absolute/backups/pre-0.9.4.cigar
cigar backup restore /absolute/backups/pre-0.9.4.cigar /absolute/state/0.9.4-rehearsal --yes
```

Restore accepts only a nonexistent or exactly empty target. It must fail on a stale, missing, or
substituted effect checkpoint, invalid signature, changed inventory, or nonempty destination.

## Upgrade rehearsal and activation

1. Point only the candidate installation at the separately restored rehearsal state.
2. Start with an explicit compatibility profile: `balanced_v1` for a 0.9.2 baseline or
   `balanced_v3` for a 0.9.3 baseline.
3. Require readiness, the exact expected storage root/revision, and an exact replay of the retained
   smoke workflow before selecting `balanced_v4`.
4. Restart with `balanced_v4`; require `getVersion` to report exactly `0.9.4` and
   `getCapabilities` to report `intelligence-balanced-v4` with the unchanged Context ABI and
   protocol range.
5. Exercise materialization, at least one verified delta, checkpoint/restart, and effect
   reconciliation if effects are enabled. Compare semantic identities, not display text.
6. Activate the candidate for real work only after the release verifier accepts the complete
   artifact directory and the rehearsal has no unresolved compatibility, recovery, or replay
   difference.

Stop on any version/ABI/profile mismatch, missing backup root, migration-ledger difference,
readiness failure, semantic replay difference, unknown effect, or content-bearing diagnostic. Keep
the prior installation and backup until the candidate has passed the release retention window.

## Behavior rollback

Behavior rollback does not change the binary or storage. Stop work, set `intelligence_profile` to
`balanced_v3` or `balanced_v1`, restart, and require the matching capability. Re-run the retained
legacy replay before resuming effects. The cursor-signing key and v5 migration ledger must remain
unchanged across the restart.

## Binary rollback

Binary rollback never opens or rewrites the candidate's state with an older runtime:

1. stop the candidate and every effect dispatcher;
2. preserve the candidate state byte-for-byte for diagnosis;
3. verify the pre-upgrade backup again;
4. restore it into another distinct empty location;
5. change `balanced_v4` to the older runtime's compatible profile;
6. activate the retained versioned installation against only that restored state; and
7. require its exact version, capability, readiness, canonical root, and retained replay before
   admitting work.

Never downgrade a live state directory, manually edit the migration ledger, delete a revision
anchor, reuse only a database/WAL pair, or let two versions share one writable state. Follow the
[storage-v5 guide](honey-storage-v5.md) and
[local recovery runbook](../runbooks/local-storage-recovery.md) for the underlying state rules.

Honey remains developer-preview software unless and until the separate production-promotion gates
close. A successful source rehearsal does not prove clean installation, signatures,
reproducibility, notarization, cross-platform support, or production readiness.
