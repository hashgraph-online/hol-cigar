# Local storage recovery

Use a signed backup before an irreversible migration, key destruction, or physical garbage collection. Keep the SQLite database, its `.cigar-revision` anchor, encrypted blob root, encrypted keystore, and OS credential entry under the same operational ownership; never copy a live WAL file as a backup.

For routine backup, create the signed archive through the storage API, verify it with the expected tenant/operator identity, and retain the returned canonical root. Restore only into an empty location. Activation is permitted after signature, inventory, SQLite integrity, state checksum, repository revision, and root checks all pass.

If startup reports storage unavailable after WAL damage or a revision-anchor mismatch, stop writers and preserve the database, WAL, anchor, and blob directories byte-for-byte. Do not delete the anchor or force a checkpoint. Verify the newest signed backup and restore to a new empty location. Compare its canonical root with the recorded backup receipt before switching the daemon.

If a blob fails authentication, leave the metadata reference intact for diagnosis. The local store moves corrupt or swapped ciphertext into the tenant quarantine without formatting a path, key, or plaintext. Restore the exact encrypted file from a verified backup, then reopen and run reconciliation. A missing or inactive wrapping key is an availability incident, not permission to delete ciphertext.

Key rotation changes only the key used for new blobs. Retired keys remain required for historical decryption. Destroy a retired key only after retention, replay, legal-hold, and verified-backup policy prove that no live or retained blob references it.

Projection corruption does not require metadata restore. Run the transactional atom/FTS rebuild from durable state with cancellation and confirm tenant counts and exact lookup probes afterward.
