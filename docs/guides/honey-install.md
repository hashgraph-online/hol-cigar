# Install CIGAR Honey v0.9.1

Honey is distributed as an unsigned Apple-silicon macOS developer-preview archive. Installation is
an explicit extract-and-`PATH` operation: there is no privileged installer, background launch agent,
or Homebrew formula.

## Verify before extraction

Download these files from the same GitHub prerelease:

- `cigar-0.9.1-honey.1-aarch64-apple-darwin.tar.gz`
- `honey-release-manifest.json`
- `SHA256SUMS`
- `RELEASE_NOTES_HONEY_v0.9.1.md`

Inspect the release manifest and require its channel to be `honey`, release state to be
`developer-preview`, target to be `aarch64-apple-darwin`, and production qualification to be false.
Then verify the archive using the checksum line from the same release.

<!-- docs-check: illustrative -->
```sh
grep '  cigar-0.9.1-honey.1-aarch64-apple-darwin.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -tzf cigar-0.9.1-honey.1-aarch64-apple-darwin.tar.gz
```

The archive contract permits only release metadata, checksums, licenses, completions, a man page,
and four executables: `cigar`, `cigard`, `cigar-mcp`, and `cigar-claude-hook`. Reject links, absolute
paths, traversal, unexpected members, duplicate normalized names, or a version different from the
release manifest.

## Extract without administrator privileges

Use a new empty directory. Retaining versioned installation directories makes rollback explicit and
prevents an interrupted extraction from partially replacing working bytes.

<!-- docs-check: illustrative -->
```sh
install_root="$HOME/.local/opt/cigar-honey-0.9.1-honey.1"
mkdir -p "$install_root"
tar -xzf cigar-0.9.1-honey.1-aarch64-apple-darwin.tar.gz -C "$install_root"
export PATH="$install_root/bin:$PATH"
cigar --output json version
cigar help
```

The machine-readable version document must report product version `0.9.1-honey.1`, Context ABI
`cigar.context.v1`, the release source revision, and the release build profile. Add the versioned
`bin` directory to the shell startup file only after this check passes.

Honey is unsigned and unnotarized. A quarantine attribute added by the browser may cause macOS to
block first launch. Review the exact checksum and release origin, then use the standard System
Settings Privacy & Security approval if you choose to trust it. Do not globally disable Gatekeeper,
and do not copy an unverified executable around the quarantine decision.

## State and configuration locations

- Project configuration and embedded state default to `<project>/.cigar`.
- User CLI configuration follows the platform configuration directory; `cigar --explain-config`
  shows the exact winning file and value source.
- `CIGAR_PROJECT_STATE_DIRECTORY` explicitly relocates project state.
- `CIGAR_HOME`, when set, owns CIGAR integration data such as the Claude installation receipt;
  otherwise integration data defaults below `$HOME/.cigar`.
- Daemon database, blob, key, socket, and journal paths come from the explicit daemon configuration.

Keep state directories owner-private. Never place authorization tokens in command arguments or
project-controlled configuration; use an explicit authorization file when a transport requires one.

## Upgrade and rollback

Create and verify a signed CIGAR backup before changing the binary or migrating state. Stop the local
daemon, install the new archive into a different directory, verify it, and switch `PATH`. Never copy
a live SQLite WAL or only part of the state directory.

<!-- docs-check: illustrative -->
```sh
cigar backup create "$HOME/cigar-backups/pre-honey-upgrade" --yes
cigar backup verify "$HOME/cigar-backups/pre-honey-upgrade"
cigar doctor --security --deep
```

If startup reports an incompatible migration, stop and use the verified backup with `backup restore`
into a distinct empty directory. Do not downgrade a state directory in place.

Honey 0.9.1 moves v4 state into a separately constructed v5 target; it does not upgrade the live
database in place. Follow the [storage v5 migration guide](honey-storage-v5.md) for preflight space
evidence, activation, rollback, compaction, deep integrity, and content-free telemetry.

## Complete uninstall

First uninstall the Claude integration, if present, and stop every local `cigard` process. Remove only
the versioned installation directory and shell entry you created. This leaves user data intact.

<!-- docs-check: illustrative -->
```sh
cigar plugin uninstall claude-code --yes
rm -rf "$HOME/.local/opt/cigar-honey-0.9.1-honey.1"
```

After making and verifying a backup, a user who deliberately wants to erase all Honey data may remove
the known project `.cigar` directories and the explicitly selected `CIGAR_HOME`. Do not run a broad
filesystem search-and-delete: source repositories and unrelated provider configuration are not owned
by CIGAR.

Continue with the [Honey quickstart](honey-quickstart.md) or consult
[Honey troubleshooting](honey-troubleshooting.md).
