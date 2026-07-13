# CLI reference

The complete generated command list is in `crates/cigar-cli/assets/cigar-help.txt` and the packaged
manual page. Core groups are source, context, project, focus, space, handoff, effect, replay, policy,
backup, garbage collection, diagnostics, daemon/MCP service, plugin, and release verification.

Machine output is one `cigar.cli.output.v1` JSON object on stdout. Progress is restricted to an
interactive stderr and disabled by `--quiet`. Use `--authorization-file`; credentials in arguments,
URLs, project configuration, or debug output are rejected. Mutations require `--yes` unless
`--dry-run` is supplied, and `--non-interactive` never invents confirmation.

Targets are explicit: `--embedded`, `--local`, or `--remote URL`. Configuration precedence is
compiled defaults, system, user, project, explicit configuration, environment, then CLI flags.
`--explain-config` shows the winning source while redacting authorization material.

`cigar release verify <directory>` is the installed-binary offline gate. It must fail if any required
artifact, evidence receipt, SBOM, provenance statement, checksum, or detached signature is missing or
changed.
