# Claude Code integration

The Claude Code distribution is a signed plugin archive containing the manifest, compatibility
declaration, hooks, skills, schemas, checksum manifest, license, notice, and the platform hook
executable. Install only after release verification; the source adapter directory is not a
distribution artifact.

<!-- docs-check: command claude-plugin-flow -->
```sh
cigar plugin install claude-code --yes
cigar plugin doctor claude-code
cigar plugin uninstall claude-code --yes
```

Hooks receive bounded documented events and invoke CIGAR through explicit local configuration. A
missing or incompatible binary fails closed. Plugin output must not include prompts, source content,
credentials, private paths, or unbounded environment data.
