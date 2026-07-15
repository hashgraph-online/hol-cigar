# Claude Code integration

The current Claude Code artifact is an unsigned development plugin archive containing the manifest,
compatibility declaration, hooks, skills, schemas, checksum manifest, license, notice, and the exact
hook and MCP server copied from the matching Apple-silicon runtime archive. Runtime configuration
uses plugin-root-bound commands and never resolves either executable through ambient `PATH`. It is not a supported distribution.
A future release must pass package verification, approved Developer ID signing, notarization, and
installed qualification before these commands become release installation instructions. The
release-mode CLI embeds the manifest-bound adapter payload and never depends on the source checkout.

The installed-candidate documentation gate verifies the exact Honey demo, runtime, and Claude plugin
archives by independently supplied SHA-256, checks that the plugin carries the runtime's hook and MCP
bytes, and executes the packaged Claude/MCP story twice under the no-egress boundary. It does not make
a model call and does not treat an installer exit code alone as lifecycle evidence.

<!-- docs-check: command claude-plugin-flow -->
```sh
cigar plugin install claude-code --yes
cigar plugin doctor claude-code
cigar plugin uninstall claude-code --yes
```

Hooks receive bounded documented events and invoke CIGAR through explicit local configuration. A
missing or incompatible binary fails closed. Plugin output must not include prompts, source content,
credentials, private paths, or unbounded environment data.

Development installed qualification is limited to Claude Code `2.1.207` on Apple-silicon macOS. It
uses an isolated home and public plugin commands, makes no model call, and keeps signing,
notarization, publication, and support claims false.
