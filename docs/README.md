# CIGAR documentation

CIGAR is an alpha project from [HOL.org](https://hol.org).

Start at the [documentation home](site/index.md). The published set is declared by
`site-manifest.v1.json`; implementation notes under `execution/` are intentionally excluded.

- [Five-minute quickstart](guides/quickstart.md)
- [Concepts](guides/concepts.md)
- [Install and uninstall](guides/install.md)
- [Project and focus workflows](guides/workflows.md)
- [Handoffs, effects, and replay](guides/handoffs-effects-replay.md)
- [Deployment profiles](guides/deployment.md)
- [SDK guides](guides/sdks.md)
- [Public API reference](reference/public-api.md)
- [Operations](operations/index.md)
- [Troubleshooting](troubleshooting/index.md)
- [Release verification](release/verification.md)

The Honey 0.9.1 alpha path has its own bounded installation and usage guides:

- [Honey install](guides/honey-install.md)
- [Honey offline quickstart](guides/honey-quickstart.md)
- [Honey two-agent workflow](guides/honey-two-agent.md)
- [Honey Python](guides/honey-python.md), [TypeScript](guides/honey-typescript.md), and
  [Rust](guides/honey-rust.md)
- [Honey MCP and Claude Code](guides/honey-mcp-claude.md)
- [Honey effects and replay](guides/honey-effects-replay.md)
- [Honey troubleshooting](guides/honey-troubleshooting.md) and
  [security limitations](guides/honey-security-limitations.md)

`python3 scripts/release/check_docs.py --execute-local` checks links, anchors, strict JSON/TOML
examples, version selectors, and all locally executable documentation commands. Every shell example
is SHA-256-bound to exactly one structurally validated command entry, and every non-page site asset
must appear in the explicit asset allowlist and be referenced. Candidate and live commands remain
mandatory, but run only in the installed-artifact and isolated operations lanes declared by
`commands.v1.json`.
