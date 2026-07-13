# CIGAR documentation

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

`python3 scripts/release/check_docs.py --execute-local` checks links, anchors, strict JSON/TOML
examples, version selectors, and all locally executable documentation commands. Every shell example
is SHA-256-bound to exactly one structurally validated command entry, and every non-page site asset
must appear in the explicit asset allowlist and be referenced. Candidate and live commands remain
mandatory, but run only in the installed-artifact and isolated operations lanes declared by
`commands.v1.json`.
