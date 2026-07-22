# CIGAR documentation

CIGAR is an alpha project from [HOL.org](https://hol.org). It compiles governed, versioned context
for agent workflows. It indexes configured sources,
selects evidence under explicit contracts and policy, emits deterministic bundles and manifests,
supports attenuated handoffs, journals external effects, and reconstructs decisions for replay.
It does not make model output deterministic and does not promise universal exactly-once behavior for
external systems.

For a first result, follow the [five-minute quickstart](../guides/quickstart.md). Before production,
choose a [deployment profile](../guides/deployment.md), read [security hardening](../operations/security-hardening.md),
and practice every [operator runbook](../operations/index.md). Interface details are in the
[public API reference](../reference/public-api.md), while artifact trust begins with
[offline release verification](../release/verification.md).

## Honey 0.9.1 alpha

Developers evaluating the local Apple-silicon Honey profile should begin with the
[Honey installation guide](../guides/honey-install.md) and
[offline context quickstart](../guides/honey-quickstart.md). The supported workflow continues through
[two-agent coordination](../guides/honey-two-agent.md),
[effects and replay](../guides/honey-effects-replay.md), and the
[MCP/Claude integration](../guides/honey-mcp-claude.md). Review
[Honey's security and qualification limitations](../guides/honey-security-limitations.md) before
using it with private repositories or mediated effects.

This site describes product version 0.9.1-honey.1 and Context ABI `cigar.context.v1`. The selector is
development-only; `latest` remains absent until an approved version is published.

<!-- docs-check: command docs-build-local -->
```sh
python3 scripts/release/build_docs_site.py --check
```
