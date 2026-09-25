# CIGAR documentation

**Create local context graphs with CIGAR 0.11.0 from npm or PyPI. No HOL service,
account, API key, daemon or database is required.** Start with the
[standalone application and agent guide](../guides/local-context.md). It covers
installation diagnostics, explicit ingestion, citations, source updates, cache reuse
and trusted answer review. Use the local `LocalContextGraph` API for this workflow.

The separate governed runtime from [HOL.org](https://hol.org) compiles versioned context
for agent workflows. It indexes configured sources,
selects evidence under explicit contracts and policy, emits deterministic bundles and manifests,
supports attenuated handoffs, journals external effects, and reconstructs decisions for replay.
It does not make model output deterministic and does not promise universal exactly-once behavior for
external systems.

For the governed runtime, follow its [five-minute quickstart](../guides/quickstart.md). Before production,
choose a [deployment profile](../guides/deployment.md), read [security hardening](../operations/security-hardening.md),
and practice every [operator runbook](../operations/index.md). Interface details are in the
[public API reference](../reference/public-api.md), while artifact trust begins with
[offline release verification](../release/verification.md).

## Honey 0.9.4 alpha

Developers evaluating the local Apple-silicon Honey profile should begin with the
[Honey installation guide](../guides/honey-install.md) and
[offline context quickstart](../guides/honey-quickstart.md). The supported workflow continues through
[two-agent coordination](../guides/honey-two-agent.md),
[effects and replay](../guides/honey-effects-replay.md), and the
[MCP/Claude integration](../guides/honey-mcp-claude.md). Review
[Honey's security and qualification limitations](../guides/honey-security-limitations.md) before
using it with private repositories or mediated effects.

The Honey runtime references describe version 0.9.4 and Context ABI `cigar.context.v1`.
The standalone guide describes the separately versioned 0.11.0 library. The npm
registry's default version is changed only when the new distribution is published.

<!-- docs-check: command docs-build-local -->
```sh
python3 scripts/release/build_docs_site.py --check
```
