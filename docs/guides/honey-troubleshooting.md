# Honey troubleshooting

Start with content-safe machine output. Do not paste source text, prompts, authorization files,
handoff capsules, encrypted blobs, or raw state into a public issue.

## Baseline diagnosis

<!-- docs-check: illustrative -->
```sh
cigar --output json version
cigar --explain-config --output json status
cigar doctor --security --deep --output json
cigar diagnostics bundle "$HOME/cigar-support/honey-diagnostics.tar" --yes
```

Require version `0.9.1-honey.1`, Context ABI `cigar.context.v1`, and the intended embedded/local
target. `--explain-config` identifies the winning layer without printing authorization contents.

## Daemon unavailable

Confirm that CLI and daemon came from the same verified archive, the configured socket path is
owner-private and short enough for a Unix socket, and only one process owns it. A stale socket may be
removed only after proving no daemon is listening. Inspect readiness before retrying mutations; never
change an uncertain effect into a fresh idempotency key.

## Migration or corrupt local state

Stop the daemon. Preserve the complete state and verified backup. Do not copy a live SQLite WAL,
delete the `.cigar-revision` anchor, edit journal JSON, or run an older binary against newer state.
Restore a verified backup into a distinct empty directory. Follow the
[local storage recovery runbook](../runbooks/local-storage-recovery.md) for evidence-preserving steps.
For v4/v5 preflight, activation, rollback, compaction, and deep verification, use the
[Honey storage v5 guide](honey-storage-v5.md). The original v4 source is evidence; do not remove it
merely because activation succeeded.

## Stale or degraded retrieval

`context plan` with strong consistency may reject a stale index rather than silently compile from it.
Refresh the registered source, wait for the advertised catalog/index watermark, or rebuild the
disposable index from durable catalog state. Honey can operate without vector retrieval; do not treat
a missing vector backend as permission to bypass policy or provenance.

## Policy denial

A denial intentionally omits protected content and may not confirm whether a denied record exists.
Check principal, tenant, project, purpose, operation class, capability, policy version, source scope,
classification, and expiry. Do not broaden the grant until the intended boundary is reviewed.

## MCP timeout or malformed response

Verify that the client starts the absolute installed `cigar-mcp` path, uses MCP 2025-06-18 framing,
and does not mix stdout logging with protocol frames. Reduce request size, set a bounded deadline, and
preserve the same idempotency key only for an identical mutation. A degraded context marker is not an
effect authorization.

## Claude plugin mismatch

Run `cigar plugin doctor claude-code --output json`. Version, compatibility cohort, manifest, hook,
and MCP digests must agree. Reinstall from one matching runtime/plugin release; never combine plugin
files from two versions. Uninstall must preserve unrelated `.claude` settings byte-for-byte.

## SDK installation

- Python: use a fresh virtual environment and `pip --no-index`; an sdist needs a complete local
  build wheelhouse.
- TypeScript: install the exact `.tgz` in a clean project with the recorded pnpm store and offline
  mode.
- Rust: use the complete local-registry kit, its source replacement configuration, and
  `cargo --offline --locked`.

If any installer contacts a public registry, the Honey offline qualification has not been reproduced.

## Safe cleanup

Stop the daemon and make a verified backup. Remove only known disposable caches or a newly created
failed-demo directory. Durable catalog, blob, key, handoff, effect, and evidence records are not
caches. Use `gc plan` and inspect the signed plan before `gc run`; never manually delete a subset of
durable state to clear an error.

Security and support boundaries are summarized in
[Honey security and limitations](honey-security-limitations.md).
