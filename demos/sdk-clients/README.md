# Cross-SDK recorded workflow

This harness executes one digest-bound workflow through the public Rust,
TypeScript, Python, and Go SDKs:

1. `discoverSources`
2. `ingestCatalog`
3. `createContextPlan`
4. `compileContextBundle`
5. `getContextBundleManifest`

Every client encodes typed requests itself. A language-appropriate recorded
transport verifies the exact canonical CBOR, operation order, idempotency
keys, and path bindings before returning the shared canonical responses. Each
client then verifies the same bundle identity, selection-manifest identity,
and contract binding. Rust creates a public `EmbeddedClientBuilder` with explicit
bounded memory storage, deny-all policy, and verified fixture identity, then runs
the recorded facade through the embedded transport and verifies ordered shutdown.
It also uses the SDK's built-in bundle/manifest verifier;
the other drivers perform the equivalent local identity checks.

Run all four from an isolated, network-disabled source-checkout environment:

```sh
python3 demos/sdk-clients/run.py \
  --output reports/sdk-recorded-workflow.json
```

For protected external evidence, set `CIGAR_EVIDENCE_DIR` to a canonical
absolute owner-only directory and make `--output` relative to it. Publication
is create-new and mode `0400`; ambiguous selectors, unsafe paths, aliases, and
overwrite are rejected.

Individual languages may be selected with repeated `--language` flags. A
partial run remains useful but sets `sdk_workflow_qualified` to false.

This is deterministic recorded-fixture evidence for source SDK behavior. It
does not prove a live daemon, published package, installer, or release
artifact. Consequently the report always leaves
`installed_artifact_qualified` and `release_qualified` false. Use
`demos/installed_artifact_test.py` with explicit release artifacts and offline
dependency stores for the separate installed-artifact probe.
