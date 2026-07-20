# Semantic reuse at the Honey v1 boundary

Honey 0.9.1 does not reinterpret `cigar.context.v1` or add a public cache operation. It provides a
small Rust SDK helper for downstream systems that want to evaluate a reuse candidate safely while a
future atomic compilation protocol remains non-selected.

## Keep correlation out of semantic input

The existing compiler `contract_digest` covers the complete normalized `ContextContract`, including
every extension. This remains unchanged. A run, job, trace, timestamp, or request ID placed in
`ContextContract.extensions` therefore changes the v1 contract digest and prevents artifact reuse.
Do not label an arbitrary extension as execution-only after the fact.

Use the typed `RequestContext` trace field for transport tracing. Keep downstream run/job IDs in a
separate execution evidence record. An `IdempotencyKey` identifies an exact mutation and its retries;
it is not a semantic cache key and should not be derived from execution correlation.

The SDK `SemanticReuseRequest` deliberately has no run, job, trace, timestamp, attempt, or
idempotency field. Its stable key binds exactly:

- normalized need, including every understood semantic extension;
- catalog/index watermark;
- authorization and disclosure-domain commitments;
- policy and target-profile digests; and
- tokenizer, materializer, and compiler fingerprints.

The domain is `CIGAR-SDK-SEMANTIC-REQUEST-KEY\0v1\0`. Fields are hashed in the order above with
explicit labels and delimiters. This is a downstream compatibility key, not a new v1 protocol
identity.

If any semantic extension is unknown, or exact current authority is uncertain, key construction
returns a closed bypass reason. A candidate is a hit only when its stored key and every pin match
exactly. Miss and bypass results do not expose the candidate key or artifact digest.

## Bind each execution separately

After an exact hit or a new compilation, `bind_semantic_execution_receipt` commits to the stable key,
exact generated/reused artifact digest, a fresh UUIDv7 operation correlation, W3C trace ID, optional
protected run/job digests, outcome, and closed reason. Changing correlation changes the receipt
digest without changing the semantic key or artifact.

This SDK value is an unsigned downstream commitment, not the proposed future server-signed receipt.
Persist or sign it under the downstream evidence policy. Unknown-extension bypasses remain governed
by the existing v1 contract/artifact identities; do not manufacture a reusable key for them.

The source archive contains the complete construction at
`sdk/rust/examples/semantic_request_key.rs` and exact mismatch, bypass, correlation, and
receipt-binding vectors at `sdk/rust/tests/semantic_reuse.rs`.
