# Honey Rust SDK

Honey ships `cigar-rust-sdk-0.9.0-honey.1-local-registry.tar.gz`, a self-contained offline Cargo
registry kit. It includes the public SDK crate, required unpublished internal crates, registry index,
checksums, and consumer configuration. Honey does not publish to crates.io.

## Configure an offline consumer

Verify and unpack the kit into an owner-controlled directory. Its root `.cargo/config.toml` replaces
crates.io with the relative `registry/`; keep that layout intact and run the supplied locked consumer
without referring to the CIGAR source checkout.

<!-- docs-check: illustrative -->
```sh
mkdir -p "$HOME/.local/share/cigar-honey/rust-registry"
tar -xzf cigar-rust-sdk-0.9.0-honey.1-local-registry.tar.gz -C "$HOME/.local/share/cigar-honey/rust-registry"
cd "$HOME/.local/share/cigar-honey/rust-registry"
cargo check --manifest-path examples/consumer/Cargo.toml --locked --offline
cargo test --manifest-path examples/consumer/Cargo.toml --locked --offline
cargo run --manifest-path examples/consumer/Cargo.toml --locked --offline
```

The three commands must succeed with an empty ordinary registry cache and network denied; otherwise
the kit is incomplete. Use `examples/consumer/Cargo.toml` and its lockfile as the template for a new
consumer only after the packaged qualification passes.

## Embedded or sidecar client

The public crate exposes generated protocol types, an embedded runtime facade, and bounded remote
client operations. Choose one storage profile and one policy profile explicitly. Every call carries
tenant/principal identity, cancellation, deadline, correlation, and mutation metadata.

```rust
use cigar_sdk::{CallOptions, EmbeddedClientBuilder};

async fn compile(client: &cigar_sdk::EmbeddedClient, plan_id: String)
    -> Result<(), cigar_sdk::SdkError>
{
    let options = CallOptions::new()
        .with_idempotency_key("rust-agent-a-compile-1")?;
    let response = client.compile_context_bundle(plan_id, options).await?;
    cigar_sdk::verify_bundle_manifest(&response.payload)?;
    Ok(())
}
```

The precise generated method signatures are authoritative; compile the packaged example rather than
copying pseudocode across SDK versions.

## Agent A coordinator

The Rust coordinator example checkpoints a parent context space, previews and creates a
recipient-bound handoff, verifies Agent B's result receipt, and merges against the exact base. It
must treat returned conflict IDs as a separate explicit resolution workflow and never overwrite the
parent projection locally.

The kit includes `examples/agent_a_coordinator.rs`; the default executable under
`examples/consumer/src/main.rs` exercises the semantic SDK workflow using only its packaged fixture
and local registry. Continue with [two-agent coordination](honey-two-agent.md).
